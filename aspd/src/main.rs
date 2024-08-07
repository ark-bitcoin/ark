
#[macro_use] extern crate log;

use std::{fs, process};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, Context};
use bitcoin::{Address, Amount, Network};
use clap::Parser;

use aspd::{App, Config};
use aspd_rpc_client as rpc;

const RPC_ADDR: &str = "[::]:3535";

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	#[arg(long, global = true)]
	datadir: Option<PathBuf>,
	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Args)]
struct CreateOpts {
	#[arg(long, default_value = "regtest")]
	network: Network,
	#[arg(long)]
	bitcoind_url: String,
	#[arg(long)]
	bitcoind_cookie: String,
	#[arg(long)]
	public_rpc_address: Option<String>,
	#[arg(long)]
	public_rpc_tls_cert_path: Option<PathBuf>,
	#[arg(long)]
	public_rpc_tls_key_path: Option<PathBuf>,
	#[arg(long)]
	admin_rpc_address: Option<String>,
	#[arg(long)]
	round_interval: Option<u64>,
	#[arg(long)]
	round_submit_time: Option<u64>,
	#[arg(long)]
	round_sign_time: Option<u64>,
	#[arg(long)]
	nb_round_nonces: Option<usize>,
	#[arg(long)]
	vtxo_expiry_delta: Option<u16>,
	#[arg(long)]
	vtxo_exit_delta: Option<u16>
}

#[derive(clap::Args)]
struct ConfigOpts {
	#[arg(long)]
	bitcoind_url: Option<String>,
	#[arg(long)]
	bitcoind_cookie: Option<String>,
	#[arg(long)]
	public_rpc_address: Option<String>,
	#[arg(long)]
	// We use a double Option because we must be able to set 
	// this variable to None.
	// None -> Do not change this variable
	// Some(None) -> Set this variable to None
	// Some(val) -> Set this variable to `val`
	public_rpc_tls_cert_path: Option<Option<PathBuf>>,
	#[arg(long)]
	public_rpc_tls_key_path: Option<Option<PathBuf>>,
	#[arg(long)]
	admin_rpc_address: Option<Option<String>>,
}

#[derive(clap::Subcommand)]
enum Command {
	#[command()]
	Create(CreateOpts),
	#[command()]
	SetConfig(ConfigOpts),
	#[command()]
	Start,
	#[command()]
	Drain {
		/// the address to send all the wallet funds to
		address: Address<bitcoin::address::NetworkUnchecked>,
	},
	#[command()]
	GetMnemonic,
	#[command()]
	DropOorConflicts,
	#[command()]
	Rpc {
		#[arg(long, default_value = RPC_ADDR)]
		addr: String,
		#[command(subcommand)]
		cmd: RpcCommand,
	},
}

#[derive(clap::Subcommand)]
enum RpcCommand {
	#[command()]
	Balance,
	#[command()]
	GetAddress,
	#[command()]
	TriggerRound,
	/// Stop aspd.
	#[command()]
	Stop,
}

#[tokio::main]
async fn main() {
	if let Err(e) = inner_main().await {
		eprintln!("An error occurred: {}", e);
		// maybe hide second print behind a verbose flag
		eprintln!("");
		eprintln!("{:?}", e);
		process::exit(1);
	}
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	if let Command::Rpc { cmd, addr } = cli.command {
		env_logger::builder()
			.filter_level(log::LevelFilter::Trace)
			.init();

		return run_rpc(&addr, cmd).await;
	}

	env_logger::builder()
		.filter_module("bitcoincore_rpc", log::LevelFilter::Warn)
		.filter_module("rustls", log::LevelFilter::Warn)
		.filter_level(log::LevelFilter::Trace)
		.init();

	match cli.command {
		Command::Rpc { .. } => unreachable!(),
		Command::Create(opts) => {
			let datadir = {
				let datadir = PathBuf::from(cli.datadir.context("need datadir")?);
				if !datadir.exists() {
					fs::create_dir_all(&datadir).context("failed to create datadir")?;
				}
				datadir.canonicalize().context("canonicalizing path")?
			};

			let cfg = config_from_create_opts(opts)?;

			App::create(&datadir, cfg)?;
		},
		Command::SetConfig(updates) => {
			let datadir = PathBuf::from(cli.datadir.context("need datadir")?);
			// Create a back-up of the old config file
			Config::create_backup_in_datadir(&datadir)?;

			// Update the configuration
			let mut cfg = Config::read_from_datadir(&datadir)?;
			merge_config(&mut cfg, updates)?;
			cfg.write_to_datadir(&datadir)?;

			println!("The configuration has been updated");
			println!("You should restart `arkd` to ensure the new configuration takes effect");
		},
		Command::Start => {
			let mut app = App::open(&cli.datadir.context("need datadir")?).await.context("server init")?;
			let jh = app.start()?;
			info!("aspd onchain address: {}", app.onchain_address().await?);
			if let Err(e) = jh.await? {
				error!("Shutdown error from aspd: {:?}", e);
				process::exit(1);
			}
		},
		Command::Drain { address } => {
			let app = App::open(&cli.datadir.context("need datadir")?).await.context("server init")?;
			println!("{}", app.drain(address).await?.compute_txid());
		},
		Command::GetMnemonic => {
			let app = App::open(&cli.datadir.context("need datadir")?).await.context("server init")?;
			println!("{}", app.get_master_mnemonic()?);
		},
		Command::DropOorConflicts => {
			let app = App::open(&cli.datadir.context("need datadir")?).await.context("server init")?;
			app.drop_all_oor_conflicts()?;
		},
	}

	Ok(())
}

async fn run_rpc(addr: &str, cmd: RpcCommand) -> anyhow::Result<()> {
	let addr = if addr.starts_with("http") {
		addr.to_owned()
	} else {
		format!("http://{}", addr)
	};
	let asp_endpoint = tonic::transport::Uri::from_str(&addr).context("invalid asp addr")?;
	let mut asp = rpc::AdminServiceClient::connect(asp_endpoint)
		.await.context("failed to connect to asp")?;

	match cmd {
		RpcCommand::Balance => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", Amount::from_sat(res.balance));
		},
		RpcCommand::GetAddress => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", res.address);
		},
		RpcCommand::TriggerRound => {
			asp.trigger_round(rpc::Empty {}).await?.into_inner();
		}
		RpcCommand::Stop => unimplemented!(),
	}
	Ok(())
}

fn merge_config(cfg: &mut Config, updates: ConfigOpts) -> anyhow::Result<()>{

	match updates.bitcoind_url {
		None => {},
		Some(url) => cfg.bitcoind_url = url,
	}

	match updates.bitcoind_cookie {
		None => {},
		Some(cookie) => cfg.bitcoind_cookie = cookie
	}

	match updates.public_rpc_address {
		None => {},
		Some(addr) => {
			cfg.public_rpc_address = addr.parse().context("public_rpc_address is invalid")?;
		}
	}

	match updates.public_rpc_tls_cert_path {
		None => {},
		Some(x) => cfg.public_rpc_tls_cert_path = x
	}

	match updates.public_rpc_tls_key_path {
		None => {},
		Some(x) => cfg.public_rpc_tls_key_path = x
	}

	match updates.admin_rpc_address {
		None => {},
		Some(None) => cfg.admin_rpc_address = None,
		Some(Some(x)) => cfg.admin_rpc_address = Some(x.parse().context("Invalid admin_rpc_address")?)
	}

	Ok(())
}

fn config_from_create_opts(opts: CreateOpts) -> Result<Config> {
	// Configure the ASP
	let mut cfg = Config {
		network: opts.network,
		bitcoind_url: opts.bitcoind_url,
		bitcoind_cookie: opts.bitcoind_cookie,
		public_rpc_tls_cert_path: opts.public_rpc_tls_cert_path,
		public_rpc_tls_key_path: opts.public_rpc_tls_key_path,
		..Default::default()
	};

	if let Some(pra) = opts.public_rpc_address {
		cfg.public_rpc_address = pra.parse()
			.context("Invalid `public_rpc_address`")?;
	}
	if let Some(ara) = opts.admin_rpc_address {
		cfg.admin_rpc_address = Some(ara.parse()
			.context("Invalid `admin_rpc_address`")?
		);
	}
	if let Some(ri) = opts.round_interval {
		cfg.round_interval = Duration::from_secs(ri);
	}
	if let Some(rst) = opts.round_submit_time {
		cfg.round_submit_time = Duration::from_secs(rst);
	}
	if let Some(rst) = opts.round_sign_time {
		cfg.round_sign_time = Duration::from_secs(rst);
	}
	if let Some(rnn) = opts.nb_round_nonces {
		cfg.nb_round_nonces = rnn;
	}
	if let Some(ved) = opts.vtxo_expiry_delta {
		cfg.vtxo_expiry_delta = ved;
	}
	if let Some(ved) = opts.vtxo_exit_delta {
		cfg.vtxo_exit_delta = ved;
	}

	Ok(cfg)
}
