
#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde_json;

use std::{env, fs, io, process};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{address, Address, Amount};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

use bark::{Wallet, Config};

const SIGNET_ASP_CERT: &'static [u8] = include_bytes!("signet.asp.21m.dev.cert.pem");

fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	/// Enable verbose logging.
	#[arg(long, short = 'v', global = true)]
	verbose: bool,

	/// Print output as JSON.
	///
	/// Note that simple string values will still be outputted as raw strings.
	#[arg(long, short = 'j', global = true)]
	json: bool,

	/// The datadir of the bark wallet.
	#[arg(long, global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create a new wallet.
	///
	/// Configuration will pass in default values when --signet is used, but will
	/// require full configuration for regtest.
	#[command()]
	Create {
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,

		/// Use regtest network.
		#[arg(long)]
		regtest: bool,
		/// Use signet network.
		#[arg(long)]
		signet: bool,

		#[arg(long)]
		asp: Option<String>,
		#[arg(long)]
		asp_cert: Option<String>,

		/// The esplora HTTP API endpoint.
		#[arg(long)]
		esplora: Option<String>,
		#[arg(long)]
		bitcoind: Option<String>,
		#[arg(long)]
		bitcoind_cookie: Option<PathBuf>,
		#[arg(long)]
		bitcoind_user: Option<String>,
		#[arg(long)]
		bitcoind_pass: Option<String>,
	},
	#[command()]
	GetAddress,
	/// The the public key used to receive vtxos.
	#[command()]
	GetVtxoPubkey,
	#[command()]
	Balance,
	#[command()]
	Onboard {
		amount: Amount,
	},
	/// Send using the built-in on-chain wallet.
	#[command()]
	SendOnchain {
		address: Address<address::NetworkUnchecked>,
		amount: Amount,
	},
	#[command()]
	SendOor {
		/// Destination for the payment.
		destination: String,
		amount: Amount,
	},
	/// Send money in an Ark round.
	#[command()]
	SendRound {
		/// Destination for the payment, this can either be an on-chain address
		/// or a public key for an Ark payment.
		destination: String,
		amount: Amount,
	},
	#[command()]
	OffboardAll,
	#[command()]
	StartExit,
	#[command()]
	ClaimExit,

	/// Dev command to drop the vtxo database.
	#[command(hide = true)]
	DropVtxos,
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let mut logbuilder = env_logger::builder();
	logbuilder.target(env_logger::Target::Stderr);
	if cli.verbose {
		logbuilder
			.filter_module("sled", log::LevelFilter::Warn)
			.filter_module("rustls", log::LevelFilter::Warn)
			.filter_module("reqwest", log::LevelFilter::Warn)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Debug)
			.filter_level(log::LevelFilter::Trace);
	} else {
		logbuilder
			.filter_module("sled", log::LevelFilter::Off)
			.filter_module("rustls", log::LevelFilter::Off)
			.filter_module("reqwest", log::LevelFilter::Off)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Off)
			.filter_level(log::LevelFilter::Info);
	}
	logbuilder.init();

	let datadir = {
		let datadir = PathBuf::from(cli.datadir);
		if !datadir.exists() {
			fs::create_dir_all(&datadir).context("failed to create datadir")?;
		}
		datadir.canonicalize().context("canonicalizing path")?
	};

	// Handle create command differently.
	if let Command::Create {
		force, regtest, signet, mut asp, asp_cert, mut esplora, bitcoind, bitcoind_cookie, bitcoind_user,
		bitcoind_pass,
	} = cli.command {
		let net = if regtest && !signet {
			bitcoin::Network::Regtest
		} else if signet && !regtest {
			bitcoin::Network::Signet
		} else {
			bail!("Need to user either --signet and --regtest");
		};

		let mut asp_cert = asp_cert.map(|p|
			fs::read(p).context("failed to read ASP cert file")
		).transpose()?;

		if signet {
			if asp.is_none() {
				asp = Some("https://signet.asp.21m.dev:35035".into());
				if asp_cert.is_none() {
					asp_cert = Some(SIGNET_ASP_CERT.to_vec());
				}
			}
			if esplora.is_none() && bitcoind.is_none() {
				esplora = Some("http://signet.21m.dev:3003".into());
			}
		}

		//TODO(stevenroose) somehow pass this in
		let cfg = Config {
			network: net,
			asp_address: asp.context("missing ASP address")?,
			asp_cert: None,
			esplora_address: esplora,
			bitcoind_address: bitcoind,
			bitcoind_cookiefile: bitcoind_cookie,
			bitcoind_user: bitcoind_user,
			bitcoind_pass: bitcoind_pass,
		};

		if force {
			fs::remove_dir_all(&datadir)?;
		}

		fs::create_dir_all(&datadir).context("failed to create datadir")?;
		let mut w = Wallet::create(&datadir, cfg, asp_cert).await.context("error creating wallet")?;
		info!("Onchain address: {}", w.get_new_onchain_address()?);
		return Ok(());
	}

	let mut w = Wallet::open(&datadir).await.context("error opening wallet")?;
	let net = w.config().network;

	match cli.command {
		Command::Create { .. } => unreachable!(),
		Command::GetAddress => println!("{}", w.get_new_onchain_address()?),
		Command::GetVtxoPubkey => println!("{}", w.vtxo_pubkey()),
		Command::Balance => {
			let onchain = w.onchain_balance().await?;
			let offchain =  w.offchain_balance().await?;
			let (claimables, unclaimables) = w.unclaimed_exits().await?;
			let claimable = claimables.iter().map(|i| i.spec.amount).sum::<Amount>();
			let unclaimable = unclaimables.iter().map(|i| i.spec.amount).sum::<Amount>();
			if cli.json {
				//TODO(stevenroose) should make a bark-json crate with these structs
				serde_json::to_writer(io::stdout(), &json!({
					"onchain": onchain.to_sat(),
					"offchain": offchain.to_sat(),
					"claimable": claimable.to_sat(),
					"unclaimable": unclaimable.to_sat(),
				})).unwrap();
			} else {
				info!("Onchain balance: {}", onchain);
				info!("Offchain balance: {}", offchain);
				if !claimables.is_empty() {
					info!("Got {} claimable exits with total value of {}",
						claimables.len(), claimable,
					);
				}
				if !unclaimables.is_empty() {
					info!("Got {} unclaimable exits with total value of {}",
						unclaimables.len(), unclaimable,
					);
				}
			}
		},
		Command::Onboard { amount } => w.onboard(amount).await?,
		Command::SendOnchain { address, amount } => {
			let addr = address.require_network(net).with_context(|| {
				format!("address is not valid for configured network {}", net)
			})?;
			w.send_onchain(addr, amount).await?;
		},
		Command::SendOor { destination, amount } => {
			let pk = PublicKey::from_str(&destination).context("invalid pubkey")?;
			w.send_oor_payment(pk, amount).await?;
			info!("Success");
		},
		Command::SendRound { destination, amount } => {
			if let Ok(pk) = PublicKey::from_str(&destination) {
				debug!("Sending to Ark public key {}", pk);
				w.send_ark_payment(pk, amount).await?;
			} else if let Ok(addr) = Address::from_str(&destination) {
				let addr = addr.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;
				debug!("Sending to on-chain address {}", addr);
				w.send_ark_onchain_payment(addr, amount).await?;
			} else {
				bail!("Invalid destination");
			}
		},
		Command::OffboardAll => w.offboard_all().await?,
		Command::StartExit => w.start_unilateral_exit().await?,
		Command::ClaimExit => w.claim_unilateral_exit().await?,

		// dev commands

		Command::DropVtxos => {
			w.drop_vtxos().await?;
			info!("Dropped all vtxos");
		},
	}
	Ok(())
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let verbose = cli.verbose;

	if let Err(e) = inner_main(cli).await {
		eprintln!("An error occurred: {}", e);

		// this is taken from anyhow code because it's not exposed
		if let Some(cause) = e.source() {
			eprintln!("Caused by:");
			for error in anyhow::Chain::new(cause) {
				eprintln!("	{}", error);
			}
		}
		eprintln!();

		if verbose {
			eprintln!();
			eprintln!("Stack backtrace:");
			eprintln!("{}", e.backtrace());
		}
		process::exit(1);
	}
}
