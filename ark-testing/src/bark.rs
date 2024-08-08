
use std::{env, fmt, fs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io::prelude::*;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::address::{Address, NetworkUnchecked};
use bitcoin::Amount;
use serde_json;
use tokio::process::Command as TokioCommand;
use which::which;

use crate::constants::env::BARK_EXEC;

#[derive(Debug, Clone)]
struct BarkCommand {
	exe_path: PathBuf,
	args: Vec<String>
}

impl BarkCommand {

	pub fn new() -> anyhow::Result<Self> {
		match env::var(BARK_EXEC) {
			Ok(aspd_exec) => {
				Ok(BarkCommand {
					exe_path: which(aspd_exec)?,
					args: vec![]}
				)
			},
			Err(env::VarError::NotPresent) => {
				Ok(BarkCommand {
					exe_path: which("cargo")?,
					args: ["run", "--package", "bark-client", "--"].iter().map(|x| x.to_string()).collect()
				})
			},
			Err(_) => anyhow::bail!("Failed to read BARK_EXEC"),
		}
	}

	pub fn arg<S>(&mut self, arg: S) -> &mut Self
		where S: AsRef<OsStr> {
			let osstr = arg.as_ref().to_str().unwrap().to_owned();

			self.args.push(osstr);
			self
	}

	pub fn args<I,S>(&mut self, args: I) -> &mut Self
		where
		I: IntoIterator<Item = S>,
		S: AsRef<OsStr>,
	{
		for arg in args {
			self.arg(arg.as_ref());
		}
		self
	}

	pub fn tokio(&self) -> TokioCommand {
		let mut cmd = TokioCommand::new(self.exe_path.clone());
		cmd.args(self.args.clone());
		cmd
	}
}

impl std::fmt::Display for BarkCommand {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:?} {}", self.exe_path, self.args.join(" "))
	}

}

pub struct Bark {
	name: String,
	config: BarkConfig,
	counter: AtomicUsize,
}
pub struct BarkConfig {
	pub datadir: PathBuf,
	pub asp_url: String,
	pub network: String,
	pub bitcoind_url: String,
	pub bitcoind_cookie: PathBuf
}

impl BarkConfig {

	pub async fn create(self, name: impl AsRef<str>) -> anyhow::Result<Bark> {

		let output = BarkCommand::new()?
			.arg("create")
			.arg("--datadir")
			.arg(&self.datadir)
			.arg("--asp")
			.arg(&self.asp_url)
			.arg(format!("--{}", self.network))
			.arg("--bitcoind-cookie")
			.arg(&self.bitcoind_cookie)
			.arg("--bitcoind")
			.arg(&self.bitcoind_url)
			.tokio()
			.output()
			.await?;

		if !output.status.success() {
			let stdout = String::from_utf8(output.stdout)?;
			let stderr = String::from_utf8(output.stderr)?;

			error!("{}", stderr);
			error!("{}", stdout);

			anyhow::bail!("Failed to create {}", name.as_ref());
		}

		Ok(Bark {
			name: name.as_ref().to_string(),
			config: self,
			counter: AtomicUsize::new(0)
		})
	}
}

impl Bark {

	pub fn name(&self) -> &str {
		&self.name
	}

	pub async fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let json = self.run(["balance", "--json"]).await?;
		let json = serde_json::from_str::<serde_json::Value>(&json).unwrap();
		let sats = json.as_object().unwrap().get("offchain").unwrap().as_i64().unwrap();
		Ok(Amount::from_sat(sats as u64))
	}

	pub async fn get_address(&self) -> anyhow::Result<Address> {
		let address_string = self.run(["get-address"]).await?.trim().to_string();
		let address_unchecked = Address::<NetworkUnchecked>::from_str(&address_string)?;
		Ok(address_unchecked.assume_checked())
	}

	pub async fn get_vtxo_pubkey(&self) -> anyhow::Result<String> {
		Ok(self.run(["get-vtxo-pubkey"]).await?)
	}

	pub async fn send_round(&self, destination: impl fmt::Display, amount: Amount) -> anyhow::Result<()> {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send-round", &destination, &amount, "--verbose"]).await?;
		Ok(())
	}

	pub async fn send_oor(&self, destination: impl fmt::Display, amount: Amount) -> anyhow::Result<()> {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send-oor", &destination, &amount, "--verbose"]).await?;
		Ok(())
	}

	pub async fn onboard(&self, amount: Amount) -> anyhow::Result<()> {
		info!("{}: Onboard {}", self.name, amount);

		self.run(["onboard", &amount.to_string()]).await?;
		Ok(())
	}

	pub async fn run<I,S>(&self, args: I) -> anyhow::Result<String>
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		let args: Vec<String>  = args.into_iter().map(|x| x.as_ref().to_string()).collect();

		let mut command = BarkCommand::new()?;
		command
			.arg("--datadir")
			.arg(&self.config.datadir)
			.args(args);

		let output = command
			.tokio()
			.output()
			.await?;

		// Write logs to disk
		// Create a folder for each command
		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		let folder_name = self.config.datadir.join("cmd").join(count.to_string());
		fs::create_dir_all(&folder_name)?;

		let mut cmd_file = fs::File::create(folder_name.join("cmd"))?;
		write!(cmd_file, "{}", command)?;

		let mut stderr_file = fs::File::create(folder_name.join("stderr.log"))?;
		writeln!(stderr_file, "{}", String::from_utf8(output.stderr)?)?;

		let mut stdout_file = fs::File::create(folder_name.join("stdout.log"))?;
		let stdout_str = String::from_utf8(output.stdout)?;
		writeln!(stdout_file, "{}", stdout_str)?;

		if output.status.success() {
			return Ok(stdout_str.trim().to_string())
		}
		else {
			anyhow::bail!("Failed to execute {:?}", command)
		}
	}
}
