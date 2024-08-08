
#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;

mod database;
mod exit;
mod onchain;
mod psbtext;


use std::{fs, iter};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{bip32, secp256k1, Address, Amount, FeeRate, Network, OutPoint, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use tokio_stream::StreamExt;

use ark::{musig, BaseVtxo, OffboardRequest, VtxoRequest, Vtxo, VtxoId, VtxoSpec};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};
use aspd_rpc_client as rpc;


lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub struct ArkInfo {
	pub asp_pubkey: PublicKey,
	pub nb_round_nonces: usize,
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
}

/// Configuration of the Bark wallet.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
	/// The Bitcoin network to run Bark on.
	///
	/// Default value: signet.
	pub network: Network,

	/// The address of your ASP.
	pub asp_address: String,

	/// Path to PEM encoded ASP TLS certificate file.
	pub asp_cert: Option<PathBuf>,

	/// The address of the Esplora HTTP server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	pub esplora_address: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
	pub bitcoind_address: Option<String>,

	/// The path to the bitcoind rpc cookie file.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_cookiefile: Option<PathBuf>,

	/// The bitcoind RPC username.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_user: Option<String>,

	/// The bitcoind RPC password.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_pass: Option<String>,
}

impl Default for Config {
	fn default() -> Config {
		Config {
			network: Network::Signet,
			asp_address: "http://127.0.0.1:3535".to_owned(),
			asp_cert: None,
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
		}
	}
}

pub struct Wallet {
	config: Config,
	db: database::Db,
	onchain: onchain::Wallet,
	vtxo_seed: bip32::Xpriv,
	// ASP stuff
	asp: rpc::ArkServiceClient<tonic::transport::Channel>,
	ark_info: ArkInfo,
}

impl Wallet {
	/// Create new wallet.
	pub async fn create(
		datadir: &Path,
		mut config: Config,
		asp_cert: Option<Vec<u8>>,
	) -> anyhow::Result<Wallet> {
		info!("Creating new bark Wallet at {}", datadir.display());
		trace!("Config: {:?}", config);

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&datadir).context("can't create dir")?;
		if fs::read_dir(&datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		if let Some(cert) = asp_cert {
			if config.asp_cert.is_some() {
				bail!("Can't set the ASP cert file path in config and provide a raw cert file");
			}
			let path = fs::canonicalize(datadir)?.join("asp.cert");
			fs::write(&path, cert)
				.context("failed to write ASP cert file")?;
			config.asp_cert = Some(path);
		}

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&config)
			.expect("serialization can't error");
		fs::write(datadir.join("config.json"), config_str.as_bytes())
			.context("failed to write config file")?;

		// generate seed
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

		// write it to file
		fs::write(datadir.join("mnemonic"), mnemonic.to_string().as_bytes())
			.context("failed to write mnemonic")?;

		// from then on we can open the wallet
		Ok(Wallet::open(&datadir).await.context("failed to open")?)
	}

	/// Open existing wallet.
	pub async fn open(datadir: &Path) -> anyhow::Result<Wallet> {
		info!("Opening bark Wallet at {}", datadir.display());

		let config = {
			let path = datadir.join("config.json");
			let bytes = fs::read(&path)
				.with_context(|| format!("failed to read config file: {}", path.display()))?;
			serde_json::from_slice::<Config>(&bytes).context("invalid config file")?
		};
		trace!("Config: {:?}", config);

		// read mnemonic file
		let mnemonic_path = datadir.join("mnemonic");
		let mnemonic_str = fs::read_to_string(&mnemonic_path)
			.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
		let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;
		let seed = mnemonic.to_seed("");

		//TODO(stevenroose) check if bitcoind has txindex enabled

		// create on-chain wallet
		let chain_source = if let Some(ref url) = config.esplora_address {
			onchain::ChainSource::Esplora {
				url: url.clone(),
			}
		} else if let Some(ref url) = config.bitcoind_address {
			let auth = if let Some(ref c) = config.bitcoind_cookiefile {
				bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(c.clone())
			} else {
				bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			onchain::ChainSource::Bitcoind {
				url: url.clone(),
				auth: auth,
			}
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};
		let onchain = onchain::Wallet::create(config.network, seed, &datadir, chain_source)
			.context("failed to create onchain wallet")?;

		let db = database::Db::open(&datadir.join("db")).context("failed to open db")?;

		let vtxo_seed = {
			let master = bip32::Xpriv::new_master(config.network, &seed).unwrap();
			master.derive_priv(&SECP, &[350.into()]).unwrap()
		};

		let asp_uri = tonic::transport::Uri::from_str(&config.asp_address)
			.context("invalid asp addr")?;
		let asp_endpoint = if let Some(ref cert_path) = config.asp_cert {
			let domain = asp_uri.host().context("ASP address has no domain")?.to_owned();
			let cert = fs::read(cert_path)
				.with_context(|| format!("failed to read ASP cert file: {}", cert_path.display()))?;
			tonic::transport::Channel::builder(asp_uri)
				.tls_config(tonic::transport::ClientTlsConfig::new()
					.ca_certificate(tonic::transport::Certificate::from_pem(&cert))
					.domain_name(domain))?
		} else {
			asp_uri.try_into().context("failed to convert ASP addr into endpoint")?
		};
		let mut asp = rpc::ArkServiceClient::connect(asp_endpoint)
			.await.context("failed to connect to asp")?;

		let ark_info = {
			let res = asp.get_ark_info(rpc::Empty{})
				.await.context("ark info request failed")?.into_inner();
			if config.network != res.network.parse().context("invalid network from asp")? {
				bail!("ASP is for net {} while we are on net {}", res.network, config.network);
			}
			ArkInfo {
				asp_pubkey: PublicKey::from_slice(&res.pubkey).context("asp pubkey")?,
				nb_round_nonces: res.nb_round_nonces as usize,
				vtxo_expiry_delta: res.vtxo_expiry_delta as u16,
				vtxo_exit_delta: res.vtxo_exit_delta as u16,
			}
		};

		Ok(Wallet { config, db, onchain, vtxo_seed, asp, ark_info })
	}

	pub fn config(&self) -> &Config {
		&self.config
	}

	pub fn get_new_onchain_address(&mut self) -> anyhow::Result<Address> {
		self.onchain.new_address()
	}

	pub async fn onchain_balance(&mut self) -> anyhow::Result<Amount> {
		self.onchain.sync().await
	}

	pub async fn offchain_balance(&mut self) -> anyhow::Result<Amount> {
		self.sync_ark().await.context("ark sync error")?;

		let mut sum = Amount::ZERO;
		for vtxo in self.db.get_all_vtxos()? {
			sum += vtxo.spec().amount;
			debug!("Vtxo {}: {}", vtxo.id(), vtxo.spec().amount);
		}
		Ok(sum)
	}

	//TODO(stevenroose) remove
	pub async fn drop_vtxos(&self) -> anyhow::Result<()> {
		for vtxo in self.db.get_all_vtxos()? {
			self.db.remove_vtxo(vtxo.id())?;
		}
		self.db.store_claim_inputs(&[])?;
		Ok(())
	}

	// Onboard a vtxo with the given vtxo amount.
	//
	// NB we will spend a little more on-chain to cover minrelayfee.
	pub async fn onboard(&mut self, amount: Amount) -> anyhow::Result<()> {
		//TODO(stevenroose) impl key derivation
		let key = self.vtxo_seed.to_keypair(&SECP);

		let current_height = self.onchain.tip().await?;
		let spec = ark::VtxoSpec {
			user_pubkey: key.public_key(),
			asp_pubkey: self.ark_info.asp_pubkey,
			expiry_height: current_height + self.ark_info.vtxo_expiry_delta as u32,
			exit_delta: self.ark_info.vtxo_exit_delta,
			amount: amount,
		};
		let onboard_amount = amount + ark::onboard::onboard_surplus();
		let addr = Address::from_script(&ark::onboard::onboard_spk(&spec), self.config.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		self.onchain.sync().await.context("sync error")?;
		let onboard_tx = self.onchain.prepare_tx(addr, onboard_amount)?;
		let utxo = OutPoint::new(onboard_tx.unsigned_tx.compute_txid(), 0);

		// We ask the ASP to cosign our onboard vtxo reveal tx.
		let (user_part, priv_user_part) = ark::onboard::new_user(spec, utxo);
		let asp_part = {
			let res = self.asp.request_onboard_cosign(aspd_rpc_client::OnboardCosignRequest {
				user_part: {
					let mut buf = Vec::new();
					ciborium::into_writer(&user_part, &mut buf).unwrap();
					buf
				},
			}).await.context("error requesting onboard cosign")?;
			ciborium::from_reader::<ark::onboard::AspPart, _>(&res.into_inner().asp_part[..])
				.context("invalid ASP part in response")?
		};

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = ark::onboard::finish(user_part, asp_part, priv_user_part, &key);
		self.db.store_vtxo(&vtxo).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(onboard_tx)?;
		trace!("Broadcasting onboard tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.onchain.broadcast_tx(&tx).await?;

		info!("Onboard successfull");

		Ok(())
	}

	pub fn vtxo_pubkey(&self) -> PublicKey {
		self.vtxo_seed.to_keypair(&SECP).public_key()
	}

	fn add_new_vtxo(&mut self, vtxos: &SignedVtxoTree, leaf_idx: usize) -> anyhow::Result<()> {
		let exit_branch = vtxos.exit_branch(leaf_idx).unwrap();
		let dest = &vtxos.spec.vtxos[leaf_idx];
		let vtxo = Vtxo::Round {
			base: BaseVtxo {
				spec: VtxoSpec {
					user_pubkey: dest.pubkey,
					asp_pubkey: self.ark_info.asp_pubkey,
					expiry_height: vtxos.spec.expiry_height,
					exit_delta: vtxos.spec.exit_delta,
					amount: dest.amount,
				},
				utxo: vtxos.utxo,
			},
			leaf_idx: leaf_idx,
			exit_branch: exit_branch,
		};

		if self.db.has_spent_vtxo(vtxo.id())? {
			debug!("Not adding vtxo {} because we previously forfeited it", vtxo.id());
			return Ok(());
		}

		if self.db.get_vtxo(vtxo.id())?.is_none() {
			debug!("Storing new vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
			self.db.store_vtxo(&vtxo).context("failed to store vtxo")?;
		}
		Ok(())
	}

	/// Sync with the Ark and look for received vtxos.
	pub async fn sync_ark(&mut self) -> anyhow::Result<()> {
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		//TODO(stevenroose) we won't do reorg handling here
		let current_height = self.onchain.tip().await?;
		let last_sync_height = self.db.get_last_ark_sync_height()?;
		let req = rpc::FreshRoundsRequest { start_height: last_sync_height };
		let fresh_rounds = self.asp.get_fresh_rounds(req).await?.into_inner();

		for txid in fresh_rounds.txids {
			let txid = Txid::from_slice(&txid).context("invalid txid from asp")?;
			let req = rpc::RoundId { txid: txid.to_byte_array().to_vec() };
			let round = self.asp.get_round(req).await?.into_inner();

			let tree = SignedVtxoTree::decode(&round.signed_vtxos)
				.context("invalid signed vtxo tree from asp")?;

			for (idx, dest) in tree.spec.vtxos.iter().enumerate() {
				if dest.pubkey == vtxo_key.public_key() {
					self.add_new_vtxo(&tree, idx)?;
				}
			}
		}

		//TODO(stevenroose) we currently actually could accidentally be syncing
		// a round multiple times because new blocks could have come in since we
		// took current height

		self.db.store_last_ark_sync_height(current_height)?;

		// Then sync OOR vtxos.
		debug!("Emptying OOR mailbox at ASP...");
		let req = rpc::OorVtxosRequest { pubkey: vtxo_key.public_key().serialize().to_vec() };
		let resp = self.asp.empty_oor_mailbox(req).await.context("error fetching oors")?;
		let oors = resp.into_inner().vtxos.into_iter()
			.map(|b| Vtxo::decode(&b).context("invalid vtxo from asp"))
			.collect::<Result<Vec<_>, _>>()?;
		debug!("ASP has {} OOR vtxos for us", oors.len());
		for vtxo in oors {
			// Not sure if this can happen, but well.
			if self.db.has_spent_vtxo(vtxo.id())? {
				debug!("Not adding OOR vtxo {} because we previously forfeited it", vtxo.id());
			}

			if self.db.get_vtxo(vtxo.id())?.is_none() {
				debug!("Storing new OOR vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
				self.db.store_vtxo(&vtxo).context("failed to store OOR vtxo")?;
			}
		}

		Ok(())
	}

	pub async fn send_onchain(&mut self, addr: Address, amount: Amount) -> anyhow::Result<Txid> {
		Ok(self.onchain.send_money(addr, amount).await?)
	}

	pub async fn offboard_all(&mut self) -> anyhow::Result<()> {
		let _ = self.onchain.sync().await;
		self.sync_ark().await.context("failed to sync with ark")?;

		let input_vtxos = self.db.get_all_vtxos()?;
		let vtxo_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		let addr = self.onchain.new_address()?;

		self.participate_round(move |_id, offb_fr| {
			let fee = OffboardRequest::calculate_fee(&addr.script_pubkey(), offb_fr)
				.expect("bdk created invalid scriptPubkey");
			let offb = OffboardRequest {
				amount: vtxo_sum - fee,
				script_pubkey: addr.script_pubkey(),
			};
			Ok((input_vtxos.clone(), Vec::new(), vec![offb]))
		}).await.context("round failed")?;
		Ok(())
	}

	pub async fn send_oor_payment(&mut self, destination: PublicKey, amount: Amount) -> anyhow::Result<VtxoId> {
		self.sync_ark().await.context("failed to sync with ark")?;

		let current_height = self.onchain.tip().await?;
		let fr = self.onchain.regular_fee_rate();
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let output = VtxoRequest { pubkey: destination, amount };

		// We do some kind of naive fee estimation: we try create a tx,
		// if we don't have enough fee, we add the fee we were short to
		// the desired input amount and try again.
		let mut account_for_fee = ark::oor::OOR_MIN_FEE;
		let payment = loop {
			let input_vtxos = self.db.get_expiring_vtxos(amount + account_for_fee)?;
			let change = {
				let sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
				let avail = Amount::from_sat(sum.to_sat().saturating_sub(account_for_fee.to_sat()));
				if avail < output.amount {
					bail!("Balance too low: {}", sum);
				} else if avail < output.amount + ark::P2TR_DUST {
					info!("No change, emptying wallet.");
					None
				} else {
					let change_amount = avail - output.amount;
					info!("Adding change vtxo for {}", change_amount);
					Some(VtxoRequest {
						pubkey: vtxo_key.public_key(),
						amount: change_amount,
					})
				}
			};
			let outputs = Some(output.clone()).into_iter().chain(change).collect::<Vec<_>>();

			let payment = ark::oor::OorPayment::new(
				self.ark_info.asp_pubkey,
				self.ark_info.vtxo_exit_delta,
				input_vtxos,
				outputs,
			);

			if let Err(ark::oor::InsufficientFunds { missing, .. }) = payment.check_fee(fr) {
				account_for_fee += missing;
			} else {
				break payment;
			}
		};
		trace!("OOR tx sighashes: {:?}", payment.sighashes());

		let (sec_nonces, pub_nonces) = {
			let mut secs = Vec::with_capacity(payment.inputs.len());
			let mut pubs = Vec::with_capacity(payment.inputs.len());
			for _ in 0..payment.inputs.len() {
				let (s, p) = musig::nonce_pair(&vtxo_key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		};

		let req = rpc::OorCosignRequest {
			payment: payment.encode(),
			pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		};
		let resp = self.asp.request_oor_cosign(req).await.context("cosign request failed")?.into_inner();
		let len = payment.inputs.len();
		if resp.pub_nonces.len() != len || resp.partial_sigs.len() != len {
			bail!("invalid length of asp response");
		}

		let asp_pub_nonces = resp.pub_nonces.into_iter()
			.map(|b| musig::MusigPubNonce::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp pub nonces")?;
		let asp_part_sigs = resp.partial_sigs.into_iter()
			.map(|b| musig::MusigPartialSignature::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp part sigs")?;

		trace!("OOR prevouts: {:?}", payment.inputs.iter().map(|i| i.txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let tx = payment.sign_finalize_user(
			&vtxo_key,
			sec_nonces,
			&pub_nonces,
			&asp_pub_nonces,
			&asp_part_sigs,
		);
		trace!("OOR tx: {}", bitcoin::consensus::encode::serialize_hex(&tx.signed_transaction()));
		let vtxos = tx.output_vtxos(self.ark_info.asp_pubkey, self.ark_info.vtxo_exit_delta);

		// The first one is of the recipient, we will post it to their
		// mailbox.
		// TODO(stevenroose) in the future we will use nostr for this or something
		let user_vtxo = &vtxos[0];
		let req = rpc::OorVtxo {
			pubkey: destination.serialize().to_vec(),
			vtxo: user_vtxo.encode(),
		};
		if let Err(e) = self.asp.post_oor_mailbox(req).await {
			//TODO(stevenroose) print vtxo in hex after btc fixed hex
			error!("Failed to post the OOR vtxo to the recipients mailbox: {}", e);
			//NB we will continue to at least not lose our own change
		}

		if let Some(change_vtxo) = vtxos.get(1) {
			if let Err(e) = self.db.store_vtxo(change_vtxo) {
				//TODO(stevenroose) print vtxo in hex after btc fixed hex
				error!("Failed to store change vtxo from OOR tx: {}", e);
			}
		}

		for v in input_vtxos {
			self.db.remove_vtxo(v.id()).context("failed to drop input vtxo")?;
			self.db.store_spent_vtxo(v.id(), current_height)
				.context("failed to store forfeited vtxo")?;
		}

		Ok(user_vtxo.id())
	}

	pub async fn send_ark_payment(&mut self, destination: PublicKey, amount: Amount) -> anyhow::Result<()> {
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		// Prepare the payment.
		self.sync_ark().await.context("failed to sync with ark")?;
		let payment = VtxoRequest { pubkey: destination, amount };
		let input_vtxos = self.db.get_expiring_vtxos(amount)?;
		let change = { //TODO(stevenroose) account dust
			let sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
			if sum < payment.amount {
				bail!("Balance too low: {}", sum);
			} else if sum == payment.amount {
				info!("No change, emptying wallet.");
				None
			} else {
				let amount = sum - payment.amount;
				info!("Adding change vtxo for {}", amount);
				Some(VtxoRequest {
					pubkey: vtxo_key.public_key(),
					amount,
				})
			}
		};

		let vtxos = Some(payment).into_iter().chain(change).collect::<Vec<_>>();
		self.participate_round(move |_id, _offb_fr| {
			Ok((input_vtxos.clone(), vtxos.clone(), Vec::new()))
		}).await.context("round failed")?;
		Ok(())
	}

	pub async fn send_ark_onchain_payment(&mut self, addr: Address, amount: Amount) -> anyhow::Result<()> {
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		// Prepare the payment.
		self.sync_ark().await.context("failed to sync with ark")?;
		let input_vtxos = self.db.get_all_vtxos()?;

		// do a quick check to fail early if we don't have enough money
		let maybe_fee = OffboardRequest::calculate_fee(
			&addr.script_pubkey(), FeeRate::from_sat_per_vb(1).unwrap(),
		).expect("script from address");
		let in_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		if in_sum < amount + maybe_fee {
			bail!("Balance too low");
		}

		self.participate_round(move |_id, offb_fr| {
			let offb = OffboardRequest {
				script_pubkey: addr.script_pubkey(),
				amount: amount,
			};
			let out_value = amount + offb.fee(offb_fr).expect("script from address");
			let change = {
				if in_sum < out_value {
					bail!("Balance too low");
				} else if in_sum <= out_value + ark::P2TR_DUST {
					info!("No change, emptying wallet.");
					None
				} else {
					let amount = in_sum - out_value;
					info!("Adding change vtxo for {}", amount);
					Some(VtxoRequest {
						pubkey: vtxo_key.public_key(),
						amount,
					})
				}
			};

			Ok((input_vtxos.clone(), change.into_iter().collect(), vec![offb]))
		}).await.context("round failed")?;
		Ok(())
	}

	/// Participate in a round.
	///
	/// NB Instead of taking the input and output data as arguments, we take a closure that is
	/// called to get these values. This is so because for offboards, the fee rate used for the
	/// offboards is only announced in the beginning of the round and can change between round
	/// attempts. Lateron this will also be useful so we can randomize destinations between failed
	/// round attempts for better privacy.
	async fn participate_round(
		&mut self,
		mut round_input: impl FnMut(u64, FeeRate) -> anyhow::Result<
			(Vec<Vtxo>, Vec<VtxoRequest>, Vec<OffboardRequest>)
		>,
	) -> anyhow::Result<()> {
		self.sync_ark().await.context("ark sync error")?;
		let current_height = self.onchain.tip().await?;

		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		let mut events = self.asp.subscribe_rounds(rpc::Empty {}).await?.into_inner();

		// Wait for the next round start.
		info!("Waiting for a round start...");
		let (mut round_id, offboard_feerate) = loop {
			match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Start(rpc::RoundStart {
					round_id, offboard_feerate_sat_vkb,
				}) => {
					let offb_fr = FeeRate::from_sat_per_kwu(offboard_feerate_sat_vkb / 4);
					break (round_id, offb_fr);
				},
				_ => {},
			}
		};
		info!("Round started");

		let (input_vtxos, vtxo_reqs, offb_reqs) = round_input(round_id, offboard_feerate)
			.context("error providing round input")?;
		let vtxo_ids = input_vtxos.iter().map(|v| v.id()).collect::<HashSet<_>>();
		debug!("Spending vtxos: {:?}", vtxo_ids);


		'round: loop {
			let cosign_key = Keypair::new(&SECP, &mut rand::thread_rng());
			debug!("Participating in round {} with cosign pubkey {}",
				round_id, cosign_key.public_key(),
			);

			// Prepare round participation info.
			let (sec_nonces, pub_nonces) = {
				let mut secs = Vec::with_capacity(self.ark_info.nb_round_nonces);
				let mut pubs = Vec::with_capacity(self.ark_info.nb_round_nonces);
				for _ in 0..self.ark_info.nb_round_nonces {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};

			// The round has now started. We can submit our payment.
			trace!("Submitting payment request with {} inputs, {} vtxo outputs and {} offboard outputs",
				input_vtxos.len(), vtxo_reqs.len(), offb_reqs.len());
			self.asp.submit_payment(rpc::SubmitPaymentRequest {
				cosign_pubkey: cosign_key.public_key().serialize().to_vec(),
				input_vtxos: input_vtxos.iter().map(|v| v.encode()).collect(),
				payments: vtxo_reqs.iter().map(|r| {
					rpc::Payment {
						amount: r.amount.to_sat(),
						destination: Some(rpc::payment::Destination::VtxoPublicKey(
							r.pubkey.serialize().to_vec(),
						)),
					}
				}).chain(offb_reqs.iter().map(|r| {
					rpc::Payment {
						amount: r.amount.to_sat(),
						destination: Some(rpc::payment::Destination::OffboardSpk(
							r.script_pubkey.to_bytes(),
						)),
					}
				})).collect(),
				public_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
			}).await.context("submitting payment to asp")?;


			// ****************************************************************
			// * Wait for vtxo proposal from asp.
			// ****************************************************************

			let (vtxo_tree, round_tx, vtxo_signers, vtxo_agg_nonces) = loop {
				//TODO(stevenroose) should we really gracefully handle ASP malformed data?
				// panicking seems kinda ok since if we can't understand the ASP,
				// what are we even doing?
				match events.next().await.context("events stream broke")??.event.unwrap() {
					rpc::round_event::Event::VtxoProposal(p) => {
						assert_eq!(p.round_id, round_id, "missing messages");
						let vtxos = VtxoTreeSpec::decode(&p.vtxos_spec)
							.context("decoding vtxo spec")?;
						let tx = bitcoin::consensus::deserialize::<Transaction>(&p.round_tx)
							.context("decoding round tx")?;
						let cosigners = p.vtxos_signers.into_iter().map(|k| {
							PublicKey::from_slice(&k).context("invalid pubkey")
						}).collect::<anyhow::Result<Vec<_>>>()?;
						let vtxo_nonces = p.vtxos_agg_nonces.into_iter().map(|k| {
							musig::MusigAggNonce::from_slice(&k).context("invalid agg nonce")
						}).collect::<anyhow::Result<Vec<_>>>()?;

						break (vtxos, tx, cosigners, vtxo_nonces);
					},
					// If a new round started meanwhile, pick up on that one.
					rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
						error!("Unexpected new round start...");
						round_id = id;
						continue 'round;
					},
					//TODO(stevenroose) make this robust
					other => panic!("Unexpected message: {:?}", other),
				}
			};

			let vtxos_utxo = OutPoint::new(round_tx.compute_txid(), 0);
			let conns_utxo = OutPoint::new(round_tx.compute_txid(), 1);

			// Check that the proposal contains our inputs.
			let mut my_vtxos = vtxo_reqs.clone();
			for vtxo_req in vtxo_tree.iter_vtxos() {
				if let Some(i) = my_vtxos.iter().position(|v| v == vtxo_req) {
					my_vtxos.swap_remove(i);
				}
			}
			if !my_vtxos.is_empty() {
				bail!("asp didn't include all of our vtxos, missing: {:?}", my_vtxos);
			}
			let mut my_offbs = offb_reqs.clone();
			for offb in round_tx.output.iter().skip(2) {
				if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
					my_offbs.swap_remove(i);
				}
			}
			if !my_offbs.is_empty() {
				bail!("asp didn't include all of our offboards, missing: {:?}", my_offbs);
			}

			// Check that our cosign key is included in the cosigners.
			if !vtxo_signers.contains(&cosign_key.public_key()) {
				bail!("asp didn't include our cosign key in the vtxo tree");
			}
			let cosign_agg_pk = musig::combine_keys(vtxo_signers.iter().copied());
			if cosign_agg_pk != vtxo_tree.cosign_agg_pk {
				bail!("ASP provided incorrect aggregated cosign pubkey");
			}

			// Make vtxo signatures from top to bottom, just like sighashes are returned.
			let sighashes = vtxo_tree.sighashes(vtxos_utxo);
			assert_eq!(sighashes.len(), vtxo_agg_nonces.len());
			let signatures = iter::zip(sec_nonces.into_iter(), iter::zip(sighashes, vtxo_agg_nonces))
				.map(|(sec_nonce, (sighash, agg_nonce))| {
					musig::partial_sign(
						vtxo_signers.iter().copied(),
						agg_nonce,
						&cosign_key,
						sec_nonce,
						sighash.to_byte_array(),
						Some(vtxo_tree.cosign_taptweak().to_byte_array()),
						None,
					).0
				}).collect::<Vec<_>>();
			self.asp.provide_vtxo_signatures(rpc::VtxoSignaturesRequest {
				pubkey: cosign_key.public_key().serialize().to_vec(),
				signatures: signatures.iter().map(|s| s.serialize().to_vec()).collect(),
			}).await.context("providing signatures to asp")?;


			// ****************************************************************
			// * Then proceed to get a round proposal and sign forfeits
			// ****************************************************************

			// Wait for vtxo proposal from asp.
			let (vtxos, new_round_tx, forfeit_nonces) = loop {
				//TODO(stevenroose) should we really gracefully handle ASP malformed data?
				// panicking seems kinda ok since if we can't understand the ASP,
				// what are we even doing?
				match events.next().await.context("events stream broke")??.event.unwrap() {
					rpc::round_event::Event::RoundProposal(p) => {
						assert_eq!(p.round_id, round_id, "missing messages");
						let tx = bitcoin::consensus::deserialize::<Transaction>(&p.round_tx)
							.context("decoding round tx")?;
						let vtxos = SignedVtxoTree::decode(&p.signed_vtxos)
							.context("decoding vtxo spec")?;

						// Directly filter the forfeit nonces only for out inputs.
						let forfeit_nonces = p.forfeit_nonces.into_iter().filter_map(|f| {
							let id = VtxoId::from_slice(&f.input_vtxo_id)
								.expect("invalid vtxoid from asp"); //TODO(stevenroose) maybe handle?
							if vtxo_ids.contains(&id) {
								let nonces = f.pub_nonces.into_iter().map(|s| {
									musig::MusigPubNonce::from_slice(&s)
										.expect("invalid forfeit nonce from asp")
								}).collect::<Vec<_>>();
								Some((id, nonces))
							} else {
								None
							}
						}).collect::<HashMap<_, _>>();

						break (vtxos, tx, forfeit_nonces);
					},
					// If a new round started meanwhile, pick up on that one.
					rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
						error!("Unexpected new round start...");
						round_id = id;
						continue 'round;
					},
					//TODO(stevenroose) make this robust
					other => panic!("Unexpected message: {:?}", other),
				}
			};

			if round_tx != new_round_tx {
				bail!("ASP changed the round tx halfway the round.");
			}

			// Validate the vtxo tree.
			if let Err(e) = vtxos.validate_signatures() {
				bail!("Received incorrect signed vtxo tree from asp: {}", e);
			}

			// Make forfeit signatures.
			let connectors = ConnectorChain::new(
				forfeit_nonces.values().next().unwrap().len(),
				conns_utxo,
				self.ark_info.asp_pubkey,
			);
			let forfeit_signatures = input_vtxos.iter().map(|v| {
				let sigs = connectors.connectors().enumerate().map(|(i, conn)| {
					let (sighash, _tx) = ark::forfeit::forfeit_sighash(v, conn);
					let asp_nonce = forfeit_nonces.get(&v.id())
						.with_context(|| format!("missing asp forfeit nonce for {}", v.id()))?
						.get(i)
						.context("asp didn't provide enough forfeit nonces")?;

					let (nonce, sig) = musig::deterministic_partial_sign(
						&vtxo_key,
						[vtxo_key.public_key(), self.ark_info.asp_pubkey],
						[asp_nonce.clone()],
						sighash.to_byte_array(),
						Some(v.spec().exit_taptweak().to_byte_array()),
					);
					Ok((nonce, sig))
				}).collect::<anyhow::Result<Vec<_>>>()?;
				Ok((v.id(), sigs))
			}).collect::<anyhow::Result<HashMap<_, _>>>()?;
			self.asp.provide_forfeit_signatures(rpc::ForfeitSignaturesRequest {
				signatures: forfeit_signatures.into_iter().map(|(id, sigs)| {
					rpc::ForfeitSignatures {
						input_vtxo_id: id.bytes().to_vec(),
						pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
						signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
					}
				}).collect(),
			}).await.context("providing signatures to asp")?;


			// ****************************************************************
			// * Wait for the finishing of the round.
			// ****************************************************************

			trace!("Waiting for round finish...");
			let (new_vtxos, round_tx) = match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Finished(f) => {
					if f.round_id != round_id {
						bail!("Unexpected round ID from round finished event: {} != {}",
							f.round_id, round_id);
					}
					let vtxos = SignedVtxoTree::decode(&f.signed_vtxos)
						.context("invalid vtxo tree from asp")?;
					let tx = bitcoin::consensus::deserialize::<Transaction>(&f.round_tx)
						.context("invalid round tx from asp")?;
					(vtxos, tx)
				},
				// If a new round started meanwhile, pick up on that one.
				rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
					warn!("Unexpected new round start...");
					round_id = id;
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			if vtxos != new_vtxos {
				bail!("ASP changed the vtxo tree halfway the round");
			}

			// We also broadcast the tx, just to have it go around faster.
			info!("Round finished, broadcasting round tx {}", round_tx.compute_txid());
			if let Err(e) = self.onchain.broadcast_tx(&round_tx).await {
				warn!("Couldn't broadcast round tx: {}", e);
			}

			// Then add our change vtxo(s) by just checking all vtxos that might be ours.
			for (idx, dest) in vtxos.spec.vtxos.iter().enumerate() {
				if dest.pubkey == vtxo_key.public_key() {
					self.add_new_vtxo(&vtxos, idx)?;
				}
			}

			// And remove the input vtxos.
			for v in input_vtxos {
				self.db.remove_vtxo(v.id()).context("failed to drop input vtxo")?;
				self.db.store_spent_vtxo(v.id(), current_height)
					.context("failed to store forfeited vtxo")?;
			}

			info!("Finished payment");
			break;
		}

		Ok(())
	}
}
