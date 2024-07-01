

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::{Amount, FeeRate, OutPoint, Sequence, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::{rand, KeyPair, PublicKey};
use bitcoin::sighash::TapSighash;

use ark::{musig, OffboardRequest, VtxoRequest, Vtxo, VtxoId};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};

use crate::{SECP, App};
use crate::database::ForfeitVtxo;
use crate::util::FeeRateExt;

#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start {
		id: u64,
		offboard_feerate: FeeRate,
	},
	VtxoProposal {
		id: u64,
		round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		vtxos_signers: Vec<PublicKey>,
		vtxos_agg_nonces: Vec<musig::MusigAggNonce>,
	},
	RoundProposal {
		id: u64,
		round_tx: Transaction,
		vtxos: SignedVtxoTree,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		id: u64,
		round_tx: Transaction,
		vtxos: SignedVtxoTree,
	},
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<Vtxo>,
		outputs: Vec<VtxoRequest>,
		offboards: Vec<OffboardRequest>,
		cosign_pubkey: PublicKey,
		public_nonces: Vec<musig::MusigPubNonce>,
	},
	VtxoSignatures {
		pubkey: PublicKey,
		signatures: Vec<musig::MusigPartialSignature>,
	},
	ForfeitSignatures {
		signatures: Vec<(VtxoId, Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)>,
	},
}

fn validate_payment(
	inputs: &[Vtxo],
	outputs: &[VtxoRequest],
	offboards: &[OffboardRequest],
	offboard_feerate: FeeRate,
) -> bool {
	let mut in_set = HashSet::with_capacity(inputs.len());
	let mut in_sum = Amount::ZERO;
	for input in inputs {
		in_sum = match in_sum.checked_add(input.amount()) {
			Some(sum) => sum,
			None => return false
		};

		if in_sum > Amount::MAX_MONEY || !in_set.insert(input.id()) {
			return false;
		}
	}

	let mut out_sum = Amount::ZERO;
	for output in outputs {
		out_sum = match out_sum.checked_add(output.amount) {
			Some(sum) => sum,
			None => return false
		};
		if out_sum > in_sum {
			return false;
		}
	}

	for offboard in offboards {
		let fee = match offboard.fee(offboard_feerate) {
			Some(v) => v,
			None => return false,
		};

		// out_sum = out_sum + offboard_amount + fee
		out_sum = match out_sum.checked_add(offboard.amount).and_then(|s| s.checked_add(fee)) {
			None => return false,
			Some(sum) => sum
		};
		if out_sum > in_sum {
			return false;
		}
	}

	true
}

//TODO(stevenroose) we call this method at least once for each user, potentially dossable,
// so we should keep a cached version of all these variables for the entire round
fn validate_partial_vtxo_sigs(
	cosigners: impl IntoIterator<Item = PublicKey>,
	agg_nonces: &[musig::MusigAggNonce],
	sighashes: &[TapSighash],
	taptweak: [u8; 32],
	user_pubkey: PublicKey,
	user_pub_nonces: &[musig::MusigPubNonce],
	user_signatures: &[musig::MusigPartialSignature],
) -> bool {
	let key_agg = musig::tweaked_key_agg(cosigners, taptweak).0;
	for i in 0..agg_nonces.len() {
		let session = musig::MusigSession::new(
			&musig::SECP,
			&key_agg,
			agg_nonces[i],
			musig::zkp::Message::from_digest(sighashes[i].to_byte_array()),
		);
		let success = session.partial_verify(
			&musig::SECP,
			&key_agg,
			user_signatures[i].clone(),
			user_pub_nonces[i],
			musig::pubkey_to(user_pubkey),
		);
		if !success {
			debug!("User provided invalid partial vtxo sig for node {}", i);
			return false;
		}
	}
	true
}

fn validate_forfeit_sigs(
	connectors: &ConnectorChain,
	user_nonces: &[musig::MusigPubNonce],
	part_sigs: &[musig::MusigPartialSignature],
) -> anyhow::Result<()> {
	if user_nonces.len() != connectors.len() || part_sigs.len() != connectors.len() {
		bail!("not enough forfeit signatures provided");
	}

	Ok(())
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_scheduler(
	app: Arc<App>,
	mut round_input_rx: tokio::sync::mpsc::UnboundedReceiver<RoundInput>,
	mut round_trigger_rx: tokio::sync::mpsc::Receiver<()>,
) -> anyhow::Result<()> {
	let cfg = &app.config;

	info!("Onchain balance: {}", app.sync_onchain_wallet().await?);

	//TODO(stevenroose) somehow get these from a fee estimator service
	let offboard_feerate = FeeRate::from_sat_per_vb(10).unwrap();
	let round_tx_feerate = FeeRate::from_sat_per_vb(10).unwrap();

	'round: loop {
		// Sleep for the round interval, but discard all incoming messages.
		tokio::pin! { let timeout = tokio::time::sleep(cfg.round_interval); }
		'sleep: loop {
			tokio::select! {
				() = &mut timeout => break 'sleep,
				Some(()) = round_trigger_rx.recv() => {
					info!("Starting round based on admin RPC trigger");
					break 'sleep;
				},
				_ = round_input_rx.recv() => {},
			}
		}

		let _ = app.rounds().round_busy.write().await;
		let round_id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() /
			cfg.round_interval.as_secs();
		info!("Starting round {}", round_id);

		// Start new round, announce.
		let _ = app.rounds().round_event_tx.send(RoundEvent::Start { id: round_id, offboard_feerate });

		// Allocate this data once per round so that we can keep them 
		// Perhaps we could even keep allocations between all rounds, but time
		// in between attempts is way more critial than in between rounds.
		let mut all_inputs = HashMap::<VtxoId, Vtxo>::new();
		let mut all_outputs = Vec::<VtxoRequest>::new();
		let mut all_offboards = Vec::<OffboardRequest>::new();
		let mut cosigners = HashSet::<PublicKey>::new();
		let mut vtxo_pub_nonces = HashMap::new();
		let mut allowed_inputs = HashSet::new();

		// In this loop we will try to finish the round and make new attempts.
		'attempt: loop {
			let balance = app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			info!("Current wallet balance: {}", balance);

			all_inputs.clear();
			all_outputs.clear();
			all_offboards.clear();
			cosigners.clear();
			vtxo_pub_nonces.clear();
			// NB allowed_inputs should NOT be cleared here.

			// Generate a one-time use signing key.
			let cosign_key = KeyPair::new(&SECP, &mut rand::thread_rng());
			cosigners.insert(cosign_key.public_key());

			// Start receiving payments.
			//TODO(stevenroose) we need a check to see when we have all data we need so we can skip
			// timeout
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_submit_time); }
			'receive: loop {
				tokio::select! {
					() = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::RegisterPayment {
							inputs, outputs, offboards, cosign_pubkey, public_nonces,
						} => {
							//TODO(stevenroose) verify ownership over inputs

							if !allowed_inputs.is_empty() {
								// This means we're not trying first time and we filter inputs.
								if let Some(bad) = inputs.iter().find(|i| allowed_inputs.contains(&i.id())) {
									warn!("User attempted to submit invalid input: {}", bad.id());
									//TODO(stevenroose) would be nice if user saw this
									continue 'receive;
								}
							}

							//TODO(stevenroose) check that vtxos exist!

							if !validate_payment(&inputs, &outputs, &offboards, offboard_feerate) {
								warn!("User submitted bad payment: ins {:?}; outs {:?}; offb {:?}",
									inputs, outputs, offboards);
								continue 'receive;
							}

							trace!("Received {} inputs, {} outputs and {} offboards from user",
								inputs.len(), outputs.len(), offboards.len());
							all_inputs.extend(inputs.into_iter().map(|v| (v.id(), v)));
							//TODO(stevenroose) somehow check if a tree using these outputs
							//will exceed the config.nb_round_nonces number of nodes
							all_outputs.extend(outputs);
							all_offboards.extend(offboards);
							//TODO(stevenroose) handle duplicate cosign key
							assert!(cosigners.insert(cosign_pubkey));
							vtxo_pub_nonces.insert(cosign_pubkey, public_nonces);
						},
						v => debug!("Received unexpected input: {:?}", v),
					}
				}
			}
			if all_inputs.is_empty() || (all_outputs.is_empty() && all_offboards.is_empty()) {
				info!("Nothing to do this round, sitting it out...");
				continue 'round;
			}
			info!("Received {} inputs and {} outputs for round", all_inputs.len(), all_outputs.len());
			// Make sure we don't allow other inputs next attempt.
			allowed_inputs.clear();
			allowed_inputs.extend(all_inputs.keys().copied());

			// Since it's possible in testing that we only have to do onboards,
			// and since it's pretty annoying to deal with the case of no vtxos,
			// if there are no vtxos, we will just add a fake vtxo for the ASP.
			// In practice, in later versions, it is very likely that the ASP
			// will actually want to create change vtxos, so temporarily, this
			// dummy vtxo will be a placeholder for a potential change vtxo.
			if all_outputs.is_empty() {
				lazy_static::lazy_static! {
					static ref UNSPENDABLE: PublicKey =
						"031575a4c3ad397590ccf7aa97520a60635c3215047976afb9df220bc6b4241b0d".parse().unwrap();
				}
				all_outputs.push(VtxoRequest {
					pubkey: *UNSPENDABLE,
					//TODO(stevenroose) replace with the p2tr dust value 
					amount: ark::fee::DUST,
				});
			}


			// ****************************************************************
			// * Vtxo tree construction and signing
			// *
			// * - We will always store vtxo tx data from top to bottom,
			// *   meaning from the root tx down to the leaves.
			// ****************************************************************

			let tip = app.bitcoind.get_block_count()? as u32;
			let expiry = tip + cfg.vtxo_expiry_delta as u32;
			debug!("Current tip is {}, so round vtxos will expire at {}", tip, expiry);

			let cosign_agg_pk = musig::combine_keys(cosigners.iter().copied());
			let vtxos_spec = VtxoTreeSpec::new(
				all_outputs,
				cosign_agg_pk,
				app.master_key.public_key(),
				expiry,
				cfg.vtxo_exit_delta,
			);
			//TODO(stevenroose) this is super inefficient, improve this with direct getter
			let nb_nodes = vtxos_spec.build_unsigned_tree(OutPoint::null()).nb_nodes();
			//TODO(stevenroose) handle this better to avoid obvious DoS
			assert!(nb_nodes <= cfg.nb_round_nonces);
			let connector_output = ConnectorChain::output(
				all_inputs.len(), app.master_key.public_key(),
			);

			// Build round tx.
			let spendable_utxos = app.spendable_expired_vtxos(tip)?;
			if !spendable_utxos.is_empty() {
				debug!("Will be spending {} round-related UTXOs with total value of {}",
					spendable_utxos.len(), spendable_utxos.iter().map(|v| v.amount()).sum::<Amount>(),
				);
				for u in &spendable_utxos {
					trace!("Including round-related UTXO {} with value {}", u.point, u.amount());
				}
			}
			//TODO(stevenroose) think about if we can release lock sooner
			let mut wallet = app.wallet.lock().await;
			let mut round_tx_psbt = {
				let mut b = wallet.build_tx();
				b.ordering(bdk::wallet::tx_builder::TxOrdering::Untouched);
				b.nlocktime(LockTime::from_height(tip).expect("actual height"));
				for utxo in &spendable_utxos {
					b.add_foreign_utxo_with_sequence(
						utxo.point, utxo.psbt.clone(), utxo.weight, Sequence::ZERO,
					).expect("bdk rejected foreign utxo");
				}
				b.add_recipient(vtxos_spec.cosign_spk(), vtxos_spec.total_required_value().to_sat());
				b.add_recipient(connector_output.script_pubkey, connector_output.value);
				for offb in &all_offboards {
					b.add_recipient(offb.script_pubkey.clone(), offb.amount.to_sat());
				}
				b.fee_rate(round_tx_feerate.to_bdk());
				b.finish().expect("bdk failed to create round tx")
			};
			let round_tx = round_tx_psbt.clone().extract_tx();
			let vtxos_utxo = OutPoint::new(round_tx.txid(), 0);
			let conns_utxo = OutPoint::new(round_tx.txid(), 1);

			// Generate vtxo nonces and combine with user's nonces.
			let (sec_vtxo_nonces, pub_vtxo_nonces) = {
				let mut secs = Vec::with_capacity(nb_nodes);
				let mut pubs = Vec::with_capacity(nb_nodes);
				for _ in 0..nb_nodes {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};
			let agg_vtxo_nonces = {
				let mut ret = Vec::with_capacity(nb_nodes);
				let mut buf = Vec::with_capacity(cosigners.len());
				for i in 0..nb_nodes {
					buf.clear();
					buf.push(pub_vtxo_nonces[i]);
					buf.extend(vtxo_pub_nonces.values().map(|nonces| nonces[i]));
					ret.push(musig::MusigAggNonce::new(&musig::SECP, &buf));
				}
				ret
			};
			let vtxo_sighashes = vtxos_spec.sighashes(vtxos_utxo);
			assert_eq!(vtxo_sighashes.len(), agg_vtxo_nonces.len());

			// Send out vtxo proposal to signers.
			let _ = app.rounds().round_event_tx.send(RoundEvent::VtxoProposal {
				id: round_id,
				round_tx: round_tx.clone(),
				vtxos_spec: vtxos_spec.clone(),
				vtxos_signers: cosigners.iter().copied().collect(),
				vtxos_agg_nonces: agg_vtxo_nonces.clone(),
			});

			// Wait for signatures from users.
			//TODO(stevenroose) we need a check to see when we have all data we need so we can skip
			// timeout
			let mut vtxo_part_sigs = HashMap::with_capacity(cosigners.len());
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::VtxoSignatures { pubkey, signatures } => {
							if !cosigners.contains(&pubkey) {
								debug!("Received signatures from non-signer: {}", pubkey);
								continue 'receive;
							}
							trace!("Received signatures from cosigner {}", pubkey);

							if validate_partial_vtxo_sigs(
								cosigners.iter().copied(),
								&agg_vtxo_nonces,
								&vtxo_sighashes,
								vtxos_spec.cosign_taptweak().to_byte_array(),
								pubkey,
								vtxo_pub_nonces.get(&pubkey).expect("user is cosigner"),
								&signatures,
							) {
								vtxo_part_sigs.insert(pubkey, signatures);
							} else {
								debug!("Received invalid partial vtxo sigs from signer: {}", pubkey);
								continue 'receive;
							}
						},
						v => debug!("Received unexpected input: {:?}", v),
					}
				}
			}

			//TODO(stevenroose) kick out signers that didn't sign and retry
			if cosigners.len() - 1 != vtxo_part_sigs.len() {
				error!("Not enough vtxo partial signatures! ({} != {})",
					cosigners.len() - 1, vtxo_part_sigs.len());
				continue 'round;
			}

			// Combine the vtxo signatures.
			#[cfg(debug_assertions)]
			let mut partial_sigs = Vec::with_capacity(nb_nodes);
			let mut final_vtxo_sigs = Vec::with_capacity(nb_nodes);
			for (i, sec_nonce) in sec_vtxo_nonces.into_iter().enumerate() {
				let others = vtxo_part_sigs.values().map(|s| s[i].clone()).collect::<Vec<_>>();
				let (_partial, final_sig) = musig::partial_sign(
					cosigners.iter().copied(),
					agg_vtxo_nonces[i],
					&cosign_key,
					sec_nonce,
					vtxo_sighashes[i].to_byte_array(),
					Some(vtxos_spec.cosign_taptweak().to_byte_array()),
					Some(&others),
				);
				final_vtxo_sigs.push(final_sig.expect("we provided others"));
				#[cfg(debug_assertions)]
				partial_sigs.push(_partial);
			}
			#[cfg(debug_assertions)]
			debug_assert!(validate_partial_vtxo_sigs(
				cosigners.iter().copied(),
				&agg_vtxo_nonces,
				&vtxo_sighashes,
				vtxos_spec.cosign_taptweak().to_byte_array(),
				cosign_key.public_key(),
				&pub_vtxo_nonces,
				&partial_sigs,
			), "our own partial signatures were wrong");

			// Then construct the final signed vtxo tree.
			let signed_vtxos = SignedVtxoTree::new(vtxos_spec, vtxos_utxo, final_vtxo_sigs);
			debug_assert!(signed_vtxos.validate_signatures().is_ok(), "invalid signed vtxo tree");


			// ****************************************************************
			// * Broadcast signed vtxo tree and gather forfeit signatures
			// ****************************************************************

			// Prepare nonces for forfeit txs.
			// We need to prepare N nonces for each of N inputs.
			let mut forfeit_pub_nonces = HashMap::with_capacity(all_inputs.len());
			let mut forfeit_sec_nonces = HashMap::with_capacity(all_inputs.len());
			for id in all_inputs.keys() {
				let mut secs = Vec::with_capacity(all_inputs.len());
				let mut pubs = Vec::with_capacity(all_inputs.len());
				for _ in 0..all_inputs.len() {
					let (s, p) = musig::nonce_pair(&app.master_key);
					secs.push(s);
					pubs.push(p);
				}
				forfeit_pub_nonces.insert(*id, pubs);
				forfeit_sec_nonces.insert(*id, secs);
			}

			// Send out round proposal to signers.
			let _ = app.rounds().round_event_tx.send(RoundEvent::RoundProposal {
				id: round_id,
				round_tx: round_tx.clone(),
				vtxos: signed_vtxos.clone(),
				forfeit_nonces: forfeit_pub_nonces.clone(),
			});

			let connectors = ConnectorChain::new(
				all_inputs.len(), conns_utxo, app.master_key.public_key(),
			);

			// Wait for signatures from users.
			//TODO(stevenroose) we need a check to see when we have all data we need so we can skip
			// timeout
			let mut forfeit_part_sigs = HashMap::with_capacity(all_inputs.len());
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::ForfeitSignatures { signatures } => {
							for (id, nonces, sigs) in signatures {
								if let Some(_vtxo) = all_inputs.get(&id) {
									//TODO(stevenroose) actually validate forfeit txs
									// probably make one method that both validates and cross-signs
									// the forfeit txs at the same time to save memory and not
									// double-create the musig context
									match validate_forfeit_sigs(
										&connectors,
										&nonces,
										&sigs,
									) {
										Ok(()) => { forfeit_part_sigs.insert(id, (nonces, sigs)); },
										Err(e) => debug!("Invalid forfeit sigs for {}: {}", id, e),
									}
								} else {
									debug!("User provided forfeit sigs for unknown input {}", id);
								}
							}

							// Check whether we have all and can skip the loop.
							if forfeit_part_sigs.len() == all_inputs.len() &&
								vtxo_part_sigs.len() == cosigners.len() - 1 {
								debug!("We received all signatures, continuing round...");
								break 'receive;
							}
						},
						v => debug!("Received unexpected input: {:?}", v),
					}
				}
			}

			//TODO(stevenroose) kick out signers that didn't sign and retry
			if forfeit_part_sigs.len() != all_inputs.len() {
				error!("Not enough forfeit partial signatures! ({} != {})",
					forfeit_part_sigs.len(), all_inputs.len());
				continue 'round;
			}

			// Finish the forfeit signatures.
			let mut forfeit_sigs = HashMap::with_capacity(all_inputs.len());
			let mut missing_forfeits = HashSet::new();
			for (id, vtxo) in &all_inputs {
				if let Some((user_nonces, partial_sigs)) = forfeit_part_sigs.get(id) {
					let sec_nonces = forfeit_sec_nonces.remove(id).unwrap().into_iter();
					let pub_nonces = forfeit_pub_nonces.get(id).unwrap();
					let connectors = connectors.connectors();
					let mut sigs = Vec::with_capacity(all_inputs.len());
					for (i, (conn, sec)) in connectors.zip(sec_nonces.into_iter()).enumerate() {
						let (sighash, _) = ark::forfeit::forfeit_sighash(&vtxo, conn);
						let agg_nonce = musig::nonce_agg([user_nonces[i], pub_nonces[i]]);
						let (_, sig) = musig::partial_sign(
							[app.master_key.public_key(), vtxo.spec().user_pubkey],
							agg_nonce,
							&app.master_key,
							sec,
							sighash.to_byte_array(),
							Some(vtxo.spec().exit_taptweak().to_byte_array()),
							Some(&[partial_sigs[i]]),
						);
						sigs.push(sig.expect("should be signed"));
					}
					forfeit_sigs.insert(*id, sigs);
				} else {
					missing_forfeits.insert(*id);
				}
			}
			//TODO(stevenroose) if missing forfeits, ban inputs and restart round


			// ****************************************************************
			// * Finish the round
			// ****************************************************************

			// Sign the on-chain tx.
			app.sign_round_utxo_inputs(&mut round_tx_psbt).context("signing round inputs")?;
			let opts = bdk::SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = wallet.sign(&mut round_tx_psbt, opts)?;
			assert!(finalized);
			let round_tx = round_tx_psbt.extract_tx();
			wallet.commit()?;
			drop(wallet); // we no longer need the lock

			// Broadcast over bitcoind.
			debug!("Broadcasting round tx {}", round_tx.txid());
			let bc = app.bitcoind.send_raw_transaction(&round_tx);
			if let Err(e) = bc {
				warn!("Couldn't broadcast round tx: {}", e);
			}

			// Send out the finished round to users.
			trace!("Sending out finish event.");
			let _ = app.rounds().round_event_tx.send(RoundEvent::Finished {
				id: round_id,
				vtxos: signed_vtxos.clone(),
				round_tx: round_tx.clone(),
			});

			// Store forfeit txs and round info in database.
			let round_id = round_tx.txid();
			for (id, vtxo) in all_inputs {
				let forfeit_sigs = forfeit_sigs.remove(&id).unwrap();
				let point = vtxo.point();
				trace!("Storing forfeit vtxo for vtxo {}", point);
				app.db.store_forfeit_vtxo(ForfeitVtxo { vtxo, forfeit_sigs })?;
			}

			trace!("Storing round result");
			app.db.store_round(round_tx.clone(), signed_vtxos)?;

			//TODO(stevenroose) we should have a system that actually tracks that this tx is
			// getting confirmed!
			let spent_rounds = spendable_utxos.iter().map(|u| u.point.txid).collect::<HashSet<_>>();
			for round in spent_rounds {
				debug!("Removing round with id {} because UTXOs spent", round);
				app.db.remove_round(round)?;
			}

			info!("Finished round {} with tx {}", round_id, round_tx.txid());
			break 'attempt;
		}
	}
}
