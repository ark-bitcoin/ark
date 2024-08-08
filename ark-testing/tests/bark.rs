use ark_testing::context::TestContext;

use bitcoincore_rpc::bitcoin::amount::Amount;

#[tokio::test]
async fn bark_version() {
	let ctx = TestContext::new("bark_version");
	let bitcoind = ctx.bitcoind("bitcoind-1").await.unwrap();
	let aspd = ctx.aspd("aspd-1", &bitcoind).await.unwrap();

	//
	let bark = ctx.bark("bark-1".to_string(), &bitcoind, &aspd).await.unwrap();
	let result = bark.run(&[&"--version"]).await.unwrap();

	assert!(result.starts_with("bark-client"));
}

#[tokio::test]
async fn onboard_bark() {
	let ctx = TestContext::new("bark/onboard_bark");
	let bitcoind = ctx.bitcoind("bitcoind-1").await.unwrap();
	let aspd = ctx.aspd("aspd-1", &bitcoind).await.unwrap();
	let bark = ctx.bark("bark-1".to_string(), &bitcoind, &aspd).await.unwrap();

	// Generate initial funds
	bitcoind.generate(101).await.unwrap();

	// Get the bark-address and fund it
	bitcoind.fund_bark(&bark, Amount::from_sat(100_000)).await.unwrap();
	bark.onboard(Amount::from_sat(90_000)).await.unwrap();

	// TODO: Verify the onboarded balance
	// The current cli only provides logs in stdout. This is to annoying
	let _: String = bark.run(["balance"]).await.unwrap();
}

#[tokio::test]
async fn multiple_round_payments() {
	// Initialize the test
	let ctx = TestContext::new("bark/multiple_round_payments");
	let bitcoind = ctx.bitcoind("bitcoind-1").await.unwrap();
	let aspd = ctx.aspd("aspd-1", &bitcoind).await.unwrap();

	// Fund the asp
	bitcoind.generate(106).await.unwrap();
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await.unwrap();

	// Create a few clients
	let bark_1 = ctx.bark("bark_1".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_2 = ctx.bark("bark_2".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_3 = ctx.bark("bark_3".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_4 = ctx.bark("bark_4".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_5 = ctx.bark("bark_5".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_6 = ctx.bark("bark_6".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_7 = ctx.bark("bark_7".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark_8 = ctx.bark("bark_8".to_string(), &bitcoind, &aspd).await.unwrap();

	// Provide onchain funds
	tokio::try_join!(
		bitcoind.fund_bark(&bark_1, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_2, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_3, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_4, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_5, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_6, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_7, Amount::from_sat(90_000)),
		bitcoind.fund_bark(&bark_8, Amount::from_sat(90_000)),
	).unwrap();

	// Onboard all the clients
	tokio::try_join!(
		bark_1.onboard(Amount::from_sat(80_000)),
		bark_2.onboard(Amount::from_sat(80_000)),
		bark_3.onboard(Amount::from_sat(80_000)),
		bark_4.onboard(Amount::from_sat(80_000)),
		bark_5.onboard(Amount::from_sat(80_000)),
		bark_6.onboard(Amount::from_sat(80_000)),
		bark_7.onboard(Amount::from_sat(80_000)),
		bark_8.onboard(Amount::from_sat(80_000)),
	).unwrap();

		// Get all the vtxo pubkeys
	let (a1, a2, a3, a4, a5, a6, a7, a8) =
		tokio::try_join!(
			bark_1.get_vtxo_pubkey(),
			bark_2.get_vtxo_pubkey(),
			bark_3.get_vtxo_pubkey(),
			bark_4.get_vtxo_pubkey(),
			bark_5.get_vtxo_pubkey(),
			bark_6.get_vtxo_pubkey(),
			bark_7.get_vtxo_pubkey(),
			bark_8.get_vtxo_pubkey(),
	).unwrap();

	// Perform send_round
	tokio::try_join!(
		bark_1.send_round(a2, Amount::from_sat(100)),
		bark_2.send_round(a3, Amount::from_sat(200)),
		bark_3.send_round(a4, Amount::from_sat(300)),
		bark_4.send_round(a5, Amount::from_sat(400)),
		bark_5.send_round(a6, Amount::from_sat(500)),
		bark_6.send_round(a7, Amount::from_sat(600)),
		bark_7.send_round(a8, Amount::from_sat(700)),
		bark_8.send_round(a1, Amount::from_sat(800)),
	).unwrap();

}

#[tokio::test]
async fn oor() {
	// Initialize the test
	let ctx = TestContext::new("bark/oor");
	let bitcoind = ctx.bitcoind("bitcoind-1").await.unwrap();
	let aspd = ctx.aspd("aspd-1", &bitcoind).await.unwrap();

	// Fund the asp
	bitcoind.generate(106).await.unwrap();
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await.unwrap();

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await.unwrap();
	bitcoind.fund_bark(&bark1, Amount::from_sat(90_000)).await.unwrap();
	bitcoind.fund_bark(&bark2, Amount::from_sat(5_000)).await.unwrap();
	bark1.onboard(Amount::from_sat(80_000)).await.unwrap();

	let pk2 = bark2.get_vtxo_pubkey().await.unwrap();
	bark1.send_oor(pk2, Amount::from_sat(20_000)).await.unwrap();

	assert_eq!(58_035, bark1.offchain_balance().await.unwrap().to_sat());
	assert_eq!(20_000, bark2.offchain_balance().await.unwrap().to_sat());
}

