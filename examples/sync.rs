//! Sync a view key and print the balance.
//!
//!     cargo run --release --example sync -- <UFVK> <BIRTHDAY> [DB_PATH]

use seer_sync::{run, BlockHeight, Db, LwdClient, Network, ScanningKeys, UnifiedFullViewingKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: sync <ufvk> <birthday-height> [db-path]";
    let ufvk_str = args.next().expect(usage);
    let birthday: u32 = args.next().expect(usage).parse()?;
    let path = args.next().unwrap_or_else(|| "seer.db".into());

    // Parse the view key.
    let ufvk = UnifiedFullViewingKey::decode(&Network::MainNetwork, &ufvk_str)?;
    let keys = ScanningKeys::from_ufvk(&ufvk);

    // Open the DB and init the account row with the birthday.
    let db = Db::open(&path)?;
    db.init_account(BlockHeight::from_u32(birthday))?;

    // Connect to a lightwalletd server.
    let client = LwdClient::connect_auto(Network::MainNetwork)
        .await
        .map_err(|_| "no lightwalletd server available")?;

    // Run the sync engine.  Blocks until caught up to the tip, then polls.
    run(client, &keys, Network::MainNetwork, &db).await?;

    // Print balance: sum of unspent note values per pool.
    let total = db.balance()?;
    println!("balance: {total} zat");

    Ok(())
}