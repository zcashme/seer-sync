//! Sync the bundled SQLite store and print the account's balance and history.
//!
//!     cargo run --release --features db --example balance -- <UFVK> <BIRTHDAY> [DB_PATH]

use seer_sync::db::Db;
use seer_sync::{BlockHeight, Network, ViewKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: balance <ufvk> <birthday-height> [db-path]";
    let key = ViewKey::decode(&Network::MainNetwork, &args.next().expect(usage))?;
    let birthday: u32 = args.next().expect(usage).parse()?;
    let path = args.next().unwrap_or_else(|| "seer.db".into());

    let db = Db::open(&path)?;
    let tip = seer_sync::sync(
        &key,
        Network::MainNetwork,
        BlockHeight::from_u32(birthday),
        &db,
    )
    .await?;
    match tip {
        Some(at) => println!("synced to height {}", u32::from(at.height)),
        None => println!("birthday is beyond the chain tip; nothing to scan"),
    }

    let balance = db.balance()?;
    println!(
        "balance: {} zat (orchard {}, sapling {}, transparent {})",
        u64::from(balance.total()),
        u64::from(balance.orchard),
        u64::from(balance.sapling),
        u64::from(balance.transparent),
    );

    for tx in db.transactions()? {
        println!(
            "{:>8}  {:?}  +{} -{} zat  {}",
            tx.height.map_or("mempool".into(), |h| h.to_string()),
            tx.kind,
            u64::from(tx.received),
            u64::from(tx.spent),
            tx.recipients.as_deref().unwrap_or(""),
        );
    }
    Ok(())
}
