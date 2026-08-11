//! Sync a view key and print the balance.
//!
//!     cargo run --release --example sync -- <VIEW_KEY> <BIRTHDAY> [DB_PATH]

use seer_sync::{run, BlockHeight, Db, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: sync <view-key> <birthday-height> [db-path]";
    let view_key = args.next().expect(usage);
    let birthday: u32 = args.next().expect(usage).parse()?;
    let path = args.next().unwrap_or_else(|| "seer.db".into());

    let db = Db::open(&path)?;
    db.init_account(BlockHeight::from_u32(birthday))?;

    run(&view_key, Network::MainNetwork, &db).await?;

    Ok(())
}