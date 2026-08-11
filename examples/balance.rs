//! Print the balance from an existing seer.db.
//!
//!     cargo run --release --example balance -- [DB_PATH]

use seer_sync::db::Db;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "seer.db".into());
    let db = Db::open(&path)?;

    let sync_height: u32 = db
        .conn()
        .query_row("SELECT sync_height FROM account WHERE id = 1", [], |r| r.get(0))?;

    let balance = db.balance()?;

    println!("synced to height {sync_height}");
    println!("balance: {balance} zat ({:.8} ZEC)", balance as f64 / 1e8);
    Ok(())
}