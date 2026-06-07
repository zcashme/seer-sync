//! Incoming-only sync from a UIVK, persisted to SQLite.
//!
//! A Unified *Incoming* Viewing Key carries no nullifier-deriving or outgoing
//! material, so the same `scan()` call runs in a strictly reduced mode:
//!
//!   * it sees notes paid to you, but cannot derive their nullifiers, so spends
//!     are invisible and `balance()` is gross (it never drops);
//!   * it cannot recover outputs you sent, so `recipient_address` is always NULL.
//!
//! This is a cryptographic limit of the key, not a missing feature. Sync a UFVK
//! (see live_sync_db) for spend detection and recovered recipients.

use anyhow::Result;
use seer_sync::db::Db;
use seer_sync::Network;

const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let db = Db::open("wallet.db")?;

    let height = seer_sync::scan(UIVK, &Network::MainNetwork, BIRTHDAY, &db, |_| {}).await?;

    let bal = db.balance()?;
    println!("synced to {height} (incoming-only)");
    println!(
        "orchard {} zat  sapling {} zat  total {} zat (gross — spends not detectable from a UIVK)",
        bal.orchard.into_u64(),
        bal.sapling.into_u64(),
        bal.total().into_u64()
    );
    println!("{} memo(s)", db.memos()?.len());

    Ok(())
}
