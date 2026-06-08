//! Same `scan()` path as `live_sync_db`, but with a UIVK instead of a UFVK.
//!
//! A UIVK carries only incoming viewing keys — no nullifier-deriving material —
//! so the sync sees notes paid *to* you but cannot detect when they are spent or
//! recover outputs you sent. The balance is therefore gross (incoming-only).

use seer_sync::db::Db;
use seer_sync::{Network, ViewKey};

const UIVK: &str = "uivk1ly7aruhw0um4pa24t8p65hm54xky7n682xrr6qnwxgeulp0m4054sda8dgczgkdvn4jct6al78xqa2w9z48au0zvmd05xnu9y9wrtx7xl95at3j8667xqykknudxczdm3032c8r2hghmgnq8vgg2rzy0hpp9eqs3y5k437frhje34tu4edqznafh4eswnry7m2dawtfw7kqcupj69z7xg2t3wz47wxhwlwthm3x43my6un4u04g";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Db::open_in_memory()?;
    let key = ViewKey::decode(&Network::MainNetwork, UIVK)?;

    seer_sync::scan(&key, &Network::MainNetwork, BIRTHDAY, &db).await?;
    println!("synced to height {}", db.get_sync_state()?.height);

    let balance = db.balance()?;
    println!("incoming balance: {} zat", balance.total().into_u64());
    println!("(UIVK can't derive nullifiers — spends and sent outputs are invisible)");
    Ok(())
}
