use anyhow::Result;
use seer_sync::db::Db;
use seer_sync::Network;

const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let db = Db::open("wallet.db")?;

    seer_sync::scan(UIVK, &Network::MainNetwork, BIRTHDAY, &db, |_| {}).await?;

    let bal = db.balance()?;
    println!(
        "orchard {} zat  sapling {} zat  total {} zat",
        bal.orchard.into_u64(),
        bal.sapling.into_u64(),
        bal.total().into_u64()
    );
    println!("{} memo(s)", db.memos()?.len());

    Ok(())
}
