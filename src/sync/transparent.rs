use std::collections::HashMap;

use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_transparent::address::TransparentAddress;

use crate::sync::chain::{self, ChainError, LwdClient};
use crate::{Network, TxId, ViewKey};

pub const GAP_LIMIT: u32 = 20;

#[derive(Default)]
pub(crate) struct Discovery {
    /// Every derived address in use (plus the trailing gap), keyed for
    /// output matching during the scan.
    pub addresses: HashMap<TransparentAddress, String>,
    /// txid → mined height of every transaction touching those addresses.
    pub targets: HashMap<TxId, u32>,
}

/// Walk each scope's BIP-44 address chain, asking the server which
/// transactions touched each address in `[from, to]`, stopping after
/// [`GAP_LIMIT`] consecutive unused addresses. Empty when the key has no
/// transparent component.
///
/// Discovery is stateless (no address book is persisted), so callers must
/// pass the account's whole life as the window — an address whose only
/// activity is older than the window would read as unused and end the walk
/// before later addresses are reached.
pub(crate) async fn discover(
    client: &mut LwdClient,
    key: &ViewKey,
    network: &Network,
    from: u32,
    to: u32,
) -> Result<Discovery, ChainError> {
    let mut found = Discovery::default();
    let Some(t) = key.transparent.as_ref() else {
        return Ok(found);
    };
    for internal in [false, true] {
        let mut unused = 0u32;
        for index in 0u32.. {
            if unused >= GAP_LIMIT {
                break;
            }
            let Some(addr) = t.derive(internal, index) else { break };
            let encoded = addr.encode(network);
            let txs =
                chain::fetch_taddress_transactions(client, encoded.clone(), from, to).await?;
            if txs.is_empty() {
                unused += 1;
            } else {
                unused = 0;
                for raw in &txs {
                    let height = BlockHeight::from_u32(raw.height as u32);
                    let Ok(tx) = Transaction::read(
                        &raw.data[..],
                        BranchId::for_height(network, height),
                    ) else {
                        continue;
                    };
                    found.targets.insert(tx.txid(), raw.height as u32);
                }
            }
            found.addresses.insert(addr, encoded);
        }
    }
    Ok(found)
}
