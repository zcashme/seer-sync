use std::collections::HashMap;

use crate::sync::chain::{self, ChainError, LwdClient, TransparentUtxo};
use crate::{Network, ViewKey};

pub const GAP_LIMIT: u32 = 20;

/// Fetch the current unspent transparent outputs for `key`'s transparent
/// component (empty when it has none). Compact blocks carry no transparent
/// data, so this is a snapshot of the server's address index, not part of the
/// block scan: addresses are derived per scope BIP-44 style, widening the
/// window until [`GAP_LIMIT`] trailing indices are unused.
pub async fn utxos(
    client: &mut LwdClient,
    key: &ViewKey,
    network: &Network,
    start_height: u32,
) -> Result<Vec<TransparentUtxo>, ChainError> {
    let Some(t) = key.transparent.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for internal in [false, true] {
        let mut upto = GAP_LIMIT;
        loop {
            let addrs = t.scoped_addresses(network, internal, upto);
            if addrs.is_empty() {
                break;
            }
            let fetched = chain::fetch_address_utxos(
                client,
                addrs.iter().map(|(a, _)| a.clone()).collect(),
                start_height,
            )
            .await?;
            let index_of: HashMap<&str, u32> =
                addrs.iter().map(|(a, i)| (a.as_str(), *i)).collect();
            let max_hit = fetched
                .iter()
                .filter_map(|u| index_of.get(u.address.as_str()).copied())
                .max();
            let need = max_hit.map_or(0, |m| m + 1 + GAP_LIMIT);
            if need > upto {
                upto = need;
                continue;
            }
            out.extend(fetched);
            break;
        }
    }
    Ok(out)
}
