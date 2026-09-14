use crate::bounded::BoundedMap;
use log::warn;
use ratum::bitcoin::script::output_script_size_is_valid;
use ratum::{lock, rpc};
use std::sync::Mutex;

pub struct AddressResolver {
    scripts: Mutex<BoundedMap<String, Result<Vec<u8>, Unpayable>>>,
}

const MAX_CACHED_ADDRESSES: usize = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unpayable {
    NotAnAddress,
    NoScript,
    ScriptTooLong(usize),
}

impl std::fmt::Display for Unpayable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnAddress => write!(f, "not a valid address"),
            Self::NoScript => write!(f, "an address the node returns no script for"),
            Self::ScriptTooLong(n) => {
                write!(f, "over the coinbase output limit ({n} bytes)")
            }
        }
    }
}

pub enum Payability {
    Script(Vec<u8>),
    Unpayable(Unpayable),
    Unknown(rpc::Error),
}

impl AddressResolver {
    pub fn new() -> Self {
        Self { scripts: Mutex::new(BoundedMap::new(MAX_CACHED_ADDRESSES)) }
    }

    pub fn remember(&self, address: &str, script: Result<Vec<u8>, Unpayable>) {
        lock(&self.scripts).insert(address.to_string(), script);
    }

    pub fn cached(&self, address: &str) -> Option<Result<Vec<u8>, Unpayable>> {
        lock(&self.scripts).get(address).cloned()
    }

    pub fn payability(&self, node: &rpc::Client, address: &str) -> Payability {
        if let Some(known) = self.cached(address) {
            return known.into();
        }
        let resolved = match resolve_address(node, address) {
            Payability::Script(script) => Ok(script),
            Payability::Unpayable(why) => Err(why),
            Payability::Unknown(e) => {
                warn!("could not resolve payout address {address:?}: {e}");
                return Payability::Unknown(e);
            }
        };
        if let Err(why) = &resolved {
            warn!("payout address {address:?} cannot be paid: {why}");
        }
        self.remember(address, resolved.clone());
        resolved.into()
    }
}

impl From<Result<Vec<u8>, Unpayable>> for Payability {
    fn from(r: Result<Vec<u8>, Unpayable>) -> Self {
        match r {
            Ok(script) => Self::Script(script),
            Err(why) => Self::Unpayable(why),
        }
    }
}

pub fn payable_script(script: Vec<u8>) -> Result<Vec<u8>, Unpayable> {
    if output_script_size_is_valid(&script) {
        Ok(script)
    } else {
        Err(Unpayable::ScriptTooLong(script.len()))
    }
}

pub fn resolve_address(node: &rpc::Client, address: &str) -> Payability {
    let v = match node.call("validateaddress", serde_json::json!([address])) {
        Ok(v) => v,
        Err(e) => return Payability::Unknown(e),
    };
    if v["isvalid"] != serde_json::Value::Bool(true) {
        return Payability::Unpayable(Unpayable::NotAnAddress);
    }
    match v["scriptPubKey"].as_str().and_then(|h| hex::decode(h).ok()) {
        Some(script) => payable_script(script).into(),
        None => Payability::Unpayable(Unpayable::NoScript),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::server_with;
    use ratum::fixtures::p2wpkh;

    #[test]
    fn a_cached_answer_is_returned_without_asking_the_node() {
        let server = server_with(&[], &[("alice", Ok(p2wpkh(0xa1)))], 0);
        assert!(matches!(
            server.resolver.payability(&server.node, "alice"),
            Payability::Script(s) if s == p2wpkh(0xa1)
        ));
        assert!(matches!(
            server.resolver.payability(&server.node, "unseen"),
            Payability::Unknown(_)
        ));
        assert!(server.resolver.cached("unseen").is_none());
    }

    #[test]
    fn a_payable_script_fits_a_coinbase_output() {
        assert_eq!(payable_script(p2wpkh(0xa1)), Ok(p2wpkh(0xa1)));
        assert_eq!(payable_script(vec![0x00; 42]), Err(Unpayable::ScriptTooLong(42)));
        assert!(payable_script(vec![ratum::bitcoin::script::opcode::OP_RETURN; 83]).is_ok());
        assert_eq!(
            payable_script(vec![ratum::bitcoin::script::opcode::OP_RETURN; 84]),
            Err(Unpayable::ScriptTooLong(84))
        );
    }
}
