use crate::config::Config;
use crate::datum::PoolConnectionState;
use crate::job::builder::JobBuilder;
use crate::job::{Job, JobKind};
use crate::stratum::Server;
use crate::template::waker::TemplateWaker;
use crate::template::{Template, TxnTotals};
use std::sync::Arc;

pub fn config() -> Config {
    Config::parse(
        r#"{
          "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:1"},
          "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
          "datum": {"pool_host": "", "pooled_mining_only": false, "protocol_job_slots": 6}
        }"#,
    )
    .unwrap()
}

pub fn hash(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}

pub fn template() -> Template {
    let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    wc.extend_from_slice(&[0u8; 32]);
    Template {
        height: 21,
        coinbase_value: 5_000_000_000,
        mintime: 1_700_000_000,
        curtime: 1_700_000_100,
        sizelimit: 4_000_000,
        weightlimit: 4_000_000,
        sigoplimit: 80_000,
        version: 0x2000_0000,
        nbits: 0x207f_ffff,
        prev_hash_hex: "00".repeat(32),
        prev_hash: [0u8; 32],
        witness_commitment: wc,
        blake2b_rule: true,
        reduced_data: false,
        txns: vec![],
        totals: TxnTotals::default(),
    }
}

pub fn job_with_id(stratum_job_id: &str) -> Job {
    let mut b = JobBuilder::new(Arc::new(config()));
    let mut job = b.build(Arc::new(template()), JobKind::Full, None, None, None).unwrap();
    job.stratum_job_id = stratum_job_id.to_string();
    job
}

pub fn test_server() -> Arc<Server> {
    test_server_with(|_| {})
}

pub fn test_server_with(edit: impl FnOnce(&mut Config)) -> Arc<Server> {
    let mut config = config();
    edit(&mut config);
    let config = Arc::new(config);
    let template_waker = Arc::new(TemplateWaker::default());
    let node = ratum::rpc::Client::new("http://127.0.0.1:1", "u", "p").unwrap();
    let shared = Arc::new(PoolConnectionState::new(
        config.datum.protocol_job_slots,
        64,
        Arc::clone(&template_waker),
        node.clone(),
    ));
    Server::new(config, shared, node, Arc::default(), template_waker)
}
