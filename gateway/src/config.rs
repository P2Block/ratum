use crate::username::{ModifierRange, UsernameModifier};
use serde::Deserialize;

const EXTRA_JOBS_PER_TIP: u64 = 2;

const MAX_THREADS: usize = 64;
const MAX_CLIENTS_PER_THREAD: usize = 4096;
pub const WORK_UPDATE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 5..=120;
const MIN_VARDIFF_TARGET_SHARES_MIN: u64 = 1;
const MIN_VARDIFF_QUICKDIFF_COUNT: u64 = 4;
const MIN_VARDIFF_QUICKDIFF_DELTA: u64 = 3;
const SHARE_STALE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 60..=150;
pub const DEFAULT_MAX_NETWORK_SHARE_BPS: u32 = 1000;
pub const GLOBAL_TIMEOUT_MARGIN_SECS: u64 = 5;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BitcoindConfig {
    pub rpccookiefile: String,
    pub rpcuser: String,
    pub rpcpassword: String,
    pub rpcurl: String,
    pub work_update_seconds: u64,
    pub notify_fallback: bool,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            rpccookiefile: String::new(),
            rpcuser: String::new(),
            rpcpassword: String::new(),
            rpcurl: String::new(),
            work_update_seconds: 40,
            notify_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StratumConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_clients_per_thread: usize,
    pub max_threads: usize,
    pub max_clients: usize,
    pub max_network_share_bps: u32,
    pub trust_proxy: i64,
    pub vardiff_min: u64,
    pub vardiff_target_shares_min: u64,
    pub vardiff_quickdiff_count: u64,
    pub vardiff_quickdiff_delta: u64,
    pub share_stale_seconds: u64,
    pub fingerprint_miners: bool,
    pub idle_timeout_no_subscribe: u64,
    pub idle_timeout_no_shares: u64,
    pub idle_timeout_max_last_work: u64,
    pub require_address_username: bool,
    #[serde(deserialize_with = "deserialize_modifiers")]
    pub username_modifiers: Vec<UsernameModifier>,
}

struct OrderedPairs<V>(Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrderedPairs<V> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{MapAccess, Visitor};
        use std::marker::PhantomData;

        struct Pairs<V>(PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for Pairs<V> {
            type Value = OrderedPairs<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(pair) = m.next_entry::<String, V>()? {
                    v.push(pair);
                }
                Ok(OrderedPairs(v))
            }
        }
        d.deserialize_map(Pairs(PhantomData))
    }
}

fn deserialize_modifiers<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<UsernameModifier>, D::Error> {
    let mods = OrderedPairs::<OrderedPairs<f64>>::deserialize(d)?;
    Ok(mods
        .0
        .into_iter()
        .map(|(name, ranges)| UsernameModifier {
            name,
            ranges: ranges
                .0
                .into_iter()
                .map(|(address, proportion)| ModifierRange { address, proportion })
                .collect(),
        })
        .collect())
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            listen_port: 23334,
            max_clients_per_thread: 128,
            max_threads: 8,
            max_clients: 1024,
            max_network_share_bps: DEFAULT_MAX_NETWORK_SHARE_BPS,
            trust_proxy: -1,
            vardiff_min: 16384,
            vardiff_target_shares_min: 8,
            vardiff_quickdiff_count: 8,
            vardiff_quickdiff_delta: 8,
            share_stale_seconds: 120,
            fingerprint_miners: true,
            idle_timeout_no_subscribe: 15,
            idle_timeout_no_shares: 7200,
            idle_timeout_max_last_work: 0,
            require_address_username: false,
            username_modifiers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MiningConfig {
    pub pool_address: String,
    pub coinbase_tag_primary: String,
    pub coinbase_tag_secondary: String,
    pub coinbase_unique_id: u32,
    pub save_submitblocks_dir: String,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            pool_address: String::new(),
            coinbase_tag_primary: String::new(),
            coinbase_tag_secondary: String::new(),
            coinbase_unique_id: 4242,
            save_submitblocks_dir: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub admin_password: String,
    pub allow_insecure_auth: bool,
    pub listen_addr: String,
    pub listen_port: u16,
    pub miner_listen_addr: String,
    pub miner_listen_port: u16,
    pub modify_conf: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            admin_password: String::new(),
            allow_insecure_auth: false,
            listen_addr: String::new(),
            listen_port: 0,
            miner_listen_addr: String::new(),
            miner_listen_port: 8000,
            modify_conf: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraBlockSubmissionsConfig {
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggerConfig {
    pub log_to_console: bool,
    pub log_to_stderr: bool,
    pub log_to_file: bool,
    pub log_file: String,
    pub log_rotate_daily: Option<bool>,
    pub log_calling_function: bool,
    pub log_level_console: u8,
    pub log_level_file: u8,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            log_to_console: true,
            log_to_stderr: false,
            log_to_file: false,
            log_file: String::new(),
            log_rotate_daily: None,
            log_calling_function: true,
            log_level_console: 2,
            log_level_file: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DatumConfig {
    pub pool_host: String,
    pub pool_port: u16,
    pub pool_url: String,
    pub pool_pubkey: String,
    pub pool_pass_workers: bool,
    pub protocol_job_slots: usize,
    pub pool_pass_full_users: bool,
    pub always_pay_self: Option<bool>,
    pub pooled_mining_only: bool,
    pub protocol_global_timeout: u64,
    pub protocol_v3: bool,
}

impl Default for DatumConfig {
    fn default() -> Self {
        Self {
            pool_host: "datum-beta1.mine.ocean.xyz".into(),
            pool_port: 28915,
            pool_url: String::new(),
            pool_pubkey: "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003".into(),
            pool_pass_workers: true,
            protocol_job_slots: 256,
            pool_pass_full_users: true,
            always_pay_self: None,
            pooled_mining_only: true,
            protocol_global_timeout: 60,
            protocol_v3: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bitcoind: BitcoindConfig,
    pub stratum: StratumConfig,
    pub mining: MiningConfig,
    pub api: ApiConfig,
    pub extra_block_submissions: ExtraBlockSubmissionsConfig,
    pub logger: LoggerConfig,
    pub datum: DatumConfig,
    #[serde(skip)]
    pub startup_notes: Vec<StartupNote>,
    #[serde(skip)]
    pub pool_output_script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupNote {
    pub level: log::Level,
    pub message: String,
}

pub const MAX_CONFIGURED_TAG_LEN: usize = 60;
pub const MAX_CONFIGURED_TAGS_TOTAL_LEN: usize = 88;

fn at_least(name: &str, value: u64, min: u64) -> Result<(), String> {
    if value < min { Err(format!("{name} must be at least {min}")) } else { Ok(()) }
}

fn at_most(name: &str, value: u64, max: u64) -> Result<(), String> {
    if value > max { Err(format!("{name} must be at most {max}")) } else { Ok(()) }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut c: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&mut self) -> Result<(), String> {
        self.validate_bitcoind()?;
        self.validate_stratum()?;
        self.validate_mining()?;
        self.validate_api();
        self.validate_logger();
        self.validate_datum()?;
        self.validate_username_modifiers()
    }

    fn note_warning(&mut self, message: impl Into<String>) {
        self.startup_notes.push(StartupNote { level: log::Level::Warn, message: message.into() });
    }

    fn validate_bitcoind(&mut self) -> Result<(), String> {
        if self.bitcoind.rpcurl.is_empty() {
            return Err("Required configuration option (bitcoind.rpcurl) not found".into());
        }
        if !self.bitcoind.rpcuser.is_empty() {
            if self.bitcoind.rpcpassword.is_empty() {
                return Err("bitcoind.rpcpassword is required with bitcoind.rpcuser".into());
            }
        } else if self.bitcoind.rpccookiefile.is_empty() {
            return Err("Either bitcoind.rpcuser (and bitcoind.rpcpassword) or bitcoind.rpccookiefile is required.".into());
        }
        self.bitcoind.work_update_seconds = self
            .bitcoind
            .work_update_seconds
            .clamp(*WORK_UPDATE_SECONDS_RANGE.start(), *WORK_UPDATE_SECONDS_RANGE.end());
        Ok(())
    }

    fn validate_stratum(&mut self) -> Result<(), String> {
        let s = &self.stratum;
        at_most("stratum.max_threads", s.max_threads as u64, MAX_THREADS as u64)?;
        at_most(
            "stratum.max_clients_per_thread",
            s.max_clients_per_thread as u64,
            MAX_CLIENTS_PER_THREAD as u64,
        )?;
        if s.max_clients > s.max_clients_per_thread * s.max_threads {
            return Err("stratum.max_clients exceeds max_clients_per_thread * max_threads".into());
        }
        at_least("stratum.vardiff_min", s.vardiff_min, 1)?;
        at_least(
            "stratum.vardiff_target_shares_min",
            s.vardiff_target_shares_min,
            MIN_VARDIFF_TARGET_SHARES_MIN,
        )?;
        at_least(
            "stratum.vardiff_quickdiff_count",
            s.vardiff_quickdiff_count,
            MIN_VARDIFF_QUICKDIFF_COUNT,
        )?;
        at_least(
            "stratum.vardiff_quickdiff_delta",
            s.vardiff_quickdiff_delta,
            MIN_VARDIFF_QUICKDIFF_DELTA,
        )?;
        if !SHARE_STALE_SECONDS_RANGE.contains(&s.share_stale_seconds) {
            return Err(format!(
                "stratum.share_stale_seconds must be {}..{}",
                SHARE_STALE_SECONDS_RANGE.start(),
                SHARE_STALE_SECONDS_RANGE.end()
            ));
        }
        if !s.vardiff_min.is_power_of_two() {
            let rounded = ratum::target::pow2_floor(s.vardiff_min);
            let was = s.vardiff_min;
            self.stratum.vardiff_min = rounded;
            self.note_warning(format!(
                "stratum.vardiff_min {was} is not a power of two; using {rounded}"
            ));
        }
        let max_network_share_bps = self.stratum.max_network_share_bps;
        if u64::from(max_network_share_bps) > ratum::BASIS_POINTS_PER_UNIT {
            return Err(format!(
                "stratum.max_network_share_bps must be 0..{}",
                ratum::BASIS_POINTS_PER_UNIT
            ));
        }
        if max_network_share_bps == 0 {
            self.note_warning(
                "stratum.max_network_share_bps is 0: new stratum connections are accepted whatever share of the network hashrate this gateway holds",
            );
        }
        if self.stratum.trust_proxy != -1 {
            self.note_warning("stratum.trust_proxy is set but the PROXY protocol is not supported; a connection that sends a PROXY line is closed");
        }
        Ok(())
    }

    fn validate_mining(&mut self) -> Result<(), String> {
        let m = &self.mining;
        if m.pool_address.is_empty() {
            return Err("Required configuration option (mining.pool_address) not found".into());
        }
        let tags = m.coinbase_tag_primary.len() + m.coinbase_tag_secondary.len();
        if tags > MAX_CONFIGURED_TAGS_TOTAL_LEN
            || m.coinbase_tag_primary.len() > MAX_CONFIGURED_TAG_LEN
            || m.coinbase_tag_secondary.len() > MAX_CONFIGURED_TAG_LEN
        {
            return Err(format!(
                "mining.coinbase_tag_primary and mining.coinbase_tag_secondary must be at most \
                 {MAX_CONFIGURED_TAG_LEN} bytes each and {MAX_CONFIGURED_TAGS_TOTAL_LEN} bytes together"
            ));
        }
        self.pool_output_script = crate::address::to_output_script(&m.pool_address)
            .ok_or("mining.pool_address is not an address a coinbase output can pay")?;
        Ok(())
    }

    fn validate_api(&mut self) {
        if self.api.allow_insecure_auth {
            self.note_warning(
                "api.allow_insecure_auth has no effect: the API uses HTTP Basic authentication",
            );
        }
        if self.api.modify_conf && self.api.admin_password.is_empty() {
            self.note_warning("api.modify_conf is set but api.admin_password is empty, so the settings page cannot save");
        }
    }

    fn validate_logger(&mut self) {
        if self.logger.log_rotate_daily.is_some() {
            self.note_warning("logger.log_rotate_daily has no effect: the file is held open, so rotate it with logrotate's copytruncate");
        }
    }

    fn validate_datum(&mut self) -> Result<(), String> {
        let d = &self.datum;
        if !(1..=ratum::datum::messages::share::MAX_JOBS).contains(&d.protocol_job_slots) {
            return Err(format!(
                "datum.protocol_job_slots must be 1..{}",
                ratum::datum::messages::share::MAX_JOBS
            ));
        }
        let min_slots = EXTRA_JOBS_PER_TIP
            + (self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds)
                .div_ceil(self.bitcoind.work_update_seconds);
        if (d.protocol_job_slots as u64) < min_slots {
            return Err(format!(
                "datum.protocol_job_slots must be at least {min_slots} for stratum.share_stale_seconds {} and bitcoind.work_update_seconds {}",
                self.stratum.share_stale_seconds, self.bitcoind.work_update_seconds
            ));
        }
        if d.protocol_global_timeout
            < self.bitcoind.work_update_seconds + GLOBAL_TIMEOUT_MARGIN_SECS
        {
            return Err(format!(
                "datum.protocol_global_timeout must be at least bitcoind.work_update_seconds + \
                 {GLOBAL_TIMEOUT_MARGIN_SECS}"
            ));
        }
        if d.pooled_mining_only && d.pool_host.is_empty() {
            return Err("datum.pooled_mining_only requires datum.pool_host".into());
        }
        if !d.pool_host.is_empty() {
            crate::datum::parse_pool_pubkey(&d.pool_pubkey)
                .map_err(|e| format!("datum.pool_pubkey: {e}"))?;
        }
        if self.stratum.require_address_username && !self.datum.pool_pass_full_users {
            self.note_warning("stratum.require_address_username is set but datum.pool_pass_full_users is not, so the pool never receives the address the username was checked for");
        }
        if self.datum.always_pay_self.is_some() {
            self.note_warning("datum.always_pay_self has no effect: the coinbase always pays the pool script the split leaves");
        }
        Ok(())
    }

    fn validate_username_modifiers(&mut self) -> Result<(), String> {
        let mut notes = Vec::new();
        for modifier in &self.stratum.username_modifiers {
            let modname = &modifier.name;
            let mut sum = 0f64;
            let mut covered = false;
            for range in &modifier.ranges {
                if range.proportion < 0.0 {
                    return Err(format!(
                        "stratum.username_modifiers.{modname}.{} is negative",
                        range.address
                    ));
                }
                sum += range.proportion;
                if (sum * crate::username::SELECTOR_SPACE).ceil() - 1.0
                    >= crate::username::SELECTOR_MAX as f64
                {
                    covered = true;
                    break;
                }
            }
            if !covered {
                notes.push(StartupNote {
                    level: log::Level::Error,
                    message: format!(
                        "Username modifier '{modname}' is configured to not distribute {}% of shares!",
                        100.0 * (1.0 - sum)
                    ),
                });
            }
        }
        self.startup_notes.extend(notes);
        Ok(())
    }

    pub fn stale_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds,
        )
    }

    pub fn share_queue_capacity(&self) -> usize {
        let s = &self.stratum;
        s.max_clients_per_thread
            * s.vardiff_target_shares_min as usize
            * (s.share_stale_seconds / ratum::SECS_PER_MINUTE) as usize
            * 16
    }

    pub fn seen_share_hashes_capacity(&self) -> usize {
        self.share_queue_capacity() * self.stratum.max_threads
    }

    pub fn max_network_share(&self) -> Option<f64> {
        match self.stratum.max_network_share_bps {
            0 => None,
            bps => Some(f64::from(bps) / ratum::BASIS_POINTS_PER_UNIT as f64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn minimal() -> String {
        r#"{
          "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:18443"},
          "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
          "datum": {"pool_host": "", "pooled_mining_only": false}
        }"#
        .to_string()
    }

    #[test]
    fn parses_the_minimal_file_with_defaults() {
        let c = Config::parse(&minimal()).unwrap();
        assert_eq!(c.stratum.listen_port, 23334);
        assert_eq!(c.stratum.vardiff_min, 16384);
        assert_eq!(c.api.miner_listen_port, 8000);
        assert_eq!(c.bitcoind.work_update_seconds, 40);
        assert!(!c.datum.pooled_mining_only);
    }

    #[test]
    fn the_network_share_limit_defaults_to_ten_percent_and_zero_disables_it() {
        let c = Config::parse(&minimal()).unwrap();
        assert_eq!(c.stratum.max_network_share_bps, DEFAULT_MAX_NETWORK_SHARE_BPS);
        assert_eq!(c.max_network_share(), Some(0.1));
        assert!(c.startup_notes.is_empty(), "{:?}", c.startup_notes);

        let with_bps = |bps: &str| {
            minimal().replace(
                "\"pool_address\":\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\"},",
                &format!(
                    "\"pool_address\":\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\"}},
                     \"stratum\": {{\"max_network_share_bps\": {bps}}},"
                ),
            )
        };
        let c = Config::parse(&with_bps("500")).unwrap();
        assert_eq!(c.max_network_share(), Some(0.05));

        let c = Config::parse(&with_bps("0")).unwrap();
        assert_eq!(c.max_network_share(), None, "0 refuses no connection");
        assert!(
            c.startup_notes.iter().any(|n| n.message.contains("max_network_share_bps is 0")),
            "a limit of 0 is reported at startup: {:?}",
            c.startup_notes
        );

        let e = Config::parse(&with_bps("10001")).unwrap_err();
        assert!(e.contains("stratum.max_network_share_bps must be 0..10000"), "{e}");
    }

    #[test]
    fn the_pool_url_is_empty_unless_set() {
        assert_eq!(Config::parse(&minimal()).unwrap().datum.pool_url, "");
        let text = minimal().replace(
            "\"pooled_mining_only\": false",
            "\"pooled_mining_only\": false, \"pool_url\": \"https://pool.example\"",
        );
        assert_eq!(Config::parse(&text).unwrap().datum.pool_url, "https://pool.example");
    }

    #[test]
    fn username_modifiers_are_checked() {
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"half\": {\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\": 0.5}}}, \"datum\":",
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.startup_notes.len(), 1);
        assert!(
            c.startup_notes[0].message.contains("not distribute 50% of shares"),
            "{}",
            c.startup_notes[0].message
        );
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"bad\": {\"\": -1}}}, \"datum\":",
        );
        assert!(Config::parse(&text).unwrap_err().contains("negative"));
    }

    #[test]
    fn username_modifier_ranges_keep_the_file_order() {
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"z\": {\"bcrt1qzed\": 0.9, \"bcrt1qamy\": 0.1}, \"a\": {\"\": 1}}}, \"datum\":",
        );
        let c = Config::parse(&text).unwrap();
        let names: Vec<&str> =
            c.stratum.username_modifiers.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["z", "a"]);
        let addrs: Vec<&str> =
            c.stratum.username_modifiers[0].ranges.iter().map(|r| r.address.as_str()).collect();
        assert_eq!(addrs, ["bcrt1qzed", "bcrt1qamy"]);
    }

    #[test]
    fn work_update_seconds_is_clamped() {
        let text = minimal().replace("\"rpcurl\"", "\"work_update_seconds\": 1, \"rpcurl\"");
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.bitcoind.work_update_seconds, 5);
    }
}
