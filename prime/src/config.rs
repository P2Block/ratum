#[derive(Debug, Default, PartialEq, serde::Deserialize, clap::Parser)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[command(
    name = "ratum-prime",
    version = ratum::VERSION,
    about = "DATUM Prime: the pool server of the DATUM protocol",
    allow_negative_numbers = true,
    args_override_self = true
)]
pub struct Config {
    #[arg(long)]
    pub listen: Option<String>,
    #[arg(long)]
    pub stats_listen: Option<String>,
    #[arg(long)]
    pub advertise_address: Option<String>,
    #[arg(long)]
    pub public_gateway: Option<String>,
    #[arg(long)]
    pub data_dir: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub config: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub motd: Option<String>,
    #[arg(long)]
    pub allow_agent: Option<String>,
    #[arg(long)]
    pub require_split: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub require_v3: Option<bool>,
    #[arg(long)]
    pub abw_reveal_after: Option<u64>,
    #[arg(long)]
    pub min_diff: Option<u64>,
    #[arg(long)]
    pub max_connections: Option<usize>,
    #[arg(long)]
    pub payout_address: Option<String>,
    #[arg(long)]
    pub payout_script: Option<String>,
    #[arg(long)]
    pub coinbase_tag: Option<String>,
    #[arg(long)]
    pub prime_id: Option<u32>,
    #[arg(long)]
    pub ledger: Option<String>,
    #[arg(long)]
    pub ledger_keep: Option<usize>,
    #[arg(long)]
    pub window: Option<f64>,
    #[arg(long)]
    pub window_floor: Option<u128>,
    #[arg(long)]
    pub min_payout: Option<u64>,
    #[arg(long)]
    pub fee_bps: Option<u16>,
    #[arg(long)]
    pub rpc: Option<String>,
    #[arg(long)]
    pub rpc_user: Option<String>,
    #[arg(long)]
    pub rpc_pass: Option<String>,
    #[arg(long)]
    pub rpc_cookie: Option<String>,
    #[arg(long)]
    pub poll: Option<f64>,
    #[arg(long)]
    #[serde(skip)]
    pub dump_ledger: bool,
    #[arg(long)]
    #[serde(skip)]
    pub settle_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub void_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub record_owed: Option<String>,
    #[arg(long, value_name = "IDENTITY=SATS")]
    #[serde(skip)]
    pub owed: Vec<String>,
}

impl Config {
    pub fn holds_a_secret(&self) -> bool {
        self.rpc_pass.is_some()
    }
}

pub fn parse_toml(text: &str) -> Result<Config, toml::de::Error> {
    toml::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_into_their_typed_fields() {
        let c = parse_toml("rpc-user = \"ratum\"\nmin-diff = 16384\nwindow = 8.5\n").unwrap();
        assert_eq!(c.min_diff, Some(16384));
        assert_eq!(c.window, Some(8.5));
        assert_eq!(c.rpc_user, Some("ratum".to_string()));
        assert_eq!(c.listen, None, "a setting not written stays unset");
    }

    #[test]
    fn nothing_written_is_nothing_set() {
        assert_eq!(parse_toml("").unwrap(), Config::default());
        assert_eq!(parse_toml("# only a comment\n").unwrap(), Config::default());
    }

    #[test]
    fn a_setting_may_be_annotated() {
        let c = parse_toml(
            "# the smallest share difficulty credited\nmin-diff = 16384  # a power of two\n",
        )
        .unwrap();
        assert_eq!(c.min_diff, Some(16384));
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_where_it_is() {
        let e = parse_toml("motd = \"fine\"\nmin-diff = \"soon\"\n").unwrap_err().to_string();
        assert!(e.contains("min-diff"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn a_name_the_pool_does_not_have_is_refused() {
        let e = parse_toml("min-dif = 1\n").unwrap_err().to_string();
        assert!(e.contains("min-dif"), "{e}");
        assert!(e.contains("min-diff"), "the ones it does have are named: {e}");
    }

    #[test]
    fn a_configuration_file_cannot_name_another_one() {
        let e = parse_toml("config = \"/etc/other.toml\"\n").unwrap_err().to_string();
        assert!(e.contains("config"), "{e}");
    }

    #[test]
    fn a_configuration_file_cannot_hold_a_ledger_command() {
        for text in [
            "dump-ledger = true\n",
            "settle-block = \"list\"\n",
            "void-block = \"00\"\n",
            "record-owed = \"00\"\n",
            "owed = [\"alice=1\"]\n",
        ] {
            let e = parse_toml(text).expect_err("a command is not a setting").to_string();
            assert!(e.contains("unknown field"), "{text:?}: {e}");
        }
    }

    #[test]
    fn text_that_is_not_settings_is_an_error() {
        for text in ["oops\n", "min-diff = \n", "[section]\nmin-diff = 1\n"] {
            let e = parse_toml(text).expect_err("not settings").to_string();
            assert!(!e.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn only_a_password_makes_the_files_permissions_matter() {
        assert!(!parse_toml("rpc-user = \"ratum\"\n").unwrap().holds_a_secret());
        assert!(parse_toml("rpc-pass = \"hunter2\"\n").unwrap().holds_a_secret());
    }

    #[test]
    fn the_command_line_and_the_file_share_one_field_list() {
        use clap::Parser as _;
        let c = Config::parse_from(["ratum-prime", "--min-diff", "16384", "--dump-ledger"]);
        assert_eq!(c.min_diff, Some(16384));
        assert!(c.dump_ledger);
        assert_eq!(
            parse_toml("min-diff = 16384\n").unwrap(),
            Config { dump_ledger: false, ..c },
            "the same setting reads the same from either source"
        );
    }
}
