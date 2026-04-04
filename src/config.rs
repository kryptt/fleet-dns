use std::time::Duration;

use crate::error::Error;
use crate::state::parse_duration;

/// Application configuration, loaded from environment variables.
///
/// Secrets support a `_FILE` suffix convention: if `OPNSENSE_API_KEY_FILE` is
/// set, the file's contents are read and trimmed. Direct env vars are used as
/// a fallback.
#[derive(Debug)]
pub struct Config {
    pub cloudflare_api_token: String,
    pub cloudflare_zone_id: String,
    pub opnsense_url: String,
    pub opnsense_api_key: String,
    pub opnsense_api_secret: String,
    pub default_reconcile_interval: Duration,
    pub default_dns_ttl: Duration,
    pub wan_interface: String,
    pub dry_run: bool,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `CLOUDFLARE_API_TOKEN`
    /// - `CLOUDFLARE_ZONE_ID`
    /// - `OPNSENSE_URL`
    /// - `OPNSENSE_API_KEY` or `OPNSENSE_API_KEY_FILE`
    /// - `OPNSENSE_API_SECRET` or `OPNSENSE_API_SECRET_FILE`
    ///
    /// Optional (with defaults):
    /// - `DEFAULT_RECONCILE_INTERVAL` (default `"5m"`)
    /// - `DEFAULT_DNS_TTL` (default `"300s"`)
    /// - `WAN_INTERFACE` (default `"wan"`)
    /// - `DRY_RUN` (default `"false"`)
    pub fn from_env() -> Result<Self, Error> {
        let cloudflare_api_token = require_env("CLOUDFLARE_API_TOKEN")?;
        let cloudflare_zone_id = require_env("CLOUDFLARE_ZONE_ID")?;
        let opnsense_url = require_env("OPNSENSE_URL")?;
        let opnsense_api_key = read_secret("OPNSENSE_API_KEY")?;
        let opnsense_api_secret = read_secret("OPNSENSE_API_SECRET")?;

        let default_reconcile_interval = optional_duration(
            "DEFAULT_RECONCILE_INTERVAL",
            Duration::from_secs(300),
        )?;

        let default_dns_ttl = optional_duration(
            "DEFAULT_DNS_TTL",
            Duration::from_secs(300),
        )?;

        let wan_interface = std::env::var("WAN_INTERFACE")
            .unwrap_or_else(|_| "wan".to_owned());

        let dry_run = std::env::var("DRY_RUN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Ok(Self {
            cloudflare_api_token,
            cloudflare_zone_id,
            opnsense_url,
            opnsense_api_key,
            opnsense_api_secret,
            default_reconcile_interval,
            default_dns_ttl,
            wan_interface,
            dry_run,
        })
    }
}

/// Read a required env var, returning a config error if absent.
fn require_env(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| {
        Error::Config(format!("required environment variable {name} is not set"))
    })
}

/// Read a secret value, trying `{name}_FILE` first (reading and trimming the
/// file contents), then falling back to the direct `{name}` env var.
fn read_secret(name: &str) -> Result<String, Error> {
    let file_var = format!("{name}_FILE");

    if let Ok(path) = std::env::var(&file_var) {
        let contents = std::fs::read_to_string(&path).map_err(|e| {
            Error::Config(format!("failed to read {file_var} ({path}): {e}"))
        })?;
        let trimmed = contents.trim().to_owned();
        if trimmed.is_empty() {
            return Err(Error::Config(format!(
                "{file_var} ({path}) is empty after trimming"
            )));
        }
        return Ok(trimmed);
    }

    require_env(name)
}

/// Read an optional duration env var, falling back to a default.
fn optional_duration(name: &str, default: Duration) -> Result<Duration, Error> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(val) => parse_duration(&val).ok_or_else(|| {
            Error::Config(format!(
                "invalid duration for {name}: {val:?}"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: set env vars, run a closure, then remove them.
    ///
    /// # Safety
    /// Tests using this helper must run with `--test-threads=1` or otherwise
    /// ensure no concurrent access to the process environment.
    fn with_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        for (k, v) in vars {
            // SAFETY: test-only; we serialise env-mutating tests.
            unsafe { std::env::set_var(k, v) };
        }
        f();
        for (k, _) in vars {
            // SAFETY: test-only; we serialise env-mutating tests.
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn from_env_with_all_required_vars() {
        with_env(
            &[
                ("CLOUDFLARE_API_TOKEN", "cf-token"),
                ("CLOUDFLARE_ZONE_ID", "zone-123"),
                ("OPNSENSE_URL", "https://opnsense.local"),
                ("OPNSENSE_API_KEY", "key"),
                ("OPNSENSE_API_SECRET", "secret"),
            ],
            || {
                let config = Config::from_env().expect("should succeed");
                assert_eq!(config.cloudflare_api_token, "cf-token");
                assert_eq!(config.cloudflare_zone_id, "zone-123");
                assert_eq!(config.opnsense_url, "https://opnsense.local");
                assert_eq!(config.opnsense_api_key, "key");
                assert_eq!(config.opnsense_api_secret, "secret");
                assert_eq!(config.default_reconcile_interval, Duration::from_secs(300));
                assert_eq!(config.default_dns_ttl, Duration::from_secs(300));
                assert_eq!(config.wan_interface, "wan");
                assert!(!config.dry_run);
            },
        );
    }

    #[test]
    fn from_env_reads_file_secrets() {
        let dir = std::env::temp_dir().join("fleet-dns-test-secrets");
        let _ = std::fs::create_dir_all(&dir);

        let key_path = dir.join("api_key");
        let secret_path = dir.join("api_secret");
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(b"  file-key\n")
            .unwrap();
        std::fs::File::create(&secret_path)
            .unwrap()
            .write_all(b"file-secret  \n")
            .unwrap();

        with_env(
            &[
                ("CLOUDFLARE_API_TOKEN", "cf-token"),
                ("CLOUDFLARE_ZONE_ID", "zone-123"),
                ("OPNSENSE_URL", "https://opnsense.local"),
                ("OPNSENSE_API_KEY_FILE", key_path.to_str().unwrap()),
                ("OPNSENSE_API_SECRET_FILE", secret_path.to_str().unwrap()),
            ],
            || {
                let config = Config::from_env().expect("should succeed");
                assert_eq!(config.opnsense_api_key, "file-key");
                assert_eq!(config.opnsense_api_secret, "file-secret");
            },
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_missing_required_var_fails() {
        // Ensure the required vars are absent.
        // SAFETY: test-only; serialised via --test-threads=1.
        unsafe {
            std::env::remove_var("CLOUDFLARE_API_TOKEN");
            std::env::remove_var("CLOUDFLARE_ZONE_ID");
            std::env::remove_var("OPNSENSE_URL");
            std::env::remove_var("OPNSENSE_API_KEY");
            std::env::remove_var("OPNSENSE_API_KEY_FILE");
            std::env::remove_var("OPNSENSE_API_SECRET");
            std::env::remove_var("OPNSENSE_API_SECRET_FILE");
        }

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("CLOUDFLARE_API_TOKEN"));
    }

    #[test]
    fn optional_duration_parsing() {
        let default = Duration::from_secs(60);

        // Not set -> default.
        // SAFETY: test-only; serialised via --test-threads=1.
        unsafe { std::env::remove_var("TEST_DUR") };
        assert_eq!(optional_duration("TEST_DUR", default).unwrap(), default);

        // Valid value.
        unsafe { std::env::set_var("TEST_DUR", "10m") };
        assert_eq!(
            optional_duration("TEST_DUR", default).unwrap(),
            Duration::from_secs(600)
        );
        unsafe { std::env::remove_var("TEST_DUR") };

        // Invalid value -> error.
        unsafe { std::env::set_var("TEST_DUR", "bogus") };
        assert!(optional_duration("TEST_DUR", default).is_err());
        unsafe { std::env::remove_var("TEST_DUR") };
    }

    #[test]
    fn dry_run_parsing() {
        with_env(
            &[
                ("CLOUDFLARE_API_TOKEN", "t"),
                ("CLOUDFLARE_ZONE_ID", "z"),
                ("OPNSENSE_URL", "u"),
                ("OPNSENSE_API_KEY", "k"),
                ("OPNSENSE_API_SECRET", "s"),
                ("DRY_RUN", "true"),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.dry_run);
            },
        );

        with_env(
            &[
                ("CLOUDFLARE_API_TOKEN", "t"),
                ("CLOUDFLARE_ZONE_ID", "z"),
                ("OPNSENSE_URL", "u"),
                ("OPNSENSE_API_KEY", "k"),
                ("OPNSENSE_API_SECRET", "s"),
                ("DRY_RUN", "1"),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.dry_run);
            },
        );
    }
}
