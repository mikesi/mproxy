use crate::data_path;
use crate::ip_blacklist::IpBlacklist;
use serde::{Deserialize, Serialize};
use std::fs;
use std::env;
use std::sync::Mutex;
use tracing::warn;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostConfig {
    pub host_name: String,
    pub aliases: Option<Vec<String>>,
    pub upstream_address: String,
    #[serde(default, deserialize_with = "deserialize_optional_ip_blacklist")]
    pub blacklisted_ips: Option<IpBlacklist>,
}

fn deserialize_optional_ip_blacklist<'de, D>(deserializer: D) -> Result<Option<IpBlacklist>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(value) if value.trim().is_empty() => Ok(None),
        Some(value) => match IpBlacklist::from_string(value.as_str()) {
            Ok(list) if !list.is_empty() => Ok(Some(list)),
            Ok(_) => Ok(None),
            Err(err) => {
                warn!("Invalid per-host blacklisted_ips value: {}", err);
                Ok(None)
            }
        },
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostConfigList {
    pub host_configs: Vec<HostConfig>,
}

impl Clone for HostConfigList {
    fn clone(&self) -> Self {
        HostConfigList {
            host_configs: self.host_configs.clone(),
        }
    }
}

#[derive(Debug)]
pub struct HostsConfigLoader {
    pub config_list: Mutex<HostConfigList>,
}

impl HostsConfigLoader {
    fn resolve_hosts_conf_path() -> String {
        match env::var("MPROXY_HOSTS_CONFIG_PATH") {
            Ok(p) if !p.is_empty() => p,
            _ => format!("{}/{}", data_path(), "hosts.toml"),
        }
    }

    fn load_config_list(hosts_conf_path: String) -> HostConfigList {
        toml::from_str(fs::read_to_string(&hosts_conf_path).unwrap().as_str()).unwrap()
    }
}

impl HostsConfigLoader {
    pub fn new() -> HostsConfigLoader {
        let hosts_conf_path = HostsConfigLoader::resolve_hosts_conf_path();
        if !fs::exists(&hosts_conf_path).unwrap() {
            panic!("Host config file does not exist: [{}]", &hosts_conf_path);
        }
        HostsConfigLoader {
            config_list: Mutex::from(HostsConfigLoader::load_config_list(hosts_conf_path)),
        }
    }

    pub fn refresh_hosts_config(&mut self) {
        self.config_list =
            HostsConfigLoader::load_config_list(HostsConfigLoader::resolve_hosts_conf_path()).into();
    }

    pub fn load(&self) -> HostConfigList {
        self.config_list.lock().unwrap().clone()
    }
}

