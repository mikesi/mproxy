use crate::data_path;
use serde::{Deserialize, Serialize};
use std::fs;
use std::env;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostConfig {
    pub host_name: String,
    pub aliases: Option<Vec<String>>,
    pub upstream_address: String,
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

