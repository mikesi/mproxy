use ipnet::IpNet;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
enum IpBlacklistEntry {
    Ip(IpAddr),
    Cidr(IpNet),
}

impl IpBlacklistEntry {
    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Ip(single) => *single == ip,
            Self::Cidr(net) => net.contains(&ip),
        }
    }
}

impl Display for IpBlacklistEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{}", ip),
            Self::Cidr(net) => write!(f, "{}", net),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpBlacklist {
    entries: Vec<IpBlacklistEntry>,
}

impl IpBlacklist {
    pub fn from_string(value: &str) -> Result<Self, String> {
        let mut entries = Vec::new();

        for raw in value.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }

            if let Ok(ip) = item.parse::<IpAddr>() {
                entries.push(IpBlacklistEntry::Ip(ip));
                continue;
            }

            if let Ok(cidr) = item.parse::<IpNet>() {
                entries.push(IpBlacklistEntry::Cidr(cidr));
                continue;
            }

            return Err(format!("Invalid IP or CIDR entry: {}", item));
        }

        Ok(Self { entries })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.entries.iter().any(|entry| entry.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Display for IpBlacklist {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let items: Vec<String> = self.entries.iter().map(|entry| entry.to_string()).collect();
        write!(f, "{}", items.join(","))
    }
}

impl Serialize for IpBlacklist {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for IpBlacklist {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_string(raw.as_str()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::IpBlacklist;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn parse_single_ip() {
        let blacklist = IpBlacklist::from_string("192.168.1.5").unwrap();
        assert!(blacklist.contains(IpAddr::from_str("192.168.1.5").unwrap()));
        assert!(!blacklist.contains(IpAddr::from_str("192.168.1.6").unwrap()));
    }

    #[test]
    fn parse_single_cidr() {
        let blacklist = IpBlacklist::from_string("10.0.0.0/24").unwrap();
        assert!(blacklist.contains(IpAddr::from_str("10.0.0.77").unwrap()));
        assert!(!blacklist.contains(IpAddr::from_str("10.0.1.77").unwrap()));
    }

    #[test]
    fn parse_mixed_entries() {
        let blacklist = IpBlacklist::from_string("192.168.1.5,10.0.0.0/24,127.0.0.1").unwrap();
        assert!(blacklist.contains(IpAddr::from_str("192.168.1.5").unwrap()));
        assert!(blacklist.contains(IpAddr::from_str("10.0.0.42").unwrap()));
        assert!(blacklist.contains(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!blacklist.contains(IpAddr::from_str("10.0.1.42").unwrap()));
    }

    #[test]
    fn parse_ignores_empty_items_and_whitespace() {
        let blacklist = IpBlacklist::from_string(" 127.0.0.1 , ,10.0.0.0/24 ").unwrap();
        assert!(blacklist.contains(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(blacklist.contains(IpAddr::from_str("10.0.0.10").unwrap()));
    }

    #[test]
    fn parse_invalid_entry() {
        let err = IpBlacklist::from_string("192.168.1.5,not-an-ip").unwrap_err();
        assert!(err.contains("not-an-ip"));
    }
}
