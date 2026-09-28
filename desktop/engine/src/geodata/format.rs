//! Xray geodata files (geoip.dat, geosite.dat) decoded into sing-box rule sets.
use super::*;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Attr {
    #[prost(string, tag = "1")]
    pub(crate) key: String,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Domain {
    #[prost(int32, tag = "1")]
    pub(crate) kind: i32,
    #[prost(string, tag = "2")]
    pub(crate) value: String,
    #[prost(message, repeated, tag = "3")]
    pub(crate) attribute: Vec<Attr>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Site {
    #[prost(string, tag = "1")]
    pub(crate) code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) domain: Vec<Domain>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct SiteList {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entry: Vec<Site>,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) prefix: u32,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Ip {
    #[prost(string, tag = "1")]
    pub(crate) code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub(crate) reverse_match: bool,
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct IpList {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entry: Vec<Ip>,
}
pub(crate) fn convert(bytes: &[u8], sites: bool, code: &str) -> Result<Vec<Value>, String> {
    if sites {
        let mut parts = code.split('@');
        let code = parts.next().unwrap();
        let attrs: Vec<_> = parts.collect();
        let list = SiteList::decode(bytes).map_err(|_| "geodata_invalid")?;
        let entry = list
            .entry
            .into_iter()
            .find(|e| e.code.eq_ignore_ascii_case(code))
            .ok_or("geodata_category_missing")?;
        if entry
            .domain
            .iter()
            .any(|d| !(0..4).contains(&d.kind) || d.value.is_empty())
        {
            return Err("geodata_invalid".into());
        }
        let mut rules = vec![];
        // Separate headless rules preserve OR across the four domain match types.
        for kind in 0..4 {
            let values: Vec<_> = entry
                .domain
                .iter()
                .filter(|d| {
                    d.kind == kind
                        && attrs
                            .iter()
                            .all(|a| d.attribute.iter().any(|x| x.key == *a))
                })
                .map(|d| &d.value)
                .collect();
            if !values.is_empty() {
                let mut rule = json!({});
                rule[["domain_keyword", "domain_regex", "domain_suffix", "domain"]
                    [kind as usize]] = json!(values);
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            return Err("geodata_category_empty".into());
        }
        Ok(rules)
    } else {
        let invert = code.starts_with('!');
        let code = code.trim_start_matches('!');
        let list = IpList::decode(bytes).map_err(|_| "geodata_invalid")?;
        let entry = list
            .entry
            .into_iter()
            .find(|e| e.code.eq_ignore_ascii_case(code))
            .ok_or("geodata_category_missing")?;
        let mut cidrs = vec![];
        for c in entry.cidr {
            let address = match c.ip.len() {
                4 if c.prefix <= 32 => {
                    Ipv4Addr::from(<[u8; 4]>::try_from(c.ip).unwrap()).to_string()
                }
                16 if c.prefix <= 128 => {
                    Ipv6Addr::from(<[u8; 16]>::try_from(c.ip).unwrap()).to_string()
                }
                _ => return Err("geodata_invalid".into()),
            };
            cidrs.push(format!("{address}/{}", c.prefix));
        }
        if cidrs.is_empty() {
            return Err("geodata_category_empty".into());
        }
        Ok(vec![
            json!({"ip_cidr":cidrs,"invert":invert ^ entry.reverse_match}),
        ])
    }
}
/// A valid one-category geosite list for tests; `domain` keeps fixtures distinct.
#[cfg(test)]
pub(crate) fn site_list_fixture(code: &str, domain: &str) -> Vec<u8> {
    SiteList {
        entry: vec![Site {
            code: code.into(),
            domain: vec![Domain {
                kind: 2,
                value: domain.into(),
                attribute: vec![],
            }],
        }],
    }
    .encode_to_vec()
}
