//! Validate once away from the Engine lock. Retain only category availability.
use super::{Kind, LIMIT};
use crate::geodata::{IpList, SiteList};
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Category {
    nonempty: bool,
    // Distinct attribute combinations preserve AND on one domain and OR across domains.
    attributes: BTreeSet<Vec<String>>,
}
pub(super) struct Index {
    kind: Kind,
    categories: BTreeMap<String, Category>,
    pub entries: usize,
}
impl Index {
    pub fn parse(bytes: &[u8], kind: Kind) -> Result<Self, String> {
        if bytes.len() > LIMIT {
            return Err("geodata_too_large".into());
        }
        if bytes.is_empty() {
            return Err("geodata_invalid".into());
        }
        let mut index = Self {
            kind,
            categories: BTreeMap::new(),
            entries: 0,
        };
        if kind.sites() {
            let list = SiteList::decode(bytes).map_err(|_| "geodata_invalid")?;
            for entry in list.entry {
                let mut category = Category::default();
                for domain in entry.domain {
                    if !(0..4).contains(&domain.kind) || domain.value.is_empty() {
                        return Err("geodata_invalid".into());
                    }
                    category.nonempty = true;
                    let mut attrs: Vec<_> = domain.attribute.into_iter().map(|a| a.key).collect();
                    attrs.sort();
                    attrs.dedup();
                    category.attributes.insert(attrs);
                    index.entries += 1;
                }
                index.insert(entry.code, category)?;
            }
        } else {
            let list = IpList::decode(bytes).map_err(|_| "geodata_invalid")?;
            for entry in list.entry {
                if entry
                    .cidr
                    .iter()
                    .any(|c| !matches!((c.ip.len(), c.prefix), (4, 0..=32) | (16, 0..=128)))
                {
                    return Err("geodata_invalid".into());
                }
                index.entries += entry.cidr.len();
                index.insert(
                    entry.code,
                    Category {
                        nonempty: !entry.cidr.is_empty(),
                        ..Default::default()
                    },
                )?;
            }
        }
        if index.categories.is_empty() {
            return Err("geodata_invalid".into());
        }
        Ok(index)
    }
    fn insert(&mut self, code: String, category: Category) -> Result<(), String> {
        if code.is_empty()
            || self
                .categories
                .insert(code.to_ascii_lowercase(), category)
                .is_some()
        {
            return Err("geodata_invalid".into());
        }
        Ok(())
    }
    pub fn count(&self) -> usize {
        self.categories.len()
    }
    pub fn require(&self, raw: &str) -> Result<(), String> {
        let (code, attrs) = if self.kind.sites() {
            let mut parts = raw.split('@');
            (parts.next().unwrap(), parts.collect::<Vec<_>>())
        } else {
            (raw.trim_start_matches('!'), vec![])
        };
        let category = self
            .categories
            .get(&code.to_ascii_lowercase())
            .ok_or("geodata_category_missing")?;
        if !category.nonempty
            || (!attrs.is_empty()
                && !category
                    .attributes
                    .iter()
                    .any(|a| attrs.iter().all(|x| a.iter().any(|v| v == x))))
        {
            return Err("geodata_category_empty".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geodata::{Attr, Cidr, Domain, Ip, Site};
    fn domain(attrs: &[&str]) -> Domain {
        Domain {
            kind: 2,
            value: "owned.test".into(),
            attribute: attrs.iter().map(|s| Attr { key: (*s).into() }).collect(),
        }
    }
    #[test]
    fn refresh_validation_matches_real_conversion_with_joint_attributes() {
        let bytes = SiteList {
            entry: vec![Site {
                code: "TEST".into(),
                domain: vec![domain(&["a"]), domain(&["b"]), domain(&["a", "c"])],
            }],
        }
        .encode_to_vec();
        let index = Index::parse(&bytes, Kind::Geosite).unwrap();
        assert_eq!(index.count(), 1);
        assert_eq!(index.entries, 3);
        for code in [
            "test",
            "TeSt@a",
            "test@b",
            "test@a@c",
            "test@a@b",
            "test@missing",
            "missing",
        ] {
            assert_eq!(
                index.require(code).is_ok(),
                crate::geodata::convert(&bytes, true, code).is_ok(),
                "{code}"
            );
        }
        assert!(index.require("test@a@b").is_err());
    }
    #[test]
    fn addresses_inversion_empty_and_duplicate_categories_are_distinguished() {
        let entry = Ip {
            code: "TEST".into(),
            reverse_match: true,
            cidr: vec![
                Cidr {
                    ip: vec![127, 0, 0, 0],
                    prefix: 8,
                },
                Cidr {
                    ip: vec![0; 16],
                    prefix: 128,
                },
            ],
        };
        let bytes = IpList {
            entry: vec![
                entry.clone(),
                Ip {
                    code: "empty".into(),
                    cidr: vec![],
                    reverse_match: false,
                },
            ],
        }
        .encode_to_vec();
        let index = Index::parse(&bytes, Kind::Geoip).unwrap();
        for code in ["test", "!test", "!!TEST", "empty", "!empty", "missing"] {
            assert_eq!(
                index.require(code).is_ok(),
                crate::geodata::convert(&bytes, false, code).is_ok(),
                "{code}"
            );
        }
        let duplicate = IpList {
            entry: vec![
                entry.clone(),
                Ip {
                    code: "test".into(),
                    ..entry.clone()
                },
            ],
        }
        .encode_to_vec();
        assert!(Index::parse(&duplicate, Kind::Geoip).is_err());
        let invalid = IpList {
            entry: vec![Ip {
                cidr: vec![Cidr {
                    ip: vec![1; 4],
                    prefix: 33,
                }],
                ..entry
            }],
        }
        .encode_to_vec();
        assert!(Index::parse(&invalid, Kind::Geoip).is_err());
        assert!(Index::parse(&[], Kind::Geoip).is_err());
        assert!(Index::parse(b"truncated", Kind::Geosite).is_err());
    }
}
