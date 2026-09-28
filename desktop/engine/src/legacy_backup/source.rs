use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Default, Serialize, PartialEq, Eq, Debug)]
pub struct Parts {
    pub profiles: bool,
    pub routes: bool,
    pub settings: bool,
    pub otp: bool,
    pub icons: bool,
}

pub struct SourceArchive {
    pub container_version: u32,
    pub content_version: Option<u32>,
    pub metadata: Value,
    pub created_at: Option<String>,
    pub parts: Parts,
    /// Keys are labels, never output paths. Null and empty byte arrays remain distinct.
    pub files: BTreeMap<String, Option<Vec<u8>>>,
    pub database: Option<SourceDatabase>,
}

#[derive(Clone, PartialEq)]
pub enum SourceValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}
pub type SourceRow = BTreeMap<String, SourceValue>;

pub struct SourceProfile {
    pub id: i64,
    pub kind: String,
    pub name: Option<String>,
    pub group_id: i64,
    pub outbound: Value,
    pub columns: SourceRow,
}
pub struct SourceGroup {
    pub id: i64,
    pub name: String,
    pub columns: SourceRow,
}
#[derive(Clone)]
pub struct SourceRoute {
    pub id: i64,
    pub name: String,
    pub columns: SourceRow,
}
#[derive(Clone)]
pub struct SourceRule {
    pub route_id: i64,
    pub order: i64,
    pub kind: i64,
    pub columns: SourceRow,
}
#[derive(Clone)]
pub struct SourceSetting {
    pub key: String,
    pub value: String,
    pub columns: SourceRow,
}
pub struct SourceOtp {
    pub id: i64,
    pub columns: SourceRow,
}
pub struct SourceColumn {
    pub name: String,
    pub declared_type: String,
    pub not_null: bool,
    pub default_sql: Option<String>,
    pub primary_key_order: i64,
}
pub struct SourceSchema {
    pub kind: String,
    pub name: String,
    pub table_name: String,
    /// Preserved for a future compatibility report; never executed as SQL.
    pub sql: Option<String>,
    pub columns: Vec<SourceColumn>,
}
#[derive(Default)]
pub struct SourceDatabase {
    pub profiles: Vec<SourceProfile>,
    pub groups: Vec<SourceGroup>,
    pub group_order: Vec<SourceRow>,
    pub routes: Vec<SourceRoute>,
    pub rules: Vec<SourceRule>,
    pub settings: Vec<SourceSetting>,
    pub otp: Vec<SourceOtp>,
    pub entity_ids: Vec<SourceRow>,
    pub other_tables: BTreeMap<String, Vec<SourceRow>>,
    pub schema: Vec<SourceSchema>,
}
impl SourceDatabase {
    /// Profiles by id; a duplicate id leaves the index shorter than the list.
    pub fn profiles_by_id(&self) -> BTreeMap<i64, &SourceProfile> {
        self.profiles.iter().map(|p| (p.id, p)).collect()
    }
}

/// Only this explicitly limited structure is intended for a public UI response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub container_version: u32,
    pub content_version: Option<u32>,
    pub parts: Parts,
    pub files: usize,
    pub icons: usize,
    pub unknown_files: usize,
    pub profiles: usize,
    pub groups: usize,
    pub routes: usize,
    pub rules: usize,
    pub settings: usize,
    pub otp: usize,
    pub other_tables: usize,
    pub schema_objects: usize,
}
impl SourceArchive {
    pub fn inventory(&self) -> Inventory {
        let database = self.database.as_ref();
        Inventory {
            container_version: self.container_version,
            content_version: self.content_version,
            parts: self.parts,
            files: self.files.len(),
            icons: self
                .files
                .keys()
                .filter(|k| k.starts_with("icons/"))
                .count(),
            unknown_files: self
                .files
                .keys()
                .filter(|k| *k != "database" && !k.starts_with("icons/"))
                .count(),
            profiles: database.map_or(0, |d| d.profiles.len()),
            groups: database.map_or(0, |d| d.groups.len()),
            routes: database.map_or(0, |d| d.routes.len()),
            rules: database.map_or(0, |d| d.rules.len()),
            settings: database.map_or(0, |d| d.settings.len()),
            otp: database.map_or(0, |d| d.otp.len()),
            other_tables: database.map_or(0, |d| d.other_tables.len()),
            schema_objects: database.map_or(0, |d| d.schema.len()),
        }
    }
}
