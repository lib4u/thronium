//! Small wire schemas shared by native validation and the generated TypeScript bridge.
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Schema {
    Json,
    Null,
    Boolean,
    Number,
    String,
    Literal { value: Value },
    Array { items: Box<Schema> },
    Map { values: Box<Schema> },
    Object { fields: BTreeMap<String, Field> },
    Union { members: Vec<Schema> },
    Ref { name: String },
}

#[derive(Clone, Serialize)]
pub struct Field {
    pub schema: Schema,
    pub optional: bool,
}

pub fn object(fields: impl IntoIterator<Item = (&'static str, Field)>) -> Schema {
    Schema::Object {
        fields: fields
            .into_iter()
            .map(|(name, field)| (name.into(), field))
            .collect(),
    }
}
pub fn required(schema: Schema) -> Field {
    Field {
        schema,
        optional: false,
    }
}
pub fn optional(schema: Schema) -> Field {
    Field {
        schema,
        optional: true,
    }
}
pub fn reference(name: &str) -> Schema {
    Schema::Ref { name: name.into() }
}
pub fn array(items: Schema) -> Schema {
    Schema::Array {
        items: Box::new(items),
    }
}
pub fn map(values: Schema) -> Schema {
    Schema::Map {
        values: Box::new(values),
    }
}
pub fn nullable(schema: Schema) -> Schema {
    Schema::Union {
        members: vec![Schema::Null, schema],
    }
}
pub fn union(members: Vec<Schema>) -> Schema {
    Schema::Union { members }
}
pub fn literal(value: impl Into<Value>) -> Schema {
    Schema::Literal {
        value: value.into(),
    }
}

impl Schema {
    /// Paths contain declared field names and wildcard map entries, never input values.
    pub fn validate(
        &self,
        value: &Value,
        definitions: &BTreeMap<String, Schema>,
    ) -> Result<(), String> {
        self.validate_at(value, definitions, "$", 0)
    }

    fn validate_at(
        &self,
        value: &Value,
        definitions: &BTreeMap<String, Schema>,
        path: &str,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 128 {
            return Err(path.into());
        }
        let valid = match self {
            Self::Json => true,
            Self::Null => value.is_null(),
            Self::Boolean => value.is_boolean(),
            Self::Number => value.is_number(),
            Self::String => value.is_string(),
            Self::Literal { value: expected } => value == expected,
            Self::Ref { name } => {
                return definitions
                    .get(name)
                    .ok_or_else(|| path.to_owned())?
                    .validate_at(value, definitions, path, depth + 1)
            }
            Self::Array { items } => {
                let values = value.as_array().ok_or_else(|| path.to_owned())?;
                for (index, value) in values.iter().enumerate() {
                    items.validate_at(
                        value,
                        definitions,
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                }
                true
            }
            Self::Map { values } => {
                for value in value.as_object().ok_or_else(|| path.to_owned())?.values() {
                    values.validate_at(value, definitions, &format!("{path}.*"), depth + 1)?;
                }
                true
            }
            Self::Object { fields } => {
                let object = value.as_object().ok_or_else(|| path.to_owned())?;
                for (name, field) in fields {
                    let field_path = format!("{path}.{name}");
                    match object.get(name) {
                        Some(value) => {
                            field
                                .schema
                                .validate_at(value, definitions, &field_path, depth + 1)?
                        }
                        None if field.optional => {}
                        None => return Err(field_path),
                    }
                }
                true
            }
            Self::Union { members } => members.iter().any(|schema| {
                schema
                    .validate_at(value, definitions, path, depth + 1)
                    .is_ok()
            }),
        };
        if valid {
            Ok(())
        } else {
            Err(path.into())
        }
    }

    pub fn typescript(&self) -> String {
        match self {
            Self::Json => "unknown".into(),
            Self::Null => "null".into(),
            Self::Boolean => "boolean".into(),
            Self::Number => "number".into(),
            Self::String => "string".into(),
            Self::Literal { value } => value.to_string(),
            Self::Ref { name } => name.clone(),
            Self::Array { items } => format!("Array<{}>", items.typescript()),
            Self::Map { values } => format!("Record<string, {}>", values.typescript()),
            Self::Union { members } => members
                .iter()
                .map(|schema| format!("({})", schema.typescript()))
                .collect::<Vec<_>>()
                .join(" | "),
            Self::Object { fields } if fields.is_empty() => "Record<string, never>".into(),
            Self::Object { fields } => format!(
                "{{ {} }}",
                fields
                    .iter()
                    .map(|(name, field)| format!(
                        "{}{}: {};",
                        serde_json::json!(name),
                        if field.optional { "?" } else { "" },
                        field.schema.typescript()
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }
}
