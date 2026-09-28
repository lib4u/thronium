//! Source JSON must not silently discard duplicate object members.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{cell::Cell, fmt};

struct JsonSeed<'a>(&'a Cell<usize>);

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        let count = self.0.get() + 1;
        if count > 100_000 {
            return Err(de::Error::custom("JSON item limit"));
        }
        self.0.set(count);
        struct JsonVisitor<'a>(&'a Cell<usize>);
        impl<'de> Visitor<'de> for JsonVisitor<'_> {
            type Value = Value;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON without duplicate object members")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Value::String(value.to_owned()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(Value::String(value))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element_seed(JsonSeed(self.0))? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    let value = object.next_value_seed(JsonSeed(self.0))?;
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object member"));
                    }
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(JsonVisitor(self.0))
    }
}

pub(crate) fn parse(text: &str) -> Result<Value, serde_json::Error> {
    parse_counted(text).map(|(value, _)| value)
}

pub(crate) fn parse_counted(text: &str) -> Result<(Value, usize), serde_json::Error> {
    // serde_json's default recursion limit remains enabled.
    let mut reader = serde_json::Deserializer::from_str(text);
    let count = Cell::new(0);
    let value = JsonSeed(&count).deserialize(&mut reader)?;
    reader.end()?;
    Ok((value, count.get()))
}
