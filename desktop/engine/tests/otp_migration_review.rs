//! Independent public API checks for migration boundaries; only public RFC keys.
//! Wire fixtures are built here without calling the migration encoder.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::path::Path;
use thronium_engine::{
    otp::{self, formats, migration, Draft},
    Engine,
};

fn golden(id: &str) -> Value {
    let all: Value =
        serde_json::from_str(include_str!("../src/otp/fixtures/migration/golden.json")).unwrap();
    assert!(all["cases"].as_array().unwrap().len() >= 112);
    all["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone()
}
fn varint(mut n: u64) -> Vec<u8> {
    let mut out = vec![];
    loop {
        let b = (n & 127) as u8;
        n >>= 7;
        out.push(b | if n == 0 { 0 } else { 128 });
        if n == 0 {
            return out;
        }
    }
}
fn number(field: u64, n: u64) -> Vec<u8> {
    [varint(field * 8), varint(n)].concat()
}
fn bytes(field: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(field * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn item(name: &str, issuer: &str, kind: u64, counter: Option<u64>) -> Vec<u8> {
    let mut out = [
        bytes(1, b"12345678901234567890"),
        bytes(2, name.as_bytes()),
        bytes(3, issuer.as_bytes()),
        number(4, 1),
        number(5, 1),
        number(6, kind),
    ]
    .concat();
    if let Some(counter) = counter {
        out.extend(number(7, counter));
    }
    out
}
fn payload(items: &[Vec<u8>], size: u64, index: u64, batch: Option<u64>) -> Vec<u8> {
    let mut out = items
        .iter()
        .flat_map(|entry| bytes(1, entry))
        .collect::<Vec<_>>();
    out.extend(number(2, 1));
    out.extend(number(3, size));
    out.extend(number(4, index));
    if let Some(batch) = batch {
        out.extend(number(5, batch));
    }
    out
}
fn uri(data: &[u8]) -> String {
    format!("otpauth-migration://offline?data={}", STANDARD.encode(data))
}
fn part(name: &str, size: u64, index: u64, batch: Option<u64>) -> String {
    uri(&payload(&[item(name, "", 2, None)], size, index, batch))
}
fn names(drafts: Vec<Draft>) -> Vec<String> {
    drafts.into_iter().map(|d| d.name).collect()
}
fn reject(text: &str, code: &str) {
    match formats::import(text) {
        Ok(_) => panic!("expected {code}"),
        Err(actual) => assert_eq!(actual, code),
    }
}

#[test]
fn actual_qt_multipart_uris_accept_cr_lf_and_crlf_at_public_dispatch_boundary() {
    let zero = golden("batch-two-fragment-0")["link"]
        .as_str()
        .unwrap()
        .to_owned();
    let one = golden("batch-two-fragment-1")["link"]
        .as_str()
        .unwrap()
        .to_owned();
    for separator in ["\n", "\r\n", "\r", "\r\r\n"] {
        let text = format!("  {one}{separator}\t{zero}  ");
        let parsed =
            formats::import(&text).unwrap_or_else(|error| panic!("newline {separator:?}: {error}"));
        assert_eq!(names(parsed), ["Batch part0", "Batch part1"]);
    }
}

#[test]
fn multipart_keeps_first_batch_appearance_and_index_order_and_rejects_collisions() {
    let a0 = part("A0", 2, 0, Some((-17_i64) as u64));
    let a1 = part("A1", 2, 1, Some((-17_i64) as u64));
    let b0 = part("B0", 2, 0, Some(0));
    let b1 = part("B1", 2, 1, Some(0));
    let solo = part("No batch ID", 1, 0, None);
    assert_eq!(
        names(
            formats::import(
                &[a1.clone(), solo.clone(), b1.clone(), a0.clone(), b0.clone()].join("\n")
            )
            .unwrap()
        ),
        ["A0", "A1", "No batch ID", "B0", "B1"]
    );
    assert_eq!(
        names(formats::import(&[solo.clone(), solo].join("\n")).unwrap()),
        ["No batch ID", "No batch ID"]
    );
    for bad in [a0.clone(), [a0.clone(), b1].join("\n")] {
        reject(&bad, "otp_migration_batch_incomplete");
    }
    for other in [
        a0.clone(),
        part("Conflicting replacement", 2, 0, Some((-17_i64) as u64)),
    ] {
        reject(
            &[a0.clone(), other, a1.clone()].join("\n"),
            "otp_migration_batch_duplicate",
        );
    }
    reject(
        &[a0, part("Changed size", 3, 1, Some((-17_i64) as u64))].join("\n"),
        "otp_migration_batch_invalid",
    );
    reject(
        &part("Missing multi ID", 2, 0, None),
        "otp_migration_batch_invalid",
    );
    reject(
        &part("Bad index", 1, 1, None),
        "otp_migration_batch_invalid",
    );
    for value in [
        i32::MAX as u64 + 1,
        u32::MAX as u64,
        (-2147483649_i64) as u64,
    ] {
        reject(
            &part("Truncation", 1, 0, Some(value)),
            "otp_migration_batch_invalid",
        );
    }
    for value in [i32::MIN as i64 as u64, i32::MAX as u64, 0] {
        assert_eq!(
            names(formats::import(&part("Signed boundary", 1, 0, Some(value))).unwrap()),
            ["Signed boundary"]
        );
    }
}

#[test]
fn duplicate_decoded_fields_cannot_hide_behind_nonminimal_varints_and_reordering_is_valid() {
    let original = item("Account", "Issuer", 2, None);
    let mut duplicate = original.clone();
    duplicate.extend([0x9a, 0]);
    duplicate.extend(varint(6));
    duplicate.extend(b"Second");
    reject(
        &uri(&payload(&[duplicate], 1, 0, None)),
        "otp_migration_duplicate_field",
    );
    let mut outer = payload(std::slice::from_ref(&original), 1, 0, None);
    outer.extend([0x90, 0, 0x81, 0]);
    reject(&uri(&outer), "otp_migration_duplicate_field");
    let reversed = [
        number(6, 2),
        number(5, 1),
        number(4, 1),
        bytes(3, b"Issuer"),
        bytes(2, b"Account"),
        bytes(1, b"12345678901234567890"),
    ]
    .concat();
    let nonminimal = [
        number(4, 0),
        number(3, 1),
        vec![0x90, 0, 0x81, 0],
        bytes(1, &reversed),
    ]
    .concat();
    assert!(
        formats::import(&uri(&nonminimal)).unwrap()
            == formats::import(&uri(&payload(&[original], 1, 0, None))).unwrap()
    );
    for invalid in [
        vec![0],
        vec![0x0b],
        vec![
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ],
        vec![0x10, 0x80],
        vec![0x80; 11],
    ] {
        reject(&uri(&invalid), "otp_migration_invalid");
    }
    let mut unknown = payload(&[item("Valid", "", 2, None)], 1, 0, None);
    unknown.extend(number(6, 1));
    reject(&uri(&unknown), "otp_migration_field_unsupported");
}

#[test]
fn uri_percent_decoding_is_single_pass_plus_is_literal_and_padding_bits_are_canonical() {
    let fixture = golden("base64-plus-slash-padding");
    let valid = fixture["link"].as_str().unwrap();
    let expected = formats::import(valid).unwrap();
    assert!(valid.contains('+') && valid.contains('/') && valid.ends_with('='));
    let encoded = valid.replace('+', "%2B").replace('/', "%2F");
    let encoded = encoded.replacen(
        "otpauth-migration:%2F%2Foffline",
        "OTPAUTH-MIGRATION://OFFLINE",
        1,
    );
    assert!(formats::import(&encoded).unwrap() == expected);
    assert!(formats::import(valid.trim_end_matches('=')).unwrap() == expected);
    for bad in [
        valid.replace('+', "%252B"),
        valid.replace('+', "%20"),
        format!("{valid}&data=x"),
        format!("{valid}#ignored"),
        valid.replacen("?data=", "?%64ata=", 1),
        valid.replacen("offline?", "offline/?", 1),
        valid.replacen("offline?", "user@offline?", 1),
        valid.replacen("offline?", "offline:443?", 1),
        format!("{valid}%"),
        format!("{valid}%GG"),
    ] {
        reject(&bad, "otp_migration_invalid");
    }
    // Last canonical Base64 quartet has four zero pad bits. Alter only padding
    // bits while retaining the decoded high bits; strict decoder must refuse it.
    let padded = (1..=3)
        .map(|size| {
            uri(&payload(
                &[item(&"A".repeat(size), "", 2, None)],
                1,
                0,
                None,
            ))
        })
        .find(|encoded| encoded.ends_with("=="))
        .unwrap();
    let mut bytes = padded.into_bytes();
    let at = bytes.len() - 3;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let index = ALPHABET.iter().position(|b| *b == bytes[at]).unwrap();
    assert_eq!(index & 15, 0);
    bytes[at] = ALPHABET[index + 1];
    reject(&String::from_utf8(bytes).unwrap(), "otp_migration_invalid");
}

#[test]
fn unsigned_and_negative_counter_encodings_never_round_into_the_saved_signed_range() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    let values = [0, 9_007_199_254_740_993, i64::MAX as u64];
    let input = uri(&payload(
        &values
            .into_iter()
            .map(|n| item("Counter", "RFC", 1, Some(n)))
            .collect::<Vec<_>>(),
        1,
        0,
        None,
    ));
    assert_eq!(engine.otp_import(&input).unwrap()["added"], 3);
    let metadata = engine.otp_list();
    let ids = metadata
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        metadata
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["counter"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["0", "9007199254740993", "9223372036854775807"]
    );
    assert!(!metadata.to_string().contains("GEZDGNB"));
    let before = json!(engine.store.library);
    for invalid in [i64::MAX as u64 + 1, u64::MAX] {
        let mixed = uri(&payload(
            &[
                item("Valid", "", 1, Some(7)),
                item("Invalid", "", 1, Some(invalid)),
            ],
            1,
            0,
            None,
        ));
        assert_eq!(
            engine.otp_import(&mixed).unwrap_err(),
            "otp_counter_invalid"
        );
        assert_eq!(json!(engine.store.library), before);
    }
    let exported = engine.otp_export(&ids, "migration").unwrap();
    assert!(formats::import(&exported).unwrap() == formats::import(&input).unwrap());
    assert_eq!(json!(engine.store.library), before);
    assert!(json!(engine.snapshot())["running"].is_null());
    drop(engine);
    let reopened = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    assert_eq!(json!(reopened.store.library), before);
}

#[test]
fn unicode_names_whitespace_empty_values_and_lossy_export_guards_preserve_exact_json_fallback() {
    let cases = [
        (" /%+ : account ", " Сервис:日本 🦊 "),
        ("é", "e\u{301}"),
        ("", ""),
        ("Account", ""),
        ("", "Issuer"),
    ];
    for (name, issuer) in cases {
        let link = uri(&payload(&[item(name, issuer, 2, None)], 1, 0, None));
        let drafts = formats::import(&link).unwrap();
        assert_eq!(drafts[0].name, name);
        assert_eq!(drafts[0].issuer, issuer);
        if name.is_empty() && !issuer.is_empty() {
            assert_eq!(
                migration::export_migration(&drafts).unwrap_err(),
                "otp_migration_label_unsupported"
            );
        } else {
            assert!(
                formats::import(&migration::export_migration(&drafts).unwrap()).unwrap() == drafts
            );
        }
        assert!(formats::import(&formats::export_json(&drafts).unwrap()).unwrap() == drafts);
    }
    let original = formats::import(&uri(&payload(&[item("Valid", "", 2, None)], 1, 0, None)))
        .unwrap()
        .remove(0);
    let mut unsupported = vec![];
    for digits in [4, 5, 7, 9, 10] {
        let mut d = original.clone();
        d.digits = digits;
        unsupported.push(d);
    }
    let mut d = original.clone();
    d.period = 17;
    unsupported.push(d);
    let mut d = original.clone();
    d.counter = "7".into();
    unsupported.push(d);
    let mut d = original.clone();
    d.kind = otp::Kind::Hotp;
    d.period = 17;
    unsupported.push(d);
    for draft in unsupported {
        let batch = [original.clone(), draft];
        assert_eq!(
            migration::export_migration(&batch).unwrap_err(),
            "otp_migration_export_unsupported"
        );
        assert!(formats::import(&formats::export_json(&batch).unwrap()).unwrap() == batch);
    }
}

#[test]
fn aggregate_entry_fragment_text_and_utf8_byte_limits_are_checked_before_partial_results() {
    let entry = item("One", "", 2, None);
    assert_eq!(
        formats::import(&uri(&payload(
            &vec![entry.clone(); otp::MAX_ENTRIES],
            1,
            0,
            None
        )))
        .unwrap()
        .len(),
        otp::MAX_ENTRIES
    );
    reject(
        &uri(&payload(&vec![entry; otp::MAX_ENTRIES + 1], 1, 0, None)),
        "otp_entry_limit",
    );
    let fragments = (0..256)
        .map(|i| part(&format!("Part{i}"), 256, i, Some(42)))
        .collect::<Vec<_>>();
    assert_eq!(formats::import(&fragments.join("\n")).unwrap().len(), 256);
    let mut too_many = fragments.clone();
    too_many.push(part("Independent", 1, 0, None));
    reject(&too_many.join("\n"), "otp_migration_batch_invalid");
    reject(&"x".repeat(otp::MAX_TEXT + 1), "otp_text_too_large");
    assert_eq!(
        migration::import_migration(&[&"x".repeat(otp::MAX_TEXT + 1)]).err(),
        Some("otp_text_too_large")
    );
    let label = "é".repeat(256);
    assert_eq!(
        names(formats::import(&part(&label, 1, 0, None)).unwrap()),
        std::slice::from_ref(&label)
    );
    reject(&part(&(label + "x"), 1, 0, None), "otp_label_invalid");
    let parameters = |size: usize| {
        [
            bytes(1, &vec![0x7b; size]),
            number(4, 1),
            number(5, 1),
            number(6, 2),
        ]
        .concat()
    };
    assert_eq!(
        formats::import(&uri(&payload(&[parameters(1024)], 1, 0, None)))
            .unwrap()
            .len(),
        1
    );
    reject(
        &uri(&payload(&[parameters(1025)], 1, 0, None)),
        "otp_secret_too_large",
    );
}

#[test]
fn mixed_text_and_corrupt_fragment_cannot_partially_modify_an_existing_library() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    engine
        .otp_import("otpauth://totp/Existing?secret=GEZDGNBVGY3TQOJQ&digits=6")
        .unwrap();
    let before = json!(engine.store.library);
    let valid = part("Valid", 1, 0, None);
    for text in [
        format!("{valid}\notpauth://totp/Other?secret=GEZDGNBVGY3TQOJQ"),
        format!("GEZDGNBVGY3TQOJQ\n{valid}"),
        format!("{valid}\n{{\"otp\":[]}}"),
    ] {
        assert_eq!(
            engine.otp_import(&text).unwrap_err(),
            "otp_migration_mixed_input"
        );
        assert_eq!(json!(engine.store.library), before);
    }
    let mut incomplete = payload(&[item("Discarded", "", 2, None)], 1, 0, None);
    incomplete.extend([0x0a, 100, 1]);
    assert_eq!(
        engine
            .otp_import(&[valid, uri(&incomplete)].join("\n"))
            .unwrap_err(),
        "otp_migration_invalid"
    );
    assert_eq!(json!(engine.store.library), before);
    assert!(json!(engine.snapshot())["running"].is_null());
}
