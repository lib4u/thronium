use super::*;
use serde_json::{json, Value};

#[test]
fn rfc4226_hotp_vectors_never_advance_counter() {
    let mut draft = Draft {
        secret: encode_secret(b"12345678901234567890"),
        kind: Kind::Hotp,
        ..Draft::default()
    };
    for (n, expected) in [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ]
    .iter()
    .enumerate()
    {
        draft.counter = n.to_string();
        let before = serde_json::to_value(&draft).unwrap();
        for time in [0, 1, 2_000_000_000] {
            let result = draft.code_at(time).unwrap();
            assert_eq!(&result.code, expected);
            assert_eq!(result.seconds_remaining, 0);
        }
        assert_eq!(serde_json::to_value(&draft).unwrap(), before);
    }
}

#[test]
fn rfc6238_all_three_hashes_six_times_including_large_timestamp() {
    let times = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];
    for (algorithm, key, values) in [
        (
            Algorithm::SHA1,
            b"12345678901234567890".as_slice(),
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        ),
        (
            Algorithm::SHA256,
            b"12345678901234567890123456789012".as_slice(),
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        ),
        (
            Algorithm::SHA512,
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        ),
    ] {
        let draft = Draft {
            secret: encode_secret(key),
            algorithm,
            digits: 8,
            ..Draft::default()
        };
        for (time, value) in times.into_iter().zip(values) {
            let result = draft.code_at(time).unwrap();
            assert_eq!(result.code, value);
            assert_eq!(result.seconds_remaining, (30 - time % 30) as u16);
        }
    }
}

fn sample() -> Draft {
    Draft {
        name: "Example".into(),
        secret: encode_secret(b"12345678901234567890"),
        ..Draft::default()
    }
}

#[test]
fn base32_preserves_qt_permissive_bits_padding_and_bounds() {
    for (raw, normalized) in [
        ("MY======", "MY"),
        ("m=z-_=\t\r\n", "MY"),
        ("MZX", "MY"),
        ("MZXW6", "MZXW6"),
        ("A A", "AA"),
    ] {
        assert_eq!(normalize_secret(raw).unwrap(), normalized);
    }
    for raw in [
        "",
        "A",
        "= - _\r\n",
        "M0",
        "M1",
        "M8",
        "M9",
        "M!",
        "Mö",
        "M\u{00a0}Y",
    ] {
        assert!(normalize_secret(raw).is_err());
    }
    let maximum = encode_secret(&vec![255; MAX_KEY_BYTES]);
    assert_eq!(decode_secret(&maximum).unwrap().len(), MAX_KEY_BYTES);
    assert!(normalize_secret(&(maximum + "A")).is_err());
    assert!(normalize_secret(&"_".repeat(MAX_SECRET_TEXT + 1)).is_err());
    // Every possible byte roundtrips; normalization stays stable after padding.
    let bytes: Vec<u8> = (0..=255).collect();
    let encoded = encode_secret(&bytes);
    assert_eq!(decode_secret(&encoded).unwrap(), bytes);
    assert_eq!(normalize_secret(&format!("{encoded}===")).unwrap(), encoded);
}

#[test]
fn draft_and_flat_entry_roundtrip_without_secret_in_metadata() {
    let mut draft = sample();
    draft.secret = "mzxw6===".into();
    draft.counter = "00042".into();
    let normalized = draft.normalized().unwrap();
    assert_eq!(normalized.secret, "MZXW6");
    assert_eq!(normalized.counter, "42");
    let entry = Entry {
        id: uuid::Uuid::new_v4().to_string(),
        revision: uuid::Uuid::new_v4().to_string(),
        value: normalized,
    };
    entry.validate().unwrap();
    let encoded = serde_json::to_string(&entry).unwrap();
    assert!(serde_json::from_str::<Entry>(&encoded).unwrap() == entry);
    let value: Value = serde_json::from_str(&encoded).unwrap();
    assert!(value.get("value").is_none());
    assert_eq!(value["counter"], "42");
    let metadata = json!(entry.metadata());
    assert!(metadata.get("secret").is_none());
    assert!(metadata.get("code").is_none());
    assert_eq!(metadata["revision"], entry.revision);
    let draft_json = serde_json::to_string(&entry.value).unwrap();
    assert!(serde_json::from_str::<Draft>(&draft_json).unwrap() == entry.value);
    for (key, bad) in [
        ("counter", json!(42)),
        ("algorithm", json!("SHA3")),
        ("type", json!("unknown")),
        ("secret", json!(null)),
        ("future", json!(true)),
    ] {
        let mut altered = value.clone();
        altered[key] = bad;
        assert!(serde_json::from_value::<Entry>(altered).is_err(), "{key}");
    }
    assert!(serde_json::from_str::<Draft>(r#"{"secret":"MY","secret":"MZ"}"#).is_err());
    assert!(
        serde_json::from_str::<Entry>(&format!("{{\"secret\":\"MY\",{}", &encoded[1..])).is_err()
    );
}

#[test]
fn counters_above_javascript_precision_stay_exact_and_never_overflow() {
    for number in [9007199254740993u64, i64::MAX as u64] {
        let text = format!(
            r#"[{{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","type":"hotp","counter":{number}}}]"#
        );
        let entries = formats::import(&text).unwrap();
        assert_eq!(entries[0].counter, number.to_string());
        let exported = formats::export_json(&entries).unwrap();
        assert!(exported.contains(&format!("\"counter\": \"{number}\"")));
        assert!(formats::import(&exported).unwrap() == entries);
        let uri = formats::export_uri(&entries[0]).unwrap();
        assert!(formats::import_uri(&uri).unwrap() == entries[0]);
        assert_eq!(entries[0].code_at(0).unwrap().code.len(), 6);
    }
    for value in [
        "-1",
        "+1",
        "1.0",
        "1e3",
        "9223372036854775808",
        "18446744073709551615",
        " 1",
        "",
        "00000000000000000000",
    ] {
        assert!(counter(value).is_err());
    }
    for value in ["-1", "1.0", "1e3", "9223372036854775808", "true", "null"] {
        let text = format!(r#"[{{"secret":"MY","counter":{value}}}]"#);
        assert!(formats::import(&text).is_err());
    }
}

#[test]
fn totp_boundaries_extended_digits_and_invalid_ranges() {
    let mut draft = sample();
    for period in [1u16, 30, 3600] {
        draft.period = period;
        for time in [0, u64::from(period) - 1, u64::from(period), i64::MAX as u64] {
            let result = draft.code_at(time).unwrap();
            assert_eq!(
                result.seconds_remaining,
                period - (time % u64::from(period)) as u16
            );
        }
    }
    for digits in 4..=10 {
        draft.digits = digits;
        let result = draft.code_at(0).unwrap();
        assert_eq!(result.code.len(), usize::from(digits));
        assert!(result.code.bytes().all(|c| c.is_ascii_digit()));
    }
    draft.digits = 10;
    draft.period = 30;
    assert_eq!(draft.code_at(1111111109).unwrap().code, "0907081804");
    assert!(draft.code_at(i64::MAX as u64 + 1).is_err());
    for digits in [0, 3, 11, 255] {
        draft.digits = digits;
        assert_eq!(draft.validate().unwrap_err(), "otp_digits_invalid");
    }
    draft.digits = 6;
    for period in [0, 3601, u16::MAX] {
        draft.period = period;
        assert_eq!(draft.validate().unwrap_err(), "otp_period_invalid");
    }
}

#[test]
fn uri_unicode_plus_percent_slash_and_inactive_fields_roundtrip() {
    for kind in [Kind::Totp, Kind::Hotp] {
        let draft = Draft {
            name: "user+tag%/?&:@例子 🦊".into(),
            issuer: "Issuer +%/例子".into(),
            kind,
            period: 45,
            counter: "9007199254740993".into(),
            ..sample()
        };
        let exported = formats::export_uri(&draft).unwrap();
        assert!(exported.contains("%2B"));
        assert!(exported.contains("%25"));
        assert!(formats::import_uri(&exported).unwrap() == draft);
    }
    let plus = formats::import_uri("otpauth://totp/Issuer:a+b?secret=MY&issuer=Issuer").unwrap();
    assert_eq!(plus.name, "a+b");
    let empty_issuer =
        formats::import_uri("otpauth://totp/Issuer:Account?secret=MY&issuer=").unwrap();
    assert_eq!(empty_issuer.issuer, "Issuer");
    for (name, issuer) in [
        (" space", ""),
        ("a:b", ""),
        ("name", "issuer:colon"),
        ("", "Issuer"),
    ] {
        let draft = Draft {
            name: name.into(),
            issuer: issuer.into(),
            ..sample()
        };
        assert!(formats::export_uri(&draft).is_err());
        assert!(
            formats::import(&formats::export_json(std::slice::from_ref(&draft)).unwrap()).unwrap()
                [0]
                == draft
        );
    }
}

#[test]
fn strict_uri_failures_are_atomic_static_and_never_replace_parameters() {
    for uri in [
        "otpauth://hotp/name?secret=MY",
        "otpauth://future/name?secret=MY",
        "otpauth://totp/name?secret=MY&digits=3",
        "otpauth://totp/name?secret=MY&digits=oops",
        "otpauth://totp/name?secret=MY&algorithm=unknown-private",
        "otpauth://totp/name?secret=MY&period=0",
        "otpauth://totp/name?secret=MY&secret=MZ",
        "otpauth://totp/name?secret=MY&%73ecret=MZ",
        "otpauth://totp/name?secret=MY&future=private-secret",
        "otpauth://totp/A:name?secret=MY&issuer=B",
        "otpauth://totp/na%ZZme?secret=MY",
        "otpauth://totp/na%FFme?secret=MY",
        "otpauth://totp/name?secret=MY#private-secret",
        "otpauth://user@totp/name?secret=MY",
        "otpauth://totp:12/name?secret=MY",
    ] {
        let error = formats::import(&format!(
            "{}\n{uri}",
            formats::export_uri(&sample()).unwrap()
        ))
        .err()
        .unwrap();
        assert!(error.starts_with("otp_"));
        assert!(!error.contains("private"));
    }
    assert_eq!(
        formats::import("otpauth-migration://offline?data=private").err(),
        Some("otp_migration_invalid")
    );
}

#[test]
fn strict_json_rejects_unknown_null_duplicate_or_bad_entries_as_a_whole() {
    for field in ["algorithm", "type", "digits", "period", "counter"] {
        let text = format!(r#"[{{"secret":"MY"}},{{"secret":"MY","{field}":null}}]"#);
        assert!(formats::import(&text).is_err(), "{field}");
    }
    for text in [
        r#"[{"secret":"MY"},{"secret":"invalid-private-!"}]"#,
        r#"[{"secret":"MY"},null]"#,
        r#"[{"secret":"MY","secret":"MZ"}]"#,
        r#"{"version":1,"otp":[{"secret":"MY"}],"otp":[{"secret":"MZ"}]}"#,
        r#"{"version":2,"otp":[{"secret":"MY"}]}"#,
        r#"{"otp":[{"secret":"MY"}]}"#,
        r#"[{"secret":"MY","future":"private-value"}]"#,
        r#"[{"secret":"MY","algorithm":"SHA3"}]"#,
        r#"[{"secret":"MY","type":"steam"}]"#,
        r#"[{"secret":"MY","digits":6.0}]"#,
    ] {
        let error = formats::import(text).err().unwrap();
        assert!(!error.contains("private"));
    }
    let entries = formats::import(
        r#"[{"secret":"MY","algorithm":"sha256","type":"HOTP","counter":"00042"}]"#,
    )
    .unwrap();
    assert_eq!(entries[0].algorithm.as_str(), "SHA256");
    assert_eq!(entries[0].counter, "42");
}

#[test]
fn bare_secret_grouping_line_endings_entry_text_and_export_limits() {
    let secret = encode_secret(b"1234567890");
    assert_eq!(
        formats::import(&format!("{secret}\r{secret}\n{secret}\r\n"))
            .unwrap()
            .len(),
        3
    );
    assert!(formats::import("GEZD GNBV GY3T QOJQ").is_ok());
    assert!(formats::import("GEZD GNBVGY3T QOJQ").is_err());
    assert!(formats::import("MY").is_err());
    assert!(formats::import(&" ".repeat(MAX_TEXT + 1)).is_err());
    assert_eq!(
        formats::import(&format!("{secret}\n").repeat(MAX_ENTRIES + 1)).err(),
        Some("otp_entry_limit")
    );
    assert_eq!(
        formats::import(&format!("{secret}\n").repeat(MAX_ENTRIES))
            .unwrap()
            .len(),
        MAX_ENTRIES
    );
    assert_eq!(
        formats::export_json(&vec![sample(); MAX_ENTRIES + 1]).err(),
        Some("otp_entry_limit")
    );
    let draft = Draft {
        secret: encode_secret(&vec![1; MAX_KEY_BYTES]),
        ..sample()
    };
    assert_eq!(
        formats::export_json(&vec![draft; 1000]).err(),
        Some("otp_text_too_large")
    );
    let mut draft = sample();
    draft.name = "\nprivate-name".into();
    assert_eq!(draft.validate().unwrap_err(), "otp_label_invalid");
}

#[test]
fn independent_unmodified_qt_oracle_matches_codes_normalization_and_compatible_links() {
    use sha2::Digest;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/otp/fixtures");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory.join("qt-oracle-manifest.json")).unwrap())
            .unwrap();
    for (path, hash) in manifest["sources"].as_object().unwrap() {
        // Qt's own files are frozen beside the oracle; this repository's are read.
        let body = match crate::qt_source::verbatim(path) {
            Some(frozen) => frozen.to_vec(),
            None => std::fs::read(root.join(path)).unwrap(),
        };
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(body)),
            hash.as_str().unwrap(),
            "Qt reference source changed: {path}"
        );
    }
    let golden: Value =
        serde_json::from_slice(&std::fs::read(directory.join("golden.json")).unwrap()).unwrap();
    assert_eq!(golden["qtRuntime"], "6.11.2");
    let cases = golden["cases"].as_array().unwrap();
    assert!(cases.len() >= 266);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        if case["normalizeOnly"] == true {
            let actual = normalize_secret(case["secret"].as_str().unwrap());
            if expected["normalized"] == "" {
                assert!(actual.is_err(), "{id}");
            } else {
                assert_eq!(actual.unwrap(), expected["normalized"], "{id}");
            }
            continue;
        }
        if case.get("strictReject").is_some() {
            if let Some(link) = case["link"].as_str() {
                assert!(formats::import_uri(link).is_err(), "{id}");
            } else {
                let draft: Draft = serde_json::from_value(case["entry"].clone()).unwrap();
                assert!(draft.normalized().is_err(), "{id}");
            }
            continue;
        }
        let draft: Draft = serde_json::from_value(case["entry"].clone()).unwrap();
        let normalized = draft.normalized().unwrap();
        assert_eq!(normalized.secret, expected["normalized"], "{id}");
        let time = case["time"].as_str().unwrap().parse().unwrap();
        let generated = draft.code_at(time).unwrap();
        assert_eq!(generated.code, expected["code"], "{id}");
        assert_eq!(
            json!(generated.seconds_remaining),
            expected["secondsRemaining"],
            "{id}"
        );
        let lossy = case["qtUriLossyFields"].as_array().unwrap();
        if !lossy.iter().any(|v| v == "name" || v == "issuer") {
            let from_qt = formats::import_uri(expected["link"].as_str().unwrap())
                .unwrap_or_else(|code| panic!("Qt link {id}: {code}"));
            assert_eq!(json!(from_qt), expected["parsed"], "{id}");
            let output = formats::export_uri(&draft).unwrap();
            assert!(formats::import_uri(&output).unwrap() == normalized, "{id}");
        } else {
            assert!(
                formats::export_uri(&draft).is_err(),
                "lossy Qt labels should be refused: {id}"
            );
        }
        let json = formats::export_json(&[draft]).unwrap();
        assert!(formats::import(&json).unwrap()[0] == normalized, "{id}");
        // Qt's JSON exporter omits dormant fields. Its active code must still
        // survive importing that actual export, including numeric i64 counters.
        let qt_json = formats::import(expected["json"].as_str().unwrap()).unwrap();
        assert_eq!(
            qt_json[0].code_at(time).unwrap().code,
            expected["code"],
            "{id}"
        );
    }
}
