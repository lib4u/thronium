use super::*;

pub(super) fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn text(value: &str) -> bool {
    valid_text(value)
}

pub(super) fn details(challenge: &proto::VpnChallenge, protocol: &str) -> Result<(), String> {
    use prost::Message;
    let unsupported = || "vpn_auth_unsupported".to_string();
    if challenge.encoded_len() > 65536
        || challenge.fields.len() > 128
        || challenge
            .deadline
            .is_some_and(|n| !(0..=9_007_199_254_740_991).contains(&n))
    {
        return Err(unsupported());
    }
    for value in [
        &challenge.username,
        &challenge.message,
        &challenge.banner,
        &challenge.error,
        &challenge.url,
    ] {
        if !text(value.as_deref().unwrap_or("")) {
            return Err(unsupported());
        }
    }
    let kind = challenge.kind.as_deref().unwrap_or("");
    if !matches!(
        (protocol, kind),
        ("openvpn", "credentials" | "secret" | "message" | "open-url")
            | ("openconnect", "form" | "browser")
    ) {
        return Err(unsupported());
    }
    if kind != "form" {
        return if challenge.fields.is_empty() {
            Ok(())
        } else {
            Err(unsupported())
        };
    }
    if challenge.fields.is_empty() {
        return Err(unsupported());
    }
    let mut keys = HashSet::new();
    let mut option_count = 0usize;
    for field in &challenge.fields {
        let key = field.submission_key.as_deref().unwrap_or("");
        if !identity(key) || !keys.insert(key) {
            return Err(unsupported());
        }
        for value in [&field.name, &field.label, &field.value] {
            if !text(value.as_deref().unwrap_or("")) {
                return Err(unsupported());
            }
        }
        let kind = field.kind.as_deref().unwrap_or("");
        if !matches!(kind, "text" | "password" | "select") {
            return Err(unsupported());
        }
        option_count += field.options.len();
        if field.options.len() > 128
            || option_count > 1024
            || (kind == "select") == field.options.is_empty()
        {
            return Err(unsupported());
        }
        let mut values = HashSet::new();
        for option in &field.options {
            let value = option.value.as_deref().unwrap_or("");
            if !text(value) || !text(option.label.as_deref().unwrap_or("")) || !values.insert(value)
            {
                return Err(unsupported());
            }
        }
        // An empty default means no selected option; never invent a choice.
        let selected = field.value.as_deref().unwrap_or("");
        if kind == "select" && !selected.is_empty() && !values.contains(selected) {
            return Err(unsupported());
        }
    }
    Ok(())
}

pub(super) fn answer_size(request: &SubmitRequest) -> Result<(), String> {
    let mut size = 0usize;
    for value in [&request.username, &request.password, &request.secret]
        .into_iter()
        .chain(request.form_values.iter().flat_map(|(k, v)| [k, v]))
    {
        if !text(value) {
            return Err("vpn_auth_invalid_response".into());
        }
        size += value.len();
    }
    if size > 65536 || request.form_values.len() > 128 {
        return Err("vpn_auth_invalid_response".into());
    }
    Ok(())
}

pub(super) fn answer(
    challenge: &proto::VpnChallenge,
    protocol: &str,
    request: &SubmitRequest,
) -> Result<(), String> {
    details(challenge, protocol)?;
    answer_size(request)?;
    let valid = match challenge.kind.as_deref().unwrap_or("") {
        "credentials" => request.form_values.is_empty(),
        "secret" => {
            request.username.is_empty()
                && request.password.is_empty()
                && request.form_values.is_empty()
        }
        "message" => {
            request.username.is_empty()
                && request.password.is_empty()
                && request.secret.is_empty()
                && request.form_values.is_empty()
        }
        "form" => {
            request.username.is_empty()
                && request.password.is_empty()
                && request.secret.is_empty()
                && request.form_values.len() == challenge.fields.len()
                && challenge.fields.iter().all(|field| {
                    request
                        .form_values
                        .get(field.submission_key.as_deref().unwrap_or(""))
                        .is_some_and(|answer| {
                            field.kind.as_deref() != Some("select")
                                || field
                                    .options
                                    .iter()
                                    .any(|option| option.value.as_deref().unwrap_or("") == answer)
                        })
                })
        }
        _ => return Err("vpn_auth_unsupported".into()),
    };
    if valid {
        Ok(())
    } else {
        Err("vpn_auth_invalid_response".into())
    }
}

pub(super) fn url(raw: &str) -> Result<String, String> {
    if !text(raw) || raw.chars().any(char::is_control) || raw.trim() != raw {
        return Err("vpn_auth_url_invalid".into());
    }
    let url = reqwest::Url::parse(raw).map_err(|_| "vpn_auth_url_invalid")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("vpn_auth_url_invalid".into());
    }
    Ok(raw.into())
}
