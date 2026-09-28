//! Wire DTO declarations. Update here; TypeScript and validators are generated from Rust.
use super::schema::*;
use std::collections::BTreeMap;
mod backups;
mod choices;
mod diagnostics;
mod otp;
mod profiles;
mod routing;
mod selectors;
mod snapshot;
mod subscriptions;
mod vpn;
pub fn definitions() -> BTreeMap<String, Schema> {
    let mut models: BTreeMap<String, Schema> = [
        choices::entries(),
        profiles::entries(),
        snapshot::entries(),
        subscriptions::entries(),
        vpn::entries(),
        backups::entries(),
        diagnostics::entries(),
        otp::entries(),
        routing::entries(),
        selectors::entries(),
    ]
    .into_iter()
    .flatten()
    .collect();
    // Read DTOs remain complete; request DTOs preserve Serde's legacy defaults.
    let mut names = models["SubscriptionNameRules"].clone();
    if let Schema::Object { fields } = &mut names {
        for field in fields.values_mut() {
            field.optional = true;
        }
    }
    models.insert("SubscriptionNameRulesInput".into(), names);
    let mut subscription = models["SubscriptionSettings"].clone();
    if let Schema::Object { fields } = &mut subscription {
        for (name, field) in fields.iter_mut() {
            field.optional = name != "url";
        }
        fields.get_mut("nameRules").unwrap().schema = reference("SubscriptionNameRulesInput");
    }
    models.insert("SubscriptionSettingsInput".into(), subscription);
    let mut otp = models["OtpDraft"].clone();
    if let Schema::Object { fields } = &mut otp {
        for (name, field) in fields.iter_mut() {
            field.optional = name != "secret";
        }
    }
    models.insert("OtpDraftInput".into(), otp);
    models
}
