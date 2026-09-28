//! Command names, requests and replies. Domain handlers retain their business validation.
use super::Command;
use std::collections::BTreeMap;
mod backups;
mod connection;
mod diagnostics;
mod library;
mod otp;
mod routing;
mod selectors;
mod settings;
mod subscriptions;
mod transfer;
mod vpn;
pub fn commands() -> BTreeMap<String, Command> {
    [
        library::entries(),
        connection::entries(),
        subscriptions::entries(),
        routing::entries(),
        selectors::entries(),
        diagnostics::entries(),
        vpn::entries(),
        transfer::entries(),
        backups::entries(),
        settings::entries(),
        otp::entries(),
    ]
    .into_iter()
    .flatten()
    .collect()
}
