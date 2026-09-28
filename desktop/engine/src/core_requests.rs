//! Core RPC channels, request building and configuration checks.
use super::*;

impl Engine {
    pub(crate) async fn ensure_rpc(&mut self) -> Result<&mut Rpc, String> {
        self.credentials_transition_guard()?;
        if self.store.library.preferences.connection_mode != system_proxy::ConnectionMode::Tun
            && self.rpc.as_ref().is_some_and(|r| r.managed())
        {
            if let Some(mut rpc) = self.rpc.take() {
                rpc.terminate().await;
            }
        }
        self.observe_core_exit();
        if self.recovery.pending() {
            return Err("core_reconnecting".into());
        }
        if self.rpc.is_none() {
            self.wait_external_cleanup().await?;
            self.rpc =
                Some(Rpc::spawn_logged(&self.core, &self.data_dir, Some(self.logs.clone())).await?);
        }
        Ok(self.rpc.as_mut().unwrap())
    }

    pub(crate) async fn ensure_tun_rpc(&mut self) -> Result<&mut Rpc, String> {
        self.vpn_probe_guard()?;
        self.credentials_transition_guard()?;
        if self
            .rpc
            .as_mut()
            .is_some_and(|r| r.managed() && r.is_alive())
        {
            return Ok(self.rpc.as_mut().unwrap());
        }
        if let Some(mut rpc) = self.rpc.take() {
            rpc.terminate().await;
        }
        self.rpc = Some(
            Rpc::spawn_managed(
                &self.core,
                &self.data_dir,
                self.logs.clone(),
                self.store.library.preferences.tun.request_permission,
            )
            .await?,
        );
        Ok(self.rpc.as_mut().unwrap())
    }

    pub(crate) fn build(&self, profile: &Profile) -> Result<proto::LoadConfigReq, String> {
        Self::build_with_library(profile, &self.store.library, &self.data_dir)
    }

    pub(crate) fn build_with_library(
        profile: &Profile,
        library: &store::Library,
        directory: &Path,
    ) -> Result<proto::LoadConfigReq, String> {
        Self::build_with_vpn_sources(profile, library, directory, vpn_auth::otp::Intent::Check)
            .map(|(request, _)| request)
    }

    pub(crate) fn build_with_vpn_sources(
        profile: &Profile,
        library: &store::Library,
        directory: &Path,
        intent: vpn_auth::otp::Intent,
    ) -> Result<(proto::LoadConfigReq, vpn_auth::otp::Bindings), String> {
        external_core::runtime::context(library, profile)?;
        vpn_policy::validate_context(library, profile)?;
        routing::legacy_context::validate(library, profile)?;
        let needed = vless::relevant(library, profile)?;
        let (mut compiled_library, mut compiled_profile) = vless::library(library, profile)?;
        for candidate in &mut compiled_library.profiles {
            if needed.contains(&candidate.id) && candidate.kind == ProfileKind::XrayConfig {
                geodata::Assets::new(directory, geodata::provider(candidate, library))
                    .with_library(library)
                    .rewrite_xray(&mut candidate.config)?;
            }
        }
        if compiled_profile.kind == ProfileKind::XrayConfig {
            geodata::Assets::new(directory, geodata::provider(profile, library))
                .with_library(library)
                .rewrite_xray(&mut compiled_profile.config)?;
        }
        settings::prepare_profiles(&mut compiled_library, &mut compiled_profile);
        let mut vpn_sources = vpn_auth::otp::Build::prepare(
            &mut compiled_library,
            &mut compiled_profile,
            &needed,
            library,
            intent,
        )?;
        let aliases = group_chains::prepare(
            &mut compiled_library,
            &mut compiled_profile,
            &vless::roots(library, profile)?,
        )?;
        vpn_sources.alias(aliases.clone());
        let warm_library = library;
        let warm_profile = profile;
        let library = &compiled_library;
        let profile = &compiled_profile;
        if references::key(profile.kind).is_some() {
            let port = library.preferences.inbound_port;
            let mut request = if profile.kind == ProfileKind::AutoSelector {
                auto_selector::build_with_sources(
                    profile,
                    &library.profiles,
                    port,
                    &mut vpn_sources,
                )?
            } else {
                chains::build_with_sources(profile, &library.profiles, port, &mut vpn_sources)?
            };
            // A chain whose first hop is an external core starts that core too:
            // its local server is what the chain dials first.
            if let Some(external) = external_core::runtime::carrier(&library.profiles, profile) {
                external_core::runtime::attach(&mut request, external)?;
            }
            Self::apply_policy(
                &mut request,
                profile,
                library,
                directory,
                &mut vpn_sources,
                &aliases,
            )?;
            auto_selector::apply_warm(&mut request, warm_profile, warm_library)?;
            let vpn_otp = vpn_sources.finish(&request)?;
            return Ok((request, vpn_otp));
        }
        let xray_port = if matches!(
            profile.kind,
            ProfileKind::XrayOutbound | ProfileKind::XrayConfig
        ) {
            let (port, _listener) =
                loopback_ports::claim(&Default::default()).ok_or("xray_port_missing")?;
            Some(port)
        } else {
            None
        };
        let mut request = config::build_with_sources(
            profile,
            library.preferences.inbound_port,
            xray_port,
            &mut vpn_sources,
        )?;
        Self::apply_policy(
            &mut request,
            profile,
            library,
            directory,
            &mut vpn_sources,
            &aliases,
        )?;
        auto_selector::apply_warm(&mut request, warm_profile, warm_library)?;
        let vpn_otp = vpn_sources.finish(&request)?;
        Ok((request, vpn_otp))
    }

    pub(crate) fn apply_policy(
        request: &mut proto::LoadConfigReq,
        profile: &Profile,
        library: &store::Library,
        directory: &Path,
        vpn_sources: &mut vpn_auth::otp::Build,
        aliases: &std::collections::HashMap<String, String>,
    ) -> Result<(), String> {
        let provider = geodata::provider(profile, library);
        let assets = geodata::Assets::new(directory, provider).with_library(library);
        if profile.kind == ProfileKind::XrayConfig {
            // Its policy and immutable geodata references were prepared above.
        } else if geodata::enabled(profile, library) {
            subscriptions::provider_policy::apply(
                request,
                provider.ok_or("subscription_routing_invalid")?,
                &assets,
            )?;
        } else if profile.kind != ProfileKind::SingBoxConfig {
            let mut routing = geodata::catalog::resolve(library.routing.active()?, directory)?;
            routing::resources::resolve(&mut routing, &library.routing_resources, directory)?;
            routing::apply_with_sources(
                request,
                profile,
                &routing,
                &library.profiles,
                vpn_sources,
                aliases,
            )?;
        }
        // Portable files inside profile configurations (full JSON, TLS/SSH
        // inputs of outbounds and chain hops) become immutable cached copies.
        routing::resources::profiles::resolve_request(
            request,
            &library.routing_resources,
            directory,
        )?;
        if profile.kind != ProfileKind::XrayConfig
            && (request.need_xray == Some(true) || !request.xray_full_configs.is_empty())
        {
            request.xray_outbound_dns_strategy =
                Some(match &library.routing.active()?.legacy_constraints {
                    Some(constraints) => constraints
                        .xray_dns_strategy
                        .clone()
                        .ok_or("legacy_routing_xray_dns_missing")?,
                    None => "UseIP".into(),
                });
        }
        settings::apply(request, profile, library)?;
        dashboard::runtime::configure(request, profile, library, directory)?;
        let carrier = if profile.kind == ProfileKind::Chain {
            vpn_policy::carrier(&chains::flatten(profile, &library.profiles)?)
        } else {
            Some(profile)
        };
        if let Some(carrier) = carrier {
            vpn_policy::apply(request, carrier)?;
        }
        settings::configure_cache(request, profile, library, directory)?;
        external_core::runtime::validate_request(request)?;
        #[cfg(target_os = "windows")]
        crate::vpn_endpoint::refuse_host_wrappers(request)?;
        Ok(())
    }

    pub async fn check(&mut self, profile: &Profile) -> Result<(), String> {
        self.wait_external_cleanup().await?;
        let library = self.store.library.clone();
        self.check_with_library(profile, &library).await
    }

    /// Checks `profile` as it would start with `library`: the external core
    /// context is valid, the geodata it needs is present, and the core accepts
    /// the request built from that library. Every check of a draft, import,
    /// subscription, routing or settings change goes through here and adds
    /// only its own preconditions.
    pub(crate) async fn check_with_library(
        &mut self,
        profile: &Profile,
        library: &store::Library,
    ) -> Result<(), String> {
        external_core::runtime::context(library, profile)?;
        crate::geodata::prepare_for(
            &self.geodata,
            profile,
            library,
            &self.data_dir,
            self.settings_download_proxy()?.as_deref(),
        )
        .await?;
        let request = Self::build_with_library(profile, library, &self.data_dir)?;
        self.check_request(&request).await
    }

    pub(crate) async fn check_request(
        &mut self,
        request: &proto::LoadConfigReq,
    ) -> Result<(), String> {
        if external_core::runtime::is_request(request) {
            self.check_external_capability().await?;
        }
        let logs = self.logs.clone();
        logs.protect("check", logs::redact::request_configs(request));
        let rpc = self.ensure_rpc().await?;
        check_config(rpc, request).await.map_err(|(stage, error)| {
            let error = logs::redact::request_values(&error, request.core_config.as_deref());
            logs.event("error", stage, Some(&error));
            error
        })
    }
}
