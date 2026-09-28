//! Full configuration is only returned by an explicit user command.
use crate::{proto, store::ProfileKind, Engine};
use serde_json::{json, Value};

impl Engine {
    pub async fn connection_configuration(
        &mut self,
        id: &str,
        active: bool,
    ) -> Result<Value, String> {
        self.snapshot();
        let profile = self.profile(id)?;
        let request = if active {
            let connection = self
                .active_connection
                .as_ref()
                .filter(|c| c.id == id)
                .ok_or("active_configuration_unavailable")?;
            if connection.tun {
                self.rpc
                    .as_mut()
                    .ok_or("active_configuration_unavailable")?
                    .call::<_, proto::LoadConfigReq>("ManagedTunConfiguration", proto::EmptyReq {})
                    .await?
            } else {
                connection.redacted_request()?
            }
        } else {
            crate::external_core::runtime::context(&self.store.library, &profile)?;
            crate::geodata::prepare_for(
                &self.geodata,
                &profile,
                &self.store.library,
                &self.data_dir,
                self.settings_download_proxy()?.as_deref(),
            )
            .await?;
            let mut request = self.build(&profile)?;
            crate::tun::apply(&mut request, &profile, &self.store.library.preferences)?;
            crate::tun::apply_settings(&mut request, &self.store.library)?;
            request
        };
        let mut parts =
            vec![json!({"name":"sing-box", "config":parse(request.core_config.as_deref())?})];
        if crate::external_core::runtime::is_request(&request) {
            parts.push(json!({"name":crate::profile_descriptor::EXTERNAL_CORE, "config":crate::external_core::runtime::configuration(&request)?}));
        }
        if request.need_xray == Some(true) {
            parts.push(json!({"name":"Xray", "config":parse(request.xray_config.as_deref())?}));
        }
        for (index, config) in request.xray_full_configs.iter().enumerate() {
            parts
                .push(json!({"name":format!("Xray {}", index + 2), "config":parse(Some(config))?}));
        }
        Ok(
            json!({"source":if active {"active"} else {"preview"}, "parts":parts,
            "profileOwned":matches!(profile.kind, ProfileKind::SingBoxConfig | ProfileKind::XrayConfig)}),
        )
    }
}

fn parse(input: Option<&str>) -> Result<Value, String> {
    serde_json::from_str(input.ok_or("invalid_configuration")?)
        .map_err(|_| "invalid_configuration".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProfileDraft;
    #[tokio::test]
    async fn preview_has_actual_dns_and_routing_without_starting_a_core() {
        let directory = tempfile::tempdir().unwrap();
        let mut engine =
            Engine::open(directory.path(), &directory.path().join("absent-core")).unwrap();
        let id = engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "fixture".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"direct"}),
            })
            .unwrap();
        let preview = engine.connection_configuration(&id, false).await.unwrap();
        assert!(preview["parts"][0]["config"]["dns"].is_object());
        assert!(preview["parts"][0]["config"]["route"].is_object());
        assert_eq!(
            preview["parts"][0]["config"]["inbounds"][0]["listen_port"],
            2080
        );
        assert!(engine.rpc.is_none());
        assert_eq!(
            engine
                .connection_configuration(&id, true)
                .await
                .unwrap_err(),
            "active_configuration_unavailable"
        );
    }
}
