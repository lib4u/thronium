//! Editor revisions cover editable profile data, independently of library telemetry.
use crate::{store::Profile, vless, Engine, ProfileDraft};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditableProfile {
    #[serde(flatten)]
    pub profile: Profile,
    pub expected_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vless_core: Option<vless::Core>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditRequest {
    #[serde(flatten)]
    pub draft: ProfileDraft,
    pub expected_revision: Option<String>,
}

impl Engine {
    pub(crate) fn profile_edit_revision(&self, profile: &Profile) -> String {
        let preferences = &self.store.library.preferences;
        let editable = json!({
            "id": profile.id, "name": profile.name, "groupId": profile.group_id,
            "kind": profile.kind, "config": profile.config, "vpnPolicy": profile.vpn_policy,
            "vlessCore": preferences.vless_overrides.get(&profile.id),
            "inheritedCore": if vless::is_vless(profile) { Some(preferences.vless_core) } else { None },
        });
        format!("{:x}", Sha256::digest(editable.to_string().as_bytes()))
    }

    pub fn editable_profile(&self, id: &str) -> Result<EditableProfile, String> {
        let profile = self.profile(id)?;
        Ok(EditableProfile {
            expected_revision: self.profile_edit_revision(&profile),
            vless_core: self
                .store
                .library
                .preferences
                .vless_overrides
                .get(id)
                .copied(),
            profile,
        })
    }

    fn check_profile_edit(&self, id: &str, expected: Option<&str>) -> Result<Profile, String> {
        let profile = self.profile(id)?;
        if expected != Some(self.profile_edit_revision(&profile).as_str()) {
            return Err("profile_configuration_changed".into());
        }
        Ok(profile)
    }

    /// Compare and commit under the same exclusive Engine owner. Creation has no baseline.
    pub fn save_profile_edit(
        &mut self,
        request: EditRequest,
        choice: Option<Option<vless::Core>>,
    ) -> Result<String, String> {
        if let Some(id) = request.draft.id.as_deref() {
            self.check_profile_edit(id, request.expected_revision.as_deref())?;
        }
        self.save_profile_choice(request.draft, choice)
    }

    pub fn save_profile_configuration(
        &mut self,
        id: &str,
        expected: &str,
        config: Value,
    ) -> Result<String, String> {
        let previous = self.check_profile_edit(id, Some(expected))?;
        self.save_profile(ProfileDraft {
            id: Some(previous.id),
            name: previous.name,
            group_id: previous.group_id,
            kind: previous.kind,
            vpn_policy: Default::default(),
            config,
        })
    }

    /// Return the new baseline atomically so a core-only edit preserves unsaved JSON.
    pub fn save_profile_core(
        &mut self,
        id: &str,
        expected: &str,
        core: Option<vless::Core>,
    ) -> Result<EditableProfile, String> {
        self.check_profile_edit(id, Some(expected))?;
        self.vless_core(id, core)?;
        self.editable_profile(id)
    }
}
