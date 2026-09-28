//! Reading, answering and cancelling VPN authentication challenges.
use super::*;

pub(crate) fn unexpired(challenge: &proto::VpnChallenge, at: i64) -> Result<(), String> {
    if challenge
        .deadline
        .is_some_and(|deadline| deadline > 0 && deadline <= at)
    {
        Err("vpn_auth_expired".into())
    } else {
        Ok(())
    }
}

impl Engine {
    pub(crate) async fn current_vpn_challenge(
        &mut self,
        request: &ChallengeRequest,
    ) -> Result<(proto::VpnChallenge, String, Option<u64>), String> {
        let is_managed = self.rpc.as_ref().is_some_and(|rpc| rpc.managed());
        if !validate::identity(&request.session_id)
            || !validate::identity(&request.endpoint_tag)
            || !validate::identity(&request.challenge_id)
            || self.vpn.status.session_id.as_deref() != Some(&request.session_id)
            || !self.vpn_live()
        {
            return Err("vpn_auth_stale".into());
        }
        if is_managed && self.vpn.managed_version != 1 {
            return Err("vpn_auth_managed_unsupported".into());
        }
        let generation = if is_managed {
            Some(self.vpn.generation.ok_or("vpn_auth_stale")?)
        } else {
            None
        };
        let response = self.query_vpn().await?;
        let status = response
            .results
            .into_iter()
            .find(|e| e.tag.as_deref() == Some(&request.endpoint_tag))
            .ok_or("vpn_auth_stale")?;
        let challenge = status
            .challenge
            .filter(|c| {
                c.id.as_deref() == Some(&request.challenge_id)
                    && c.endpoint_tag.as_deref() == Some(&request.endpoint_tag)
            })
            .ok_or("vpn_auth_stale")?;
        let protocol = self
            .vpn
            .status
            .endpoints
            .iter()
            .find(|e| e.tag == request.endpoint_tag)
            .ok_or("vpn_auth_stale")?
            .protocol
            .clone();
        unexpired(&challenge, now())?;
        Ok((challenge, protocol, generation))
    }
    pub async fn vpn_challenge(&mut self, request: ChallengeRequest) -> Result<Challenge, String> {
        let (challenge, protocol, _) = self.current_vpn_challenge(&request).await?;
        validate::details(&challenge, &protocol)?;
        Ok(Challenge {
            session_id: request.session_id,
            endpoint_tag: request.endpoint_tag,
            challenge_id: request.challenge_id,
            kind: challenge.kind.unwrap_or_default(),
            username: challenge.username.unwrap_or_default(),
            message: challenge.message.unwrap_or_default(),
            banner: challenge.banner.unwrap_or_default(),
            error: challenge.error.unwrap_or_default(),
            echo: challenge.echo.unwrap_or(false),
            deadline: challenge.deadline.unwrap_or(0),
            fields: challenge
                .fields
                .into_iter()
                .map(|f| Field {
                    submission_key: f.submission_key.unwrap_or_default(),
                    name: f.name.unwrap_or_default(),
                    label: f.label.unwrap_or_default(),
                    kind: f.kind.unwrap_or_default(),
                    value: f.value.unwrap_or_default(),
                    options: f
                        .options
                        .into_iter()
                        .map(|o| Choice {
                            value: o.value.unwrap_or_default(),
                            label: o.label.unwrap_or_default(),
                        })
                        .collect(),
                })
                .collect(),
        })
    }
    pub async fn submit_vpn_challenge(&mut self, request: SubmitRequest) -> Result<(), String> {
        // Bound untrusted answer input before doing any RPC. No response is logged.
        validate::answer_size(&request)?;
        let identity = ChallengeRequest {
            session_id: request.session_id.clone(),
            endpoint_tag: request.endpoint_tag.clone(),
            challenge_id: request.challenge_id.clone(),
        };
        let (challenge, protocol, generation) = self.current_vpn_challenge(&identity).await?;
        validate::answer(&challenge, &protocol, &request)?;
        if challenge.kind.as_deref() == Some("message") {
            self.vpn
                .acknowledge(&request.endpoint_tag, &request.challenge_id);
            // Sent as Qt does; the pinned OpenVPN client refuses to complete a
            // message, which is not an error for the user.
            let _ = self
                .vpn_answer(
                    generation,
                    false,
                    proto::SubmitVpnChallengeRequest {
                        endpoint_tag: Some(request.endpoint_tag),
                        challenge_id: Some(request.challenge_id),
                        ..Default::default()
                    },
                )
                .await;
            return Ok(());
        }
        self.otp_manual_answer(&request.endpoint_tag, &request.challenge_id, false);
        self.vpn_answer(
            generation,
            false,
            proto::SubmitVpnChallengeRequest {
                endpoint_tag: Some(request.endpoint_tag),
                challenge_id: Some(request.challenge_id),
                username: Some(request.username),
                password: Some(request.password),
                secret: Some(request.secret),
                form_values: request.form_values.into_iter().collect(),
            },
        )
        .await
    }
    pub async fn cancel_vpn_challenge(&mut self, request: ChallengeRequest) -> Result<(), String> {
        // Unsupported fields do not prevent cancellation of the verified ID.
        let (_, _, generation) = self.current_vpn_challenge(&request).await?;
        self.otp_manual_answer(&request.endpoint_tag, &request.challenge_id, true);
        self.vpn_answer(
            generation,
            true,
            proto::SubmitVpnChallengeRequest {
                endpoint_tag: Some(request.endpoint_tag),
                challenge_id: Some(request.challenge_id),
                ..Default::default()
            },
        )
        .await
    }
    pub(crate) async fn vpn_answer(
        &mut self,
        generation: Option<u64>,
        cancel: bool,
        request: proto::SubmitVpnChallengeRequest,
    ) -> Result<(), String> {
        let rpc = self.rpc.as_mut().ok_or("vpn_auth_stale")?;
        let result = if let Some(generation) = generation {
            managed::action(rpc, generation, cancel, request).await
        } else {
            rpc.call::<_, proto::ErrorResp>(
                if cancel {
                    "CancelVPNChallenge"
                } else {
                    "SubmitVPNChallenge"
                },
                request,
            )
            .await
        };
        match &result {
            Err(error) if error == "vpn_auth_stale" => {
                self.vpn_stale_generation();
                return Err(error.clone());
            }
            Err(error) if error == "vpn_auth_managed_unsupported" => {
                self.vpn.managed_unsupported();
                return Err(error.clone());
            }
            _ => {}
        }
        let _ = self.query_vpn().await;
        match result {
            Ok(reply) if reply.error.as_deref().unwrap_or("").is_empty() => Ok(()),
            _ => Err(if cancel {
                "vpn_auth_cancel_failed"
            } else {
                "vpn_auth_submit_failed"
            }
            .into()),
        }
    }
    pub async fn vpn_challenge_url(&mut self, request: ChallengeRequest) -> Result<String, String> {
        let (challenge, protocol, _) = self.current_vpn_challenge(&request).await?;
        validate::details(&challenge, &protocol)?;
        if protocol != "openvpn" || challenge.kind.as_deref() != Some("open-url") {
            return Err("vpn_auth_unsupported".into());
        }
        validate::url(challenge.url.as_deref().unwrap_or(""))
    }
}
