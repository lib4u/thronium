//! The update worker protocol: claiming, renewing, checking, applying and releasing jobs.
use super::*;

impl Engine {
    /// The worker is making progress: renew its lease and keep the downloaded
    /// subscription it validates from expiring.
    pub(crate) fn keep_job_alive(&mut self, i: usize) {
        let job = &mut self.subscription_jobs.jobs[i];
        job.touched = Instant::now();
        if let Some(ticket) = job
            .ticket
            .as_ref()
            .and_then(|token| self.subscription_tickets.get_mut(token))
        {
            ticket.touch();
        }
    }
    /// Called by the host while one validation runs longer than the lease: a
    /// check may download lists and start the Core.
    pub fn renew_subscription_job(&mut self, id: &str, owner: &str) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        self.keep_job_alive(i);
        Ok(())
    }
    pub(crate) fn job_index(&self, id: &str, owner: &str) -> Result<usize, String> {
        self.subscription_jobs
            .jobs
            .iter()
            .position(|j| {
                j.id == id
                    && j.owner.as_deref() == Some(owner)
                    && j.status.active()
                    && j.touched.elapsed() <= LEASE
            })
            .ok_or("subscription_job_cancelled".into())
    }
    pub fn claim_subscription_job(&mut self, owner: &str) -> Result<Value, String> {
        if uuid::Uuid::parse_str(owner).is_err() {
            return Err("invalid_download_id".into());
        }
        self.queue_due_subscriptions();
        if self
            .subscription_jobs
            .jobs
            .iter()
            .any(|j| j.status.active() && j.owner.is_some())
        {
            return Ok(Value::Null);
        }
        let queued: Vec<_> = self
            .subscription_jobs
            .jobs
            .iter()
            .filter(|j| j.status == Status::Queued)
            .map(|j| j.id.clone())
            .collect();
        for id in queued {
            let i = self
                .subscription_jobs
                .jobs
                .iter()
                .position(|j| j.id == id)
                .unwrap();
            let job = &self.subscription_jobs.jobs[i];
            let group_id = job.group_id.clone();
            let group = match self.group(&group_id) {
                Ok(g) if g.subscription.is_some() => g,
                _ => {
                    self.finish_subscription_job(
                        &id,
                        Status::Cancelled,
                        Some("group_not_found".into()),
                    )?;
                    continue;
                }
            };
            if source(&group) != job.source
                || (job.scheduled
                    && !group
                        .subscription
                        .as_ref()
                        .and_then(next_due)
                        .is_some_and(|due| due <= now()))
            {
                self.finish_subscription_job(
                    &id,
                    Status::Cancelled,
                    Some("subscription_changed".into()),
                )?;
                continue;
            }
            // A manual request or reviewed preview takes precedence over background work.
            if self.subscription_jobs.manual.contains_key(&group_id)
                || self
                    .subscription_tickets
                    .values()
                    .any(|t| t.group_id == group_id)
            {
                continue;
            }
            let attempt = LastUpdate {
                at: now(),
                status: Status::Downloading,
                error: None,
                counts: Counts::default(),
            };
            let mut next = self.store.library.clone();
            next.groups
                .iter_mut()
                .find(|g| g.id == group_id)
                .unwrap()
                .subscription
                .as_mut()
                .unwrap()
                .last_update = Some(attempt);
            if self.store.commit(next).is_err() {
                let job = &mut self.subscription_jobs.jobs[i];
                job.status = Status::Error;
                job.error = Some("subscription_storage_error".into());
                job.finished_at = Some(now());
                continue;
            }
            let job = &mut self.subscription_jobs.jobs[i];
            job.status = Status::Downloading;
            job.owner = Some(owner.into());
            job.touched = Instant::now();
            return Ok(json!({"id":id,"groupId":group_id}));
        }
        Ok(Value::Null)
    }
    pub fn begin_manual_subscription(
        &mut self,
        group: &str,
        request_id: &str,
    ) -> Result<Request, String> {
        if self
            .subscription_jobs
            .jobs
            .iter()
            .any(|j| j.group_id == group && j.status.active() && j.owner.is_some())
            || self.subscription_jobs.manual.contains_key(group)
        {
            return Err("subscription_group_busy".into());
        }
        let request = self.subscription_request(group)?;
        self.subscription_jobs
            .manual
            .insert(group.into(), (request_id.into(), Instant::now()));
        Ok(request)
    }
    pub fn end_manual_subscription(&mut self, group: &str, request_id: &str) {
        if self
            .subscription_jobs
            .manual
            .get(group)
            .is_some_and(|(id, _)| id == request_id)
        {
            self.subscription_jobs.manual.remove(group);
        }
    }
    pub fn subscription_job_request(&mut self, id: &str, owner: &str) -> Result<Request, String> {
        let i = self.job_index(id, owner)?;
        if self.subscription_jobs.jobs[i].status != Status::Downloading {
            return Err("subscription_job_state".into());
        }
        let request = self.subscription_request(&self.subscription_jobs.jobs[i].group_id)?;
        self.subscription_jobs.jobs[i].touched = Instant::now();
        Ok(request)
    }
    pub fn subscription_job_downloaded(
        &mut self,
        id: &str,
        owner: &str,
        request: Request,
        result: Download,
    ) -> Result<Value, String> {
        let i = self.job_index(id, owner)?;
        let value = self.subscription_downloaded(request, result)?;
        self.subscription_jobs.jobs[i].ticket = value["ticket"].as_str().map(str::to_owned);
        self.subscription_jobs.jobs[i].touched = Instant::now();
        Ok(value)
    }
    pub fn prepare_subscription_job(
        &mut self,
        id: &str,
        owner: &str,
        drafts: Vec<ProfileDraft>,
        omitted: Omitted,
    ) -> Result<usize, String> {
        let i = self.job_index(id, owner)?;
        if self.subscription_jobs.jobs[i].status != Status::Downloading {
            return Err("subscription_job_state".into());
        }
        let token = self.subscription_jobs.jobs[i]
            .ticket
            .clone()
            .ok_or("subscription_preview_required")?;
        let changes = self.preview_subscription(&token, drafts)?;
        if let Some(ticket) = self.subscription_tickets.get_mut(&token) {
            ticket.omitted = omitted;
        }
        let job = &mut self.subscription_jobs.jobs[i];
        job.validation = changes
            .iter()
            .filter(|c| matches!(c.action.as_str(), "added" | "updated"))
            .map(|c| c.id.clone())
            .collect();
        job.total = job.validation.len();
        job.checked = 0;
        job.counts = Counts::of(&changes);
        job.counts.skipped = omitted.skipped;
        job.counts.warned = omitted.warned;
        job.status = Status::Checking;
        job.touched = Instant::now();
        Ok(job.total)
    }
    pub fn subscription_job_check_request(
        &mut self,
        id: &str,
        owner: &str,
    ) -> Result<ValidationRequest, String> {
        let i = self.job_index(id, owner)?;
        let job = &self.subscription_jobs.jobs[i];
        if job.status != Status::Checking || job.checked >= job.total {
            return Err("subscription_job_state".into());
        }
        let token = job.ticket.as_ref().ok_or("subscription_expired")?;
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.stamp != self.subscription_stamp(&job.group_id)? {
            return Err("subscription_changed".into());
        }
        let profile = ticket
            .plan
            .as_ref()
            .and_then(|p| {
                p.profiles
                    .iter()
                    .find(|p| p.id == job.validation[job.checked])
            })
            .cloned()
            .ok_or("subscription_invalid_profiles")?;
        let mut library = self.store.library.clone();
        let group = library
            .groups
            .iter_mut()
            .find(|g| g.id == ticket.group_id)
            .ok_or("group_not_found")?;
        group
            .subscription
            .as_mut()
            .ok_or("subscription_missing")?
            .metadata = ticket.metadata.clone();
        let proxy = self.settings_download_proxy()?;
        self.keep_job_alive(i);
        let job = &self.subscription_jobs.jobs[i];
        Ok(ValidationRequest {
            core: self.core.clone(),
            directory: self.data_dir.clone(),
            proxy,
            profile,
            library,
            checked: job.checked,
            last: job.checked + 1 == job.total,
        })
    }
    pub fn subscription_job_checked(
        &mut self,
        id: &str,
        owner: &str,
        checked: usize,
    ) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        let job = &mut self.subscription_jobs.jobs[i];
        if job.status != Status::Checking || job.checked != checked || checked >= job.total {
            return Err("subscription_job_state".into());
        }
        job.checked += 1;
        self.keep_job_alive(i);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) async fn check_subscription_job(
        &mut self,
        id: &str,
        owner: &str,
    ) -> Result<(), String> {
        let request = self.subscription_job_check_request(id, owner)?;
        let checked = request.checked;
        Validator::default().check(id, request).await?;
        self.subscription_job_checked(id, owner, checked)
    }
    pub async fn apply_subscription_job_with_stop(
        &mut self,
        id: &str,
        owner: &str,
    ) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        let job = &self.subscription_jobs.jobs[i];
        if job.status != Status::Checking || job.checked != job.total {
            return Err("subscription_validation_required".into());
        }
        let token = job.ticket.clone().ok_or("subscription_expired")?;
        let previous = self.stop_for_subscription(&token).await?;
        match self.apply_subscription_job(id, owner) {
            Ok(()) => Ok(()),
            Err(error) => {
                if previous.is_some() {
                    Err(self.recover_connection(previous, error).await)
                } else {
                    Err(error)
                }
            }
        }
    }
    pub fn apply_subscription_job(&mut self, id: &str, owner: &str) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        let job = &self.subscription_jobs.jobs[i];
        if job.status != Status::Checking || job.checked != job.total {
            return Err("subscription_validation_required".into());
        }
        let token = job.ticket.clone().ok_or("subscription_expired")?;
        let omitted = Omitted {
            skipped: self.subscription_jobs.jobs[i].counts.skipped,
            warned: self.subscription_jobs.jobs[i].counts.warned,
        };
        let changes = self.apply_subscription(&token)?;
        let outcome = LastUpdate::of(&changes, omitted);
        let job = &mut self.subscription_jobs.jobs[i];
        job.status = outcome.status;
        job.counts = outcome.counts;
        job.finished_at = Some(now());
        job.ticket = None;
        job.owner = None;
        job.source = Value::Null;
        job.validation.clear();
        Ok(())
    }
    pub(crate) fn finish_subscription_job(
        &mut self,
        id: &str,
        status: Status,
        error: Option<String>,
    ) -> Result<(), String> {
        let Some(i) = self
            .subscription_jobs
            .jobs
            .iter()
            .position(|j| j.id == id && j.status.active())
        else {
            return Ok(());
        };
        let job = &mut self.subscription_jobs.jobs[i];
        job.status = status;
        job.error = error.clone();
        job.finished_at = Some(now());
        job.owner = None;
        if let Some(token) = job.ticket.take() {
            self.subscription_tickets.remove(&token);
        }
        let mut next = self.store.library.clone();
        if let Some(group) = next.groups.iter_mut().find(|g| g.id == job.group_id) {
            if source(group) == job.source {
                if let Some(subscription) = &mut group.subscription {
                    subscription.last_update = Some(LastUpdate {
                        at: now(),
                        status,
                        error,
                        counts: job.counts.clone(),
                    });
                    self.store.commit(next)?;
                }
            }
        }
        job.source = Value::Null;
        job.validation.clear();
        Ok(())
    }
    pub fn fail_subscription_job(
        &mut self,
        id: &str,
        owner: &str,
        error: &str,
    ) -> Result<(), String> {
        self.job_index(id, owner)?;
        // Only registered codes reach snapshots; parser errors and provider bodies may contain secrets.
        let code = if crate::ipc::registered(error).is_some()
            || error
                .strip_prefix("subscription_http_")
                .is_some_and(|c| c.len() == 3 && c.bytes().all(|v| v.is_ascii_digit()))
        {
            error
        } else {
            "subscription_update_failed"
        };
        self.finish_subscription_job(
            id,
            if code == "subscription_untransferred_parameters" {
                Status::NeedsReview
            } else {
                Status::Error
            },
            Some(code.into()),
        )
    }
    pub fn cancel_subscription_jobs(&mut self) -> Result<Vec<String>, String> {
        let ids: Vec<_> = self
            .subscription_jobs
            .jobs
            .iter()
            .filter(|j| j.status.active())
            .map(|j| j.id.clone())
            .collect();
        for id in &ids {
            self.finish_subscription_job(id, Status::Cancelled, None)?;
        }
        Ok(ids)
    }
    pub fn release_subscription_worker(&mut self, owner: &str) -> Result<Vec<String>, String> {
        let ids: Vec<_> = self
            .subscription_jobs
            .jobs
            .iter()
            .filter(|j| j.owner.as_deref() == Some(owner) && j.status.active())
            .map(|j| j.id.clone())
            .collect();
        for id in &ids {
            self.finish_subscription_job(
                id,
                Status::Error,
                Some("subscription_worker_interrupted".into()),
            )?;
        }
        Ok(ids)
    }
    pub fn clear_subscription_jobs(&mut self) {
        self.subscription_jobs.jobs.retain(|j| j.status.active());
    }
}
