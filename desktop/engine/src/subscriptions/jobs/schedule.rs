//! Queueing subscription updates: manual requests and automatic due intervals.
use super::*;

pub fn next_due(subscription: &Subscription) -> Option<u64> {
    let interval = subscription.settings.interval_minutes as u64 * 60;
    if interval == 0 {
        return None;
    }
    let last = subscription.last_update.as_ref();
    let base = last.map(|u| u.at).or(subscription.updated_at).unwrap_or(0);
    if base == 0 {
        return Some(0);
    }
    let delay = if last.is_some_and(|u| {
        matches!(
            u.status,
            Status::Error | Status::Downloading | Status::Checking
        )
    }) {
        interval.min(300)
    } else {
        interval
    };
    Some(base.saturating_add(delay))
}

impl Engine {
    pub(crate) fn enqueue_updates(
        &mut self,
        ids: Vec<String>,
        scheduled: bool,
        at: u64,
    ) -> Result<usize, String> {
        let groups = ids
            .iter()
            .map(|id| self.group(id))
            .collect::<Result<Vec<_>, _>>()?;
        if groups.iter().any(|g| g.subscription.is_none()) {
            return Err("subscription_missing".into());
        }
        let mut seen = HashSet::new();
        let groups: Vec<_> = groups
            .into_iter()
            .filter(|g| {
                seen.insert(g.id.clone())
                    && !self
                        .subscription_jobs
                        .jobs
                        .iter()
                        .any(|j| j.group_id == g.id && j.status.active())
            })
            .collect();
        let active = self
            .subscription_jobs
            .jobs
            .iter()
            .filter(|j| j.status.active())
            .count();
        if active + groups.len() > MAX_JOBS {
            return Err("subscription_queue_full".into());
        }
        let batch = uuid::Uuid::new_v4().to_string();
        let count = groups.len();
        let remove = self
            .subscription_jobs
            .jobs
            .len()
            .saturating_add(count)
            .saturating_sub(MAX_JOBS);
        let mut removed = 0;
        self.subscription_jobs.jobs.retain(|j| {
            if removed < remove && !j.status.active() {
                removed += 1;
                false
            } else {
                true
            }
        });
        for group in groups {
            self.subscription_jobs.jobs.push(Job {
                id: uuid::Uuid::new_v4().to_string(),
                batch_id: batch.clone(),
                group_id: group.id.clone(),
                group_name: group.name.clone(),
                scheduled,
                status: Status::Queued,
                checked: 0,
                total: 0,
                created_at: at,
                finished_at: None,
                error: None,
                counts: Counts::default(),
                owner: None,
                touched: Instant::now(),
                ticket: None,
                source: source(&group),
                validation: vec![],
                routing_failed: false,
            });
        }
        Ok(count)
    }
    pub fn enqueue_subscription_updates(&mut self) -> Result<usize, String> {
        let ids = self
            .store
            .library
            .groups
            .iter()
            .filter(|g| g.subscription.is_some())
            .map(|g| g.id.clone())
            .collect();
        self.enqueue_updates(ids, false, now())
    }
    /// A first import survives app shutdown before a worker claims its job.
    pub fn enqueue_subscription_update(&mut self, id: &str) -> Result<usize, String> {
        let previous = self.subscription_jobs.jobs.clone();
        let count = self.enqueue_updates(vec![id.into()], false, now())?;
        if count > 0 {
            let mut next = self.store.library.clone();
            let subscription = next
                .groups
                .iter_mut()
                .find(|g| g.id == id)
                .unwrap()
                .subscription
                .as_mut()
                .unwrap();
            subscription.last_update = Some(LastUpdate {
                at: now(),
                status: Status::Queued,
                error: None,
                counts: Counts::default(),
            });
            if self.store.commit(next).is_err() {
                self.subscription_jobs.jobs = previous;
                return Err("subscription_storage_error".into());
            }
        }
        Ok(count)
    }
    pub fn queue_due_subscriptions(&mut self) {
        self.queue_due_subscriptions_at(now());
    }
    pub(crate) fn queue_due_subscriptions_at(&mut self, at: u64) {
        let imports = self
            .store
            .library
            .groups
            .iter()
            .filter(|g| {
                g.subscription.as_ref().is_some_and(|s| {
                    s.updated_at.is_none()
                        && s.last_update.as_ref().is_some_and(|u| {
                            u.status.active()
                                || (u.status == Status::Error
                                    && u.error.as_deref()
                                        == Some("subscription_worker_interrupted"))
                        })
                }) && !self.subscription_jobs.jobs.iter().any(|j| {
                    j.group_id == g.id
                        && j.error.as_deref() == Some("subscription_storage_error")
                        && j.finished_at
                            .is_some_and(|time| time.saturating_add(300) > at)
                })
            })
            .map(|g| g.id.clone())
            .collect();
        let _ = self.enqueue_updates(imports, false, at);
        let expired: Vec<_> = self
            .subscription_jobs
            .jobs
            .iter()
            .filter(|j| j.status.active() && j.owner.is_some() && j.touched.elapsed() > LEASE)
            .map(|j| j.id.clone())
            .collect();
        for id in expired {
            let _ = self.finish_subscription_job(
                &id,
                Status::Error,
                Some("subscription_worker_interrupted".into()),
            );
        }
        self.subscription_jobs
            .manual
            .retain(|_, (_, started)| started.elapsed() < Duration::from_secs(45));
        self.subscription_tickets.retain(|_, t| !t.expired());
        let ids = self
            .store
            .library
            .groups
            .iter()
            .filter(|g| {
                g.subscription
                    .as_ref()
                    .and_then(next_due)
                    .is_some_and(|due| due <= at)
                    && !self.subscription_jobs.jobs.iter().any(|j| {
                        j.group_id == g.id
                            && j.error.as_deref() == Some("subscription_storage_error")
                            && j.finished_at
                                .is_some_and(|time| time.saturating_add(300) > at)
                    })
            })
            .map(|g| g.id.clone())
            .collect();
        let _ = self.enqueue_updates(ids, true, at);
    }
}
