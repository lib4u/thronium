use crate::proto::{ConnectionMetaData, QueryConnectionsResp};
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Qt's `direct` stats tag: egress the connection did not send through a
/// server. Its bytes are counted apart from the profile that was running.
pub const DIRECT_OUTBOUND: &str = "direct";
/// Qt's `kSpeedSampleMinMs`: below it the previous rate and baseline are kept,
/// so a fast poll cannot turn a rounding remainder into a rate.
const MIN_SAMPLE: Duration = Duration::from_millis(500);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: String,
    pub created_at: i64,
    pub upload: i64,
    pub download: i64,
    /// Bytes per second over the last sampling window, as Qt's list shows them.
    pub upload_speed: i64,
    pub download_speed: i64,
    pub outbound: String,
    pub network: String,
    pub destination: String,
    pub protocol: String,
    pub domain: String,
    pub process: String,
    pub chain: Vec<String>,
    pub source: String,
}

impl From<&ConnectionMetaData> for Connection {
    fn from(c: &ConnectionMetaData) -> Self {
        Self {
            id: c.id.clone().unwrap_or_default(),
            created_at: c.created_at.unwrap_or_default(),
            upload: c.upload.unwrap_or_default(),
            download: c.download.unwrap_or_default(),
            upload_speed: 0,
            download_speed: 0,
            outbound: c.outbound.clone().unwrap_or_default(),
            network: c.network.clone().unwrap_or_default(),
            destination: c.dest.clone().unwrap_or_default(),
            protocol: c.protocol.clone().unwrap_or_default(),
            domain: c.domain.clone().unwrap_or_default(),
            process: c.process.clone().unwrap_or_default(),
            chain: c.chain.clone(),
            source: c.source.clone().unwrap_or_default(),
        }
    }
}

pub struct Delta {
    pub process: String,
    pub upload: i64,
    pub download: i64,
    /// The bytes left the machine without a server, as Qt's `direct` tag.
    pub direct: bool,
}

#[derive(Clone, Copy)]
struct Sample {
    upload: i64,
    download: i64,
    at: Instant,
    upload_speed: i64,
    download_speed: i64,
}

#[derive(Default)]
pub struct Traffic {
    seen: HashMap<String, (i64, i64)>,
    samples: HashMap<String, Sample>,
    pub upload: i64,
    pub download: i64,
    pub active: Vec<Connection>,
}

impl Traffic {
    pub fn update(&mut self, response: QueryConnectionsResp) -> Vec<Delta> {
        self.update_at(response, Instant::now())
    }
    pub(crate) fn update_at(&mut self, response: QueryConnectionsResp, now: Instant) -> Vec<Delta> {
        let mut deltas = Vec::new();
        let mut next = HashMap::new();
        // A connection may close between the core's active and closed snapshots.
        // Merge its counters once. The closed ring is re-reported, not drained.
        for c in response.active.iter().chain(&response.closed) {
            if let Some(id) = c.id.as_ref().filter(|id| !id.is_empty()) {
                let counts = next.entry(id.clone()).or_insert((0, 0));
                counts.0 = counts.0.max(c.upload.unwrap_or_default());
                counts.1 = counts.1.max(c.download.unwrap_or_default());
            }
        }
        for (id, (up, down)) in &next {
            let (old_up, old_down) = self.seen.get(id).copied().unwrap_or_default();
            let meta = response
                .active
                .iter()
                .chain(&response.closed)
                .find(|c| c.id.as_ref() == Some(id));
            deltas.push(Delta {
                process: meta
                    .and_then(|c| c.process.as_ref())
                    .cloned()
                    .unwrap_or_default(),
                upload: (up - old_up).max(0),
                download: (down - old_down).max(0),
                direct: meta.is_some_and(|c| c.outbound.as_deref() == Some(DIRECT_OUTBOUND)),
            });
            self.upload = self.upload.saturating_add((up - old_up).max(0));
            self.download = self.download.saturating_add((down - old_down).max(0));
        }
        self.seen = next;
        self.active = response.active.iter().map(Connection::from).collect();
        // Closed connections leave the map with their samples, as in Qt.
        let mut samples = HashMap::with_capacity(self.active.len());
        for connection in &mut self.active {
            let sample = match self.samples.get(&connection.id) {
                // The first sighting seeds a baseline and shows no rate yet.
                None => Sample {
                    upload: connection.upload,
                    download: connection.download,
                    at: now,
                    upload_speed: 0,
                    download_speed: 0,
                },
                Some(previous) => {
                    let elapsed = now.saturating_duration_since(previous.at);
                    if elapsed < MIN_SAMPLE {
                        *previous
                    } else {
                        let millis = elapsed.as_millis().max(1) as i64;
                        let rate = |current: i64, before: i64| {
                            (current - before).max(0).saturating_mul(1000) / millis
                        };
                        Sample {
                            upload: connection.upload,
                            download: connection.download,
                            at: now,
                            upload_speed: rate(connection.upload, previous.upload),
                            download_speed: rate(connection.download, previous.download),
                        }
                    }
                }
            };
            connection.upload_speed = sample.upload_speed;
            connection.download_speed = sample.download_speed;
            samples.insert(connection.id.clone(), sample);
        }
        self.samples = samples;
        self.active
            .sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        deltas
    }

    pub fn stopped(&mut self) {
        self.active.clear();
        self.seen.clear();
        self.samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn conn(id: &str, up: i64, down: i64) -> ConnectionMetaData {
        ConnectionMetaData {
            id: Some(id.into()),
            upload: Some(up),
            download: Some(down),
            ..Default::default()
        }
    }

    #[test]
    fn live_closed_and_repeated_ring_do_not_double_count() {
        let mut traffic = Traffic::default();
        traffic.update(QueryConnectionsResp {
            active: vec![conn("a", 10, 30)],
            closed: vec![],
        });
        traffic.update(QueryConnectionsResp {
            active: vec![conn("a", 20, 40)],
            closed: vec![conn("a", 25, 50), conn("b", 5, 15)],
        });
        assert_eq!((traffic.upload, traffic.download), (30, 65));
        traffic.update(QueryConnectionsResp {
            active: vec![],
            closed: vec![conn("a", 25, 50), conn("b", 5, 15)],
        });
        assert_eq!((traffic.upload, traffic.download), (30, 65));
        traffic.update(QueryConnectionsResp::default());
        assert_eq!((traffic.upload, traffic.download), (30, 65));
        assert!(traffic.seen.is_empty());
    }

    #[test]
    fn direct_egress_is_reported_apart_from_what_a_server_carried() {
        let tagged = |id: &str, outbound: &str| ConnectionMetaData {
            outbound: Some(outbound.into()),
            ..conn(id, 7, 11)
        };
        let mut traffic = Traffic::default();
        let deltas = traffic.update(QueryConnectionsResp {
            active: vec![tagged("a", DIRECT_OUTBOUND), tagged("b", "proxy")],
            closed: vec![],
        });
        let direct: Vec<_> = deltas.iter().filter(|d| d.direct).collect();
        assert_eq!(direct.len(), 1);
        assert_eq!((direct[0].upload, direct[0].download), (7, 11));
        assert_eq!(deltas.iter().filter(|d| !d.direct).count(), 1);
    }

    #[test]
    fn a_rate_needs_a_window_and_never_survives_its_connection() {
        let start = Instant::now();
        let mut traffic = Traffic::default();
        traffic.update_at(
            QueryConnectionsResp {
                active: vec![conn("a", 1000, 2000)],
                closed: vec![],
            },
            start,
        );
        // The first sighting is only a baseline.
        assert_eq!(traffic.active[0].download_speed, 0);
        // Too soon: the previous rate and baseline are kept instead of a
        // remainder divided by a few milliseconds.
        traffic.update_at(
            QueryConnectionsResp {
                active: vec![conn("a", 1100, 2200)],
                closed: vec![],
            },
            start + Duration::from_millis(100),
        );
        assert_eq!(traffic.active[0].upload_speed, 0);
        traffic.update_at(
            QueryConnectionsResp {
                active: vec![conn("a", 3000, 6000)],
                closed: vec![],
            },
            start + Duration::from_millis(2000),
        );
        assert_eq!(
            (
                traffic.active[0].upload_speed,
                traffic.active[0].download_speed
            ),
            (1000, 2000)
        );
        // A closed connection takes its sample with it, so a reused id starts over.
        traffic.update_at(
            QueryConnectionsResp::default(),
            start + Duration::from_secs(3),
        );
        assert!(traffic.samples.is_empty());
    }
}
