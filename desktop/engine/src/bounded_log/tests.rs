use super::*;

#[derive(Serialize, Deserialize)]
struct Entry {
    id: u64,
    at: u64,
}
impl LogEntry for Entry {
    fn id(&self) -> u64 {
        self.id
    }
    fn at(&self) -> u64 {
        self.at
    }
    fn stamp(&mut self, id: u64, at: u64) {
        self.id = id;
        self.at = at;
    }
    fn valid(&self, now: u64) -> bool {
        self.at <= now && self.id > 0
    }
}
struct Spec;
impl LogSpec for Spec {
    type Entry = Entry;
    const FILE: &'static str = "history.json";
    const WRITE_ERROR: &'static str = "history_write_failed";
    const MAX_ENTRIES: usize = 500;
    const MAX_BYTES: u64 = 256 * 1024;
    const RETENTION_SECS: u64 = 7 * 86400;
}

#[test]
fn failed_clear_preserves_memory_disk_and_next_id() {
    let directory = tempfile::tempdir().unwrap();
    let mut log = BoundedLog::<Spec>::default();
    log.record(Entry { id: 0, at: 0 });
    log.save(directory.path()).unwrap();
    let previous = log.view();
    let disk = std::fs::read(directory.path().join(Spec::FILE)).unwrap();
    assert_eq!(
        log.clear_and_save(&directory.path().join("missing"))
            .unwrap_err(),
        Spec::WRITE_ERROR
    );
    assert_eq!(log.view(), previous);
    assert_eq!(BoundedLog::<Spec>::load(directory.path()).view(), previous);
    assert_eq!(
        std::fs::read(directory.path().join(Spec::FILE)).unwrap(),
        disk
    );
    log.clear_and_save(directory.path()).unwrap();
    assert_eq!(log.view()["total"], 0);
    assert_eq!(
        BoundedLog::<Spec>::load(directory.path()).view()["total"],
        0
    );
    assert_eq!(log.record(Entry { id: 0, at: 0 }), 2);
}

#[test]
fn read_excludes_expired_entries_without_waiting_for_a_new_record() {
    let mut log = BoundedLog::<Spec>::default();
    log.record(Entry { id: 0, at: 0 });
    log.record(Entry { id: 0, at: 0 });
    log.entries[0].at = now() - Spec::RETENTION_SECS - 10;
    assert_eq!(log.view()["total"], 1);
    assert_eq!(log.view()["entries"][0]["id"], 2);
}
