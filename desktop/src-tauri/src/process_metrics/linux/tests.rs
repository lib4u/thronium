use super::*;
use std::time::Duration;
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};

const SYS: System = System {
    hz: 100,
    page: 4096,
    cpus: 4,
};
#[derive(Default)]
struct Fake {
    stats: RefCell<BTreeMap<u32, VecDeque<Result<Stat, u16>>>>,
    descendants: RefCell<BTreeMap<u32, Result<Vec<u32>, u16>>>,
    reads: RefCell<Vec<u32>>,
}
impl Fake {
    fn insert(&self, pid: u32, parent: u32, start: u64, ticks: u64, pages: u64, children: &[u32]) {
        self.stats.borrow_mut().insert(
            pid,
            VecDeque::from([Ok(stat(pid, parent, start, ticks, pages))]),
        );
        self.descendants
            .borrow_mut()
            .insert(pid, Ok(children.to_vec()));
    }
    fn error(&self, pid: u32, reason: u16) {
        self.stats
            .borrow_mut()
            .insert(pid, VecDeque::from([Err(reason)]));
    }
    fn ticks(&self, pid: u32, ticks: u64) {
        self.stats
            .borrow_mut()
            .get_mut(&pid)
            .unwrap()
            .front_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .ticks = ticks;
    }
}
impl ProcSource for Fake {
    fn stat(&self, pid: u32, budget: &mut Budget) -> Result<Stat, u16> {
        budget.available()?;
        self.reads.borrow_mut().push(pid);
        let mut stats = self.stats.borrow_mut();
        let sequence = stats.get_mut(&pid).ok_or(5u16)?;
        if sequence.len() > 1 {
            sequence.pop_front().unwrap()
        } else {
            sequence.front().cloned().unwrap_or(Err(5))
        }
    }
    fn children(&self, pid: u32, budget: &mut Budget) -> Result<Vec<u32>, u16> {
        budget.available()?;
        self.descendants
            .borrow()
            .get(&pid)
            .cloned()
            .unwrap_or(Ok(Vec::new()))
    }
}
fn stat(pid: u32, parent: u32, start: u64, ticks: u64, rss_pages: u64) -> Stat {
    Stat {
        identity: Identity { pid, start },
        parent,
        ticks,
        rss_pages,
    }
}
fn record(pid: u32, name: &[u8], state: &str) -> Vec<u8> {
    let mut suffix = vec!["0".to_owned(); 22];
    suffix[0] = state.to_owned();
    suffix[1] = "42".into();
    suffix[11] = "120".into();
    suffix[12] = "30".into();
    suffix[13] = "9999999".into();
    suffix[14] = "9999999".into();
    suffix[19] = "76543".into();
    suffix[20] = "99999".into();
    suffix[21] = "12".into();
    let mut bytes = format!("{pid} (").into_bytes();
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(format!(") {} 0 0 0\n", suffix.join(" ")).as_bytes());
    bytes
}
fn singleton(ticks: u64, start: u64) -> Tree {
    let process = stat(100, 1, start, ticks, 12);
    Tree {
        entries: BTreeMap::from([(process.identity, process)]),
        root_valid: true,
        reason: None,
    }
}
fn library() -> (Fake, OwnedProcess) {
    let source = Fake::default();
    source.insert(100, 1, 10, 100, 10, &[101, 200]);
    source.insert(101, 100, 11, 50, 5, &[]);
    source.insert(200, 100, 20, 200, 20, &[201]);
    source.insert(201, 200, 21, 100, 10, &[]);
    source.insert(300, 1, 30, 999999, 999999, &[]);
    (
        source,
        OwnedProcess {
            pid: 200,
            instance: 9,
            start_time: Some(20),
        },
    )
}

#[test]
fn stat_parser_handles_real_comm_grammar_and_ignores_waited_child_cpu() {
    let parsed = parse_stat(&record(77, b"worker ) with (\n\xffname", "S"), 77).unwrap();
    assert_eq!(
        parsed.identity,
        Identity {
            pid: 77,
            start: 76543
        }
    );
    assert_eq!(parsed.parent, 42);
    assert_eq!(parsed.ticks, 150);
    assert_eq!(parsed.rss_pages, 12);
}
#[test]
fn stat_parser_rejects_malformed_signed_overflow_and_dead_processes() {
    assert_eq!(parse_stat(b"77 (x) R 1", 77).unwrap_err(), 7);
    assert_eq!(parse_stat(&record(77, b"x", "S"), 78).unwrap_err(), 7);
    for state in ["Z", "X", "x"] {
        assert_eq!(parse_stat(&record(77, b"x", state), 77).unwrap_err(), 5);
    }
    let text = String::from_utf8(record(77, b"x", "S")).unwrap();
    assert_eq!(
        parse_stat(text.replace("99999 12", "99999 -1").as_bytes(), 77).unwrap_err(),
        7
    );
    assert_eq!(
        parse_stat(
            text.replace("120 30", "18446744073709551615 30").as_bytes(),
            77
        )
        .unwrap_err(),
        7
    );
    assert_eq!(parse_stat(&record(0, b"x", "S"), 0).unwrap_err(), 7);
}
#[test]
fn rate_is_normalized_by_online_cpus_and_preserves_real_zero() {
    let now = Instant::now();
    let mut baseline = None;
    let first = usage(singleton(100, 10), &mut baseline, now, SYS, None);
    assert_eq!(first.reason, Some(1));
    assert_eq!(first.cpu_percent, None);
    let second = usage(
        singleton(300, 10),
        &mut baseline,
        now + Duration::from_secs(1),
        SYS,
        None,
    );
    assert_eq!(second.cpu_percent, Some(50.0));
    assert_eq!(second.rss_bytes, Some(12 * 4096));
    assert_eq!(second.reason, None);
    let idle = usage(
        singleton(300, 10),
        &mut baseline,
        now + Duration::from_secs(2),
        SYS,
        None,
    );
    assert_eq!(idle.cpu_percent, Some(0.0));
}
#[test]
fn rate_resets_on_gap_short_interval_counter_and_membership_changes() {
    let now = Instant::now();
    let mut baseline = None;
    usage(singleton(100, 10), &mut baseline, now, SYS, None);
    let short = usage(
        singleton(101, 10),
        &mut baseline,
        now + Duration::from_millis(50),
        SYS,
        None,
    );
    assert_eq!(short.reason, Some(12));
    assert_eq!(short.cpu_percent, None);
    let gap = usage(
        singleton(500, 10),
        &mut baseline,
        now + Duration::from_secs(5),
        SYS,
        None,
    );
    assert_eq!(gap.reason, Some(3));
    let reversed = usage(
        singleton(1, 10),
        &mut baseline,
        now + Duration::from_secs(6),
        SYS,
        None,
    );
    assert_eq!(reversed.reason, Some(11));
    let reused = usage(
        singleton(50, 20),
        &mut baseline,
        now + Duration::from_secs(7),
        SYS,
        None,
    );
    assert_eq!(reused.reason, Some(13));
    assert_eq!(reused.cpu_percent, None);
    let recovered = usage(
        singleton(150, 20),
        &mut baseline,
        now + Duration::from_secs(8),
        SYS,
        None,
    );
    assert_eq!(recovered.cpu_percent, Some(25.0));
    let cpus = usage(
        singleton(250, 20),
        &mut baseline,
        now + Duration::from_secs(9),
        System { cpus: 8, ..SYS },
        None,
    );
    assert_eq!(cpus.reason, Some(4));
}
#[test]
fn sampler_isolates_owned_core_workers_from_app_and_unrelated_processes() {
    let (source, owned) = library();
    let mut sampler = Sampler::default();
    let now = Instant::now();
    let first = sampler.sample_from(&source, 100, Some(owned), false, now, Some(SYS));
    assert_eq!(first.core_instance.as_deref(), Some("9"));
    assert_eq!(first.logical_cpus, Some(4));
    assert_eq!(first.app.processes, 2);
    assert_eq!(first.app.rss_bytes, Some(15 * 4096));
    assert_eq!(first.core.processes, 2);
    assert_eq!(first.core.rss_bytes, Some(30 * 4096));
    assert_eq!(first.core.cpu_percent, None);
    assert!(!source.reads.borrow().contains(&300));
    source.ticks(100, 120);
    source.ticks(101, 70);
    source.ticks(200, 240);
    source.ticks(201, 140);
    let second = sampler.sample_from(
        &source,
        100,
        Some(owned),
        false,
        now + Duration::from_secs(1),
        Some(SYS),
    );
    assert_eq!(second.app.cpu_percent, Some(10.0));
    assert_eq!(second.core.cpu_percent, Some(20.0));
    assert_eq!(second.interval_ms, Some(1000));
}
#[test]
fn sampler_reset_gap_and_changed_core_do_not_join_cpu_intervals() {
    let (source, owned) = library();
    let mut sampler = Sampler::default();
    let now = Instant::now();
    sampler.sample_from(&source, 100, Some(owned), false, now, Some(SYS));
    let reset = sampler.sample_from(
        &source,
        100,
        Some(owned),
        true,
        now + Duration::from_secs(1),
        Some(SYS),
    );
    assert_eq!(reset.app.reason, Some(2));
    assert_eq!(reset.core.reason, Some(2));
    let gap = sampler.sample_from(
        &source,
        100,
        Some(owned),
        false,
        now + Duration::from_secs(6),
        Some(SYS),
    );
    assert_eq!(gap.app.reason, Some(3));
    assert_eq!(gap.core.cpu_percent, None);
    let new = sampler.sample_from(
        &source,
        100,
        Some(OwnedProcess {
            instance: 10,
            ..owned
        }),
        false,
        now + Duration::from_secs(7),
        Some(SYS),
    );
    assert_eq!(new.core_instance.as_deref(), Some("10"));
    assert_eq!(new.core.reason, Some(4));
    assert_eq!(new.app.cpu_percent, Some(0.0));
}
#[test]
fn inaccessible_or_uncaptured_core_never_leaks_into_app_tree() {
    for reason in [5, 6, 7] {
        let (source, owned) = library();
        source.error(200, reason);
        let snapshot = Sampler::default().sample_from(
            &source,
            100,
            Some(owned),
            false,
            Instant::now(),
            Some(SYS),
        );
        assert_eq!(snapshot.app.status, Status::Ok);
        assert_eq!(snapshot.app.rss_bytes, Some(15 * 4096));
        assert_eq!(snapshot.core.status, Status::Unavailable);
        assert_eq!(snapshot.core.reason, Some(reason));
        assert_eq!(snapshot.core.rss_bytes, None);
        assert!(!source.reads.borrow().contains(&201));
    }
    let (source, owned) = library();
    let snapshot = Sampler::default().sample_from(
        &source,
        100,
        Some(OwnedProcess {
            start_time: None,
            ..owned
        }),
        false,
        Instant::now(),
        Some(SYS),
    );
    assert_eq!(snapshot.core.reason, Some(10));
    assert!(!source.reads.borrow().contains(&200));
    assert!(!source.reads.borrow().contains(&201));
    assert_eq!(snapshot.app.processes, 2);
}
#[test]
fn owned_root_pid_reuse_is_unavailable_not_a_newly_adopted_process() {
    let (source, owned) = library();
    source.insert(200, 100, 999, 1, 999, &[201]);
    let snapshot =
        Sampler::default().sample_from(&source, 100, Some(owned), false, Instant::now(), Some(SYS));
    assert_eq!(snapshot.core.reason, Some(4));
    assert_eq!(snapshot.core.rss_bytes, None);
    assert_eq!(snapshot.app.rss_bytes, Some(15 * 4096));
    assert!(!source.reads.borrow().contains(&201));
}
#[test]
fn root_rechecked_after_children_and_reparented_children_are_rejected() {
    let (source, _) = library();
    source.stats.borrow_mut().insert(
        200,
        VecDeque::from([
            Ok(stat(200, 100, 20, 100, 20)),
            Ok(stat(200, 100, 20, 100, 20)),
            Ok(stat(200, 100, 999, 100, 20)),
        ]),
    );
    let tree = collect(&source, 200, Some(20), None);
    assert!(!tree.root_valid);
    assert_eq!(tree.reason, Some(4));
    let (source, _) = library();
    source.insert(201, 300, 21, 100, 10, &[300]);
    let tree = collect(&source, 200, Some(20), None);
    assert!(tree.root_valid);
    assert_eq!(tree.reason, Some(4));
    assert_eq!(tree.entries.len(), 1);
    assert!(!source.reads.borrow().contains(&300));
}
#[test]
fn identity_changed_during_children_read_never_lends_descendants() {
    let (source, _) = library();
    source.stats.borrow_mut().insert(
        200,
        VecDeque::from([
            Ok(stat(200, 100, 20, 100, 20)),
            Ok(stat(200, 100, 999, 100, 20)),
        ]),
    );
    let tree = collect(&source, 200, Some(20), None);
    assert!(!tree.root_valid);
    assert_eq!(tree.reason, Some(4));
    assert!(!source.reads.borrow().contains(&201));
}
#[test]
fn partial_descendant_permission_or_disappearance_keeps_known_rss_without_cpu() {
    let (source, _) = library();
    source.error(201, 6);
    let mut baseline = None;
    let result = usage(
        collect(&source, 200, Some(20), None),
        &mut baseline,
        Instant::now(),
        SYS,
        None,
    );
    assert_eq!(result.status, Status::Partial);
    assert_eq!(result.rss_bytes, Some(20 * 4096));
    assert_eq!(result.reason, Some(6));
    assert_eq!(result.cpu_percent, None);
    assert!(baseline.is_none());
    source.error(201, 5);
    assert_eq!(collect(&source, 200, Some(20), None).reason, Some(5));
}
#[test]
fn absent_core_and_unavailable_system_have_explicit_states() {
    let (source, _) = library();
    let mut sampler = Sampler::default();
    let snapshot = sampler.sample_from(&source, 100, None, false, Instant::now(), Some(SYS));
    assert_eq!(snapshot.core.status, Status::Inactive);
    assert_eq!(snapshot.core.rss_bytes, None);
    assert_eq!(snapshot.core_instance, None);
    assert_eq!(snapshot.core.processes, 0);
    let no_system = sampler.sample_from(&source, 100, None, false, Instant::now(), None);
    assert_eq!(no_system.app.status, Status::Unavailable);
    assert_eq!(no_system.app.reason, Some(9));
    assert_eq!(no_system.logical_cpus, None);
    assert_eq!(no_system.core.status, Status::Inactive);
}
#[test]
fn scan_budgets_bound_processes_files_threads_bytes_and_elapsed_time() {
    let source = Fake::default();
    let children: Vec<_> = (2..=MAX_PROCESSES as u32 + 2).collect();
    source.insert(1, 0, 1, 1, 1, &children);
    for pid in children {
        source.insert(pid, 1, pid as u64, 1, 1, &[]);
    }
    let tree = collect(&source, 1, Some(1), None);
    assert_eq!(tree.reason, Some(8));
    assert!(source.reads.borrow().len() <= 3 * MAX_PROCESSES);
    let mut budget = Budget::new();
    budget.files = MAX_FILES;
    assert_eq!(budget.available(), Err(8));
    let mut budget = Budget::new();
    budget.threads = MAX_THREADS;
    assert_eq!(budget.thread(), Err(8));
    let mut budget = Budget::new();
    budget.processes = MAX_PROCESSES;
    assert_eq!(budget.process(), Err(8));
    let mut budget = Budget::new();
    budget.bytes = MAX_BYTES + 1;
    assert_eq!(budget.available(), Err(8));
    let mut budget = Budget::new();
    budget.started = Instant::now() - MAX_SCAN - Duration::from_millis(1);
    assert_eq!(budget.available(), Err(8));
}
#[test]
fn children_reads_every_thread_deduplicates_and_limits_input() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("100/task/100")).unwrap();
    std::fs::create_dir_all(root.join("100/task/102")).unwrap();
    std::fs::write(root.join("100/task/100/children"), b"200 201 ").unwrap();
    std::fs::write(root.join("100/task/102/children"), b"202 201\n").unwrap();
    let proc = Proc {
        root: root.to_path_buf(),
    };
    assert_eq!(
        proc.children(100, &mut Budget::new()).unwrap(),
        vec![200, 201, 202]
    );
    std::fs::write(
        root.join("100/task/102/children"),
        vec![b' '; MAX_FILE_BYTES + 1],
    )
    .unwrap();
    assert_eq!(proc.children(100, &mut Budget::new()), Err(8));
    std::fs::write(root.join("100/task/102/children"), b"0").unwrap();
    assert_eq!(proc.children(100, &mut Budget::new()), Err(7));
}
#[test]
#[ignore = "owned subprocess fixture, invoked only by its smoke test"]
fn owned_child_fixture() {
    if std::env::var_os("THRONIUM_METRICS_CHILD").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    use std::io::{BufRead, Write};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let busy = Arc::new(AtomicBool::new(true));
    let worker_flag = Arc::clone(&busy);
    let worker = std::thread::spawn(move || {
        let mut pages = vec![0u8; 4 * 1024 * 1024];
        for index in (0..pages.len()).step_by(4096) {
            pages[index] = 1;
        }
        while worker_flag.load(Ordering::Relaxed) {
            std::hint::black_box(&pages);
            std::hint::spin_loop();
        }
    });
    println!("THRONIUM_METRICS_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    busy.store(false, Ordering::Relaxed);
    worker.join().unwrap();
}
#[test]
fn real_self_and_owned_thread_spawned_child_smoke() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_metrics::linux::tests::owned_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("THRONIUM_METRICS_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = false;
    for line in BufReader::new(child.0.stdout.take().unwrap()).lines() {
        if line.unwrap().contains("THRONIUM_METRICS_READY") {
            ready = true;
            break;
        }
    }
    assert!(ready, "owned fixture exited before readiness");
    let proc = Proc {
        root: PathBuf::from("/proc"),
    };
    let pid = child.0.id();
    let identity = proc.stat(pid, &mut Budget::new()).unwrap().identity;
    let owned = OwnedProcess {
        pid,
        instance: 98765,
        start_time: Some(identity.start),
    };
    let mut sampler = Sampler::default();
    let first = sampler.sample(Some(owned), true);
    assert_eq!(first.app.status, Status::Ok);
    assert_eq!(first.core.status, Status::Ok);
    assert_eq!(first.core.processes, 1);
    assert!(first.app.rss_bytes.unwrap() > 0);
    assert!(first.core.rss_bytes.unwrap() > 1024 * 1024);
    assert_eq!(first.core.cpu_percent, None);
    let app_tree = collect(&proc, std::process::id(), None, Some(pid));
    assert!(!app_tree.entries.keys().any(|id| id.pid == pid));
    std::thread::sleep(Duration::from_millis(600));
    let second = sampler.sample(Some(owned), false);
    assert_eq!(second.core.status, Status::Ok);
    assert_eq!(second.core_instance, first.core_instance);
    assert!(
        second
            .core
            .cpu_percent
            .is_some_and(|cpu| cpu > 0.0 && cpu <= 100.0),
        "{second:?}"
    );
    assert_eq!(second.core.processes, 1);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let gone = sampler.sample(Some(owned), false);
    assert_eq!(gone.core.status, Status::Unavailable);
    assert_eq!(gone.core.reason, Some(5));
    let inactive = sampler.sample(None, false);
    assert_eq!(inactive.core.status, Status::Inactive);
    assert_eq!(inactive.core_instance, None);
}
