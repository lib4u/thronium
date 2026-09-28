use super::*;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
const GEO: &[u8] = b"\x0a\x11\x0a\x04TEST\x12\x09\x08\x02\x12\x05a.com";
struct Owner {
    state: State,
    engine: Mutex<Result<Engine, String>>,
    quitting: AtomicBool,
    _dir: tempfile::TempDir,
}
impl Owner {
    fn new() -> Arc<Self> {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
        Arc::new(Self {
            state: State::default(),
            engine: Mutex::new(Ok(engine)),
            quitting: AtomicBool::new(false),
            _dir: dir,
        })
    }
    async fn run(&self, name: &str, payload: Value) -> Result<Value, String> {
        self.state
            .execute(&self.engine, &self.quitting, name, payload)
            .await
    }
    fn spawn(
        self: &Arc<Self>,
        name: &'static str,
        payload: Value,
    ) -> tokio::task::JoinHandle<Result<Value, String>> {
        let owner = self.clone();
        tokio::spawn(async move { owner.run(name, payload).await })
    }
    async fn no_source(&self) {
        assert_eq!(
            self.engine
                .lock()
                .await
                .as_ref()
                .unwrap()
                .geodata_sources()
                .unwrap(),
            json!([])
        );
    }
}
struct Fixture {
    url: String,
    started: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
async fn fixture(body: &'static [u8]) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixture", listener.local_addr().unwrap());
    let (started, seen) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            request.push(socket.read_u8().await.unwrap());
        }
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&body[..1]).await.unwrap();
        started.send(()).unwrap();
        if wait.await.is_ok() {
            let _ = socket.write_all(&body[1..]).await;
        }
    });
    Fixture {
        url,
        started: seen,
        release,
        task,
    }
}
async fn finish(task: tokio::task::JoinHandle<Result<Value, String>>) -> Result<Value, String> {
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("operation must not wait for the delayed origin")
        .unwrap()
}

#[tokio::test]
async fn cancelled_before_dispatch_never_reuses_an_id() {
    let owner = Owner::new();
    owner
        .run("cancelRoutingDownload", json!({"requestId":"before"}))
        .await
        .unwrap();
    let result = owner
        .run(
            "loadGeodata",
            json!({"requestId":"before","kind":"geosite","url":"http://127.0.0.1:9/no-network"}),
        )
        .await;
    assert_eq!(result.err().as_deref(), Some("geodata_request_finished"));
    owner.no_source().await;
}
#[tokio::test]
async fn delayed_body_releases_engine_for_snapshot_and_cancel_without_installing() {
    let owner = Owner::new();
    let f = fixture(GEO).await;
    let task = owner.spawn(
        "loadGeodata",
        json!({"requestId":"cancel-body","kind":"geosite","url":f.url}),
    );
    f.started.await.unwrap();
    let mut guard = tokio::time::timeout(Duration::from_secs(1), owner.engine.lock())
        .await
        .expect("snapshot blocked by HTTP");
    assert!(guard.as_mut().unwrap().snapshot().running.is_none());
    drop(guard);
    owner
        .run("cancelRoutingDownload", json!({"requestId":"cancel-body"}))
        .await
        .unwrap();
    assert_eq!(
        finish(task).await.err().as_deref(),
        Some("geodata_cancelled")
    );
    let _ = f.release.send(());
    f.task.await.unwrap();
    owner.no_source().await;
    // Finishing a cancelled owner releases the slot for a later operation.
    let next = fixture(b"{}").await;
    let task = owner.spawn(
        "fetchRoutingSource",
        json!({"requestId":"next","url":next.url}),
    );
    next.started.await.unwrap();
    next.release.send(()).unwrap();
    assert_eq!(finish(task).await.unwrap()["text"], "{}");
    next.task.await.unwrap();
}
#[tokio::test]
async fn cancellation_while_commit_waits_drops_the_completed_result() {
    let owner = Owner::new();
    let f = fixture(GEO).await;
    let task = owner.spawn(
        "loadGeodata",
        json!({"requestId":"late-cancel","kind":"geosite","url":f.url}),
    );
    f.started.await.unwrap();
    let guard = owner.engine.lock().await;
    f.release.send(()).unwrap();
    f.task.await.unwrap();
    owner
        .run("cancelRoutingDownload", json!({"requestId":"late-cancel"}))
        .await
        .unwrap();
    assert_eq!(
        finish(task).await.err().as_deref(),
        Some("geodata_cancelled")
    );
    drop(guard);
    owner.no_source().await;
}
#[tokio::test]
async fn material_profile_edit_rejects_late_results_for_both_commands() {
    for name in ["loadGeodata", "fetchRoutingSource"] {
        let owner = Owner::new();
        let profile = {
            let mut guard = owner.engine.lock().await;
            guard.as_mut().unwrap().save_profile(serde_json::from_value(json!({"name":"Before","groupId":"personal","kind":"sing-box-outbound","config":{"type":"direct"}})).unwrap()).unwrap()
        };
        let f = fixture(if name == "loadGeodata" { GEO } else { b"{}" }).await;
        let task = owner.spawn(
            name,
            json!({"requestId":"stale-profile","kind":"geosite","url":f.url}),
        );
        f.started.await.unwrap();
        {
            let mut guard = owner.engine.lock().await;
            let engine = guard.as_mut().unwrap();
            let mut edit = engine.profile(&profile).unwrap();
            edit.name = "After".into();
            engine
                .save_profile(serde_json::from_value(serde_json::to_value(edit).unwrap()).unwrap())
                .unwrap();
        }
        f.release.send(()).unwrap();
        assert_eq!(
            finish(task).await.err().as_deref(),
            Some("geodata_context_changed")
        );
        f.task.await.unwrap();
        owner.no_source().await;
    }
}
#[tokio::test]
async fn unrelated_display_changes_survive_and_geodata_commits_once() {
    let owner = Owner::new();
    let f = fixture(GEO).await;
    let task = owner.spawn(
        "loadGeodata",
        json!({"requestId":"keep-display","kind":"geosite","url":f.url}),
    );
    f.started.await.unwrap();
    {
        let mut guard = owner.engine.lock().await;
        let engine = guard.as_mut().unwrap();
        let mut next = engine.store.library.preferences.clone();
        next.language = "ru".into();
        engine.preferences(next).unwrap();
    }
    f.release.send(()).unwrap();
    assert_eq!(finish(task).await.unwrap()["categories"][0]["code"], "test");
    f.task.await.unwrap();
    let guard = owner.engine.lock().await;
    assert_eq!(
        guard.as_ref().unwrap().store.library.preferences.language,
        "ru"
    );
    assert_eq!(
        guard
            .as_ref()
            .unwrap()
            .geodata_sources()
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn exit_cancels_downloads_before_waiting_for_engine_and_prevents_reuse() {
    let owner = Owner::new();
    let f = fixture(GEO).await;
    let task = owner.spawn(
        "loadGeodata",
        json!({"requestId":"exit","kind":"geosite","url":f.url}),
    );
    f.started.await.unwrap();
    owner.quitting.store(true, Ordering::SeqCst);
    owner.state.cancel_all().await;
    {
        let mut guard = tokio::time::timeout(Duration::from_secs(1), owner.engine.lock())
            .await
            .unwrap();
        guard.as_mut().unwrap().shutdown_checked().await.unwrap();
    }
    assert!(matches!(
        finish(task).await.err().as_deref(),
        Some("geodata_cancelled" | "app_quitting")
    ));
    let _ = f.release.send(());
    f.task.await.unwrap();
    owner.no_source().await;
    assert_eq!(
        owner
            .run("fetchRoutingSource", json!({"url":"http://127.0.0.1:9"}))
            .await
            .err()
            .as_deref(),
        Some("app_quitting")
    );
    // A failed application shutdown can permit new work; old request ids stay spent.
    owner.quitting.store(false, Ordering::SeqCst);
    assert_eq!(
        owner
            .run(
                "fetchRoutingSource",
                json!({"requestId":"exit","url":"http://127.0.0.1:9"})
            )
            .await
            .err()
            .as_deref(),
        Some("geodata_request_finished")
    );
}

#[tokio::test]
async fn routing_content_and_network_changes_reject_late_bytes_even_with_the_same_revision() {
    for routing in [true, false] {
        let owner = Owner::new();
        let f = fixture(GEO).await;
        let task = owner.spawn(
            "loadGeodata",
            json!({"requestId":"changed-context","kind":"geosite","url":f.url}),
        );
        f.started.await.unwrap();
        {
            let mut guard = owner.engine.lock().await;
            let library = &mut guard.as_mut().unwrap().store.library;
            if routing {
                library.routing.profiles[0].route["final"] = json!("direct");
            } else {
                library
                    .settings
                    .insert("user_agent".into(), json!("changed-fixture-agent"));
            }
        }
        f.release.send(()).unwrap();
        assert_eq!(
            finish(task).await.err().as_deref(),
            Some("geodata_context_changed")
        );
        f.task.await.unwrap();
        owner.no_source().await;
    }
}
