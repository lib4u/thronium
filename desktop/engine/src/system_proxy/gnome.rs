use super::*;
use gio::{glib, prelude::*};
pub struct Gnome;
static GTK_THREAD: std::sync::OnceLock<std::thread::ThreadId> = std::sync::OnceLock::new();
// GSettings notifications belong to the GLib context where the backend was
// initialized (GTK). Keep reads and writes there, including rapid reconnects.
fn on_context<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    // setup/recovery runs before GTK starts dispatching its main context.
    if GTK_THREAD.get() == Some(&std::thread::current().id()) {
        return f();
    }
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    glib::MainContext::default().invoke(move || {
        let _ = send.send(f());
    });
    receive.recv().map_err(|_| "system_proxy_apply_failed")?
}
fn schema(index: usize) -> Result<gio::SettingsSchema, String> {
    let suffix = KEYS[index].0;
    let schema = format!(
        "org.gnome.system.proxy{}{}",
        if suffix.is_empty() { "" } else { "." },
        suffix
    );
    let source = gio::SettingsSchemaSource::default().ok_or("system_proxy_unavailable")?;
    source
        .lookup(&schema, true)
        .ok_or_else(|| "system_proxy_unavailable".into())
}
fn settings(index: usize) -> Result<gio::Settings, String> {
    let schema = schema(index)?;
    Ok(gio::Settings::new_full(
        &schema,
        None::<&gio::SettingsBackend>,
        None,
    ))
}
pub fn available() -> bool {
    GTK_THREAD.get_or_init(|| std::thread::current().id());
    std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .any(|v| v.eq_ignore_ascii_case("gnome"))
        && (0..KEYS.len()).all(|i| schema(i).is_ok())
}
impl Backend for Gnome {
    fn read(&self) -> Result<Vec<Value>, String> {
        on_context(|| {
            gio::Settings::sync();
            (0..KEYS.len())
                .map(|i| {
                    let s = settings(i)?;
                    Ok(Value {
                        effective: s.value(KEYS[i].1).print(true).to_string(),
                        user: s.user_value(KEYS[i].1).map(|v| v.print(true).to_string()),
                    })
                })
                .collect()
        })
    }
    fn writable(&self) -> Result<(), String> {
        on_context(|| {
            for (i, (_, key)) in KEYS.iter().enumerate() {
                if !settings(i)?.is_writable(key) {
                    return Err("system_proxy_not_writable".into());
                }
            }
            Ok(())
        })
    }
    fn write(&self, index: usize, value: Option<&str>) -> Result<(), String> {
        let value = value.map(str::to_owned);
        on_context(move || {
            let s = settings(index)?;
            let key = KEYS[index].1;
            if !s.is_writable(key) {
                return Err("system_proxy_not_writable".into());
            }
            if let Some(raw) = value.as_deref() {
                let existing = s.value(key);
                let value = glib::Variant::parse(Some(existing.type_()), raw)
                    .map_err(|_| "system_proxy_recovery_failed")?;
                s.set_value(key, &value)
                    .map_err(|_| "system_proxy_apply_failed")?;
            } else {
                s.reset(key);
            }
            gio::Settings::sync();
            Ok(())
        })
    }
}
