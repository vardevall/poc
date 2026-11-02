//! Writes a scenario's run to `$VV_TRACE/<test name>.json` for the trace viewer, when `VV_TRACE`
//! is set.

use vardevall_proto::sim::Sim;
use vardevall_proto::time::Instant;

/// Saves the run of `sim`; `t0` is the scenario's time zero.
pub fn save(sim: &Sim, t0: Instant) {
    let Some(dir) = std::env::var_os("VV_TRACE") else {
        return;
    };
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("scenario").replace("::", "-");
    let body = format!(
        "{{\"name\":\"{name}\",\"t0\":{},\"sim\":{}}}",
        t0.as_duration().as_micros(),
        sim.trace()
    );
    let path = std::path::Path::new(&dir).join(format!("{name}.json"));
    if let Err(e) = std::fs::write(&path, body) {
        eprintln!("trace: {}: {e}", path.display());
    }
}
