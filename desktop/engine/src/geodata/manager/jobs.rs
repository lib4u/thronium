//! Xray geodata downloads share the request registry of all cancellable jobs.
pub struct Geodata;
impl crate::request_jobs::Codes for Geodata {
    const INVALID: &'static str = "geodata_invalid_request";
    const FINISHED: &'static str = "geodata_request_finished";
    const BUSY: &'static str = "geodata_busy";
}
pub type Jobs = crate::request_jobs::Jobs<Geodata>;
