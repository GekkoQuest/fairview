//! Fairview collects structured evidence from the local OS during an interview.
//!
//! Detectors report observations. [`policy`] decides which of those are unexpected
//! for a given session. Reports talk about findings, not "cheating".

pub mod config;
pub mod correlate;
pub mod detect;
pub mod display;
pub mod edid;
pub mod error;
pub mod evidence;
pub mod known;
pub mod origin;
pub mod overlay;
pub mod policy;
pub mod process;
pub mod report;
pub mod session;
pub mod smbios;

mod platform;

pub use config::Config;
pub use error::{Error, Result};
pub use evidence::{Finding, Inventory, Severity};
pub use report::Report;
pub use session::Session;
