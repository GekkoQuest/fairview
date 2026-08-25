mod audio;
mod camera;
mod display;
mod overlay;
mod process;
mod remote;
mod signature;
mod util;
mod vm;

pub use audio::collect_audio;
pub use camera::collect_cameras;
pub use display::collect_displays;
pub use overlay::collect_overlays;
pub use process::enrich_processes;
pub use remote::collect_remote;
pub use vm::fill_environment;

use crate::origin::SignatureStatus;
use std::path::Path;

pub fn verify_signature(path: &Path) -> SignatureStatus {
    signature::verify(path)
}
