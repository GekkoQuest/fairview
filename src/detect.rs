use crate::config::Config;
use crate::evidence::{Finding, Inventory, OverlayWindow};
use crate::overlay::OverlayObservation;
use crate::platform;
use crate::process::{self, ProcessBaseline, ProcessTable};
use crate::smbios::EnvironmentFacts;
use sysinfo::System;

pub struct Collectors {
    processes: ProcessTable,
}

pub struct Snapshot {
    pub inventory: Inventory,
    pub overlays: Vec<OverlayWindow>,
    pub overlay_obs: Vec<OverlayObservation>,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    pub process_snapshots: Vec<crate::evidence::ProcessSnapshot>,
}

impl Collectors {
    pub fn new() -> Self {
        Self {
            processes: ProcessTable::new(),
        }
    }

    pub fn collect(
        &mut self,
        config: &Config,
        process_baseline: Option<&ProcessBaseline>,
        display_baseline: Option<&[crate::evidence::DisplayInfo]>,
    ) -> Snapshot {
        self.processes.refresh();
        let mut procs = self.processes.snapshot();
        platform::enrich_processes(&mut procs);

        let mut errors = Vec::new();
        let mut findings = Vec::new();
        let mut inventory = Inventory {
            hostname: System::host_name(),
            os: System::name(),
            os_version: System::os_version(),
            ..Inventory::default()
        };

        if config.monitoring.process {
            findings.extend(process::analyze(config, &procs, process_baseline));
        }

        if config.monitoring.display {
            match platform::collect_displays() {
                Ok(displays) => {
                    findings.extend(crate::display::analyze(&displays, display_baseline));
                    inventory.displays = displays;
                }
                Err(e) => errors.push(format!("display: {e}")),
            }
        }

        let mut overlay_obs = Vec::new();
        if config.monitoring.overlay {
            match platform::collect_overlays() {
                Ok(obs) => {
                    for o in &obs {
                        if let Some(f) = crate::overlay::classify(o, |n| {
                            config.is_expected_name(n) || crate::known::is_meeting_app(n)
                        }) {
                            findings.push(f);
                        }
                    }
                    overlay_obs = obs.into_iter().filter(|o| o.is_reportable()).collect();
                }
                Err(e) => errors.push(format!("overlay: {e}")),
            }
        }

        if config.monitoring.audio {
            match platform::collect_audio() {
                Ok(sessions) => {
                    for s in &sessions {
                        if !s.capture {
                            continue;
                        }
                        let name = procs
                            .iter()
                            .find(|p| p.pid == s.pid)
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| s.name.clone());
                        findings.push(
                            crate::evidence::Finding::new(
                                crate::evidence::Detector::Audio,
                                "audio.capture",
                                crate::evidence::Severity::Low,
                                0.7,
                                format!("Process {name} (pid {}) has an active capture (mic) session on {}", s.pid, s.device),
                            )
                            .detail("device", s.device.clone())
                            .with_process(crate::evidence::ProcessRef {
                                pid: s.pid,
                                name,
                                path: None,
                            }),
                        );
                    }
                    inventory.audio_sessions = sessions;
                }
                Err(e) => errors.push(format!("audio: {e}")),
            }
        }

        if config.monitoring.camera {
            match platform::collect_cameras() {
                Ok(cameras) => {
                    for c in &cameras {
                        if c.virtual_device {
                            findings.push(
                                crate::evidence::Finding::new(
                                    crate::evidence::Detector::Camera,
                                    "camera.virtual",
                                    crate::evidence::Severity::Medium,
                                    0.75,
                                    format!("Virtual camera device: {}", c.name),
                                )
                                .detail("id", c.id.clone()),
                            );
                        } else if crate::known::capture_card_name(&c.name) {
                            findings.push(
                                crate::evidence::Finding::new(
                                    crate::evidence::Detector::Camera,
                                    "camera.capture_card",
                                    crate::evidence::Severity::Medium,
                                    0.7,
                                    format!("Capture-card / HDMI ingest device: {}", c.name),
                                )
                                .detail("id", c.id.clone()),
                            );
                        }
                    }
                    inventory.cameras = cameras;
                }
                Err(e) => errors.push(format!("camera: {e}")),
            }
        }

        if config.monitoring.remote {
            match platform::collect_remote() {
                Ok(remote) => {
                    inventory.remote_session = remote.active_session;
                    findings.extend(remote.findings);
                }
                Err(e) => errors.push(format!("remote: {e}")),
            }
        }

        if config.monitoring.environment {
            match collect_environment() {
                Ok((class, env_findings)) => {
                    inventory.environment = Some(class);
                    findings.extend(env_findings);
                }
                Err(e) => errors.push(format!("environment: {e}")),
            }
        }

        let overlays = overlay_obs.iter().map(|o| o.to_window()).collect();

        Snapshot {
            inventory,
            overlays,
            overlay_obs,
            findings,
            errors,
            process_snapshots: procs,
        }
    }
}

fn collect_environment(
) -> crate::error::Result<(crate::smbios::EnvironmentClassification, Vec<Finding>)> {
    let mut facts = EnvironmentFacts {
        hostname: System::host_name(),
        ..EnvironmentFacts::default()
    };
    platform::fill_environment(&mut facts)?;
    let class = crate::smbios::classify(&facts);
    let mut findings = Vec::new();
    match class.kind {
        crate::smbios::EnvironmentKind::VirtualGuest => {
            findings.push(
                Finding::new(
                    crate::evidence::Detector::Environment,
                    "environment.guest",
                    crate::evidence::Severity::Medium,
                    0.9,
                    "This OS looks like a virtual machine guest",
                )
                .detail(
                    "vendor",
                    class.hypervisor_vendor.clone().unwrap_or_default(),
                )
                .detail("reasons", class.reasons.join("; ")),
            );
        }
        crate::smbios::EnvironmentKind::HypervisorRoot => {
            findings.push(
                Finding::new(
                    crate::evidence::Detector::Environment,
                    "environment.root_hypervisor",
                    crate::evidence::Severity::Info,
                    0.8,
                    "A hypervisor is present but SMBIOS looks like a physical host (VBS / Hyper-V root / WSL2). This is not classified as a VM guest.",
                )
                .detail("reasons", class.reasons.join("; ")),
            );
        }
        crate::smbios::EnvironmentKind::Inconclusive => {
            findings.push(
                Finding::new(
                    crate::evidence::Detector::Environment,
                    "environment.inventory",
                    crate::evidence::Severity::Info,
                    0.4,
                    "Environment signals are inconclusive",
                )
                .detail("reasons", class.reasons.join("; ")),
            );
        }
        crate::smbios::EnvironmentKind::Physical => {}
    }
    Ok((class, findings))
}

impl Default for Collectors {
    fn default() -> Self {
        Self::new()
    }
}
