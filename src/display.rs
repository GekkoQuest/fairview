//! Display topology analysis. Platform code supplies snapshots; this module
//! compares them and looks for virtual outputs, dummy plugs, and cloned EDIDs.

use crate::edid;
use crate::evidence::{Detector, DisplayInfo, Finding, Severity};
use std::collections::HashMap;

pub fn analyze(current: &[DisplayInfo], baseline: Option<&[DisplayInfo]>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for d in current {
        if d.connector.is_virtual()
            || adapter_looks_virtual(d.adapter.as_deref().unwrap_or(""), &d.name)
        {
            findings.push(
                Finding::new(
                    Detector::Display,
                    "display.virtual",
                    Severity::High,
                    0.85,
                    format!("Virtual / indirect display is active: {}", d.name),
                )
                .detail("id", d.id.clone())
                .detail("connector", format!("{:?}", d.connector))
                .detail("adapter", d.adapter.clone().unwrap_or_default()),
            );
        } else if d.connector.is_wireless() {
            findings.push(
                Finding::new(
                    Detector::Display,
                    "display.wireless",
                    Severity::Medium,
                    0.7,
                    format!("Wireless display is active: {}", d.name),
                )
                .detail("id", d.id.clone()),
            );
        }

        if let Some(edid) = &d.edid {
            if edid::looks_like_dummy(edid) {
                findings.push(
                    Finding::new(
                        Detector::Display,
                        "display.dummy_edid",
                        Severity::High,
                        0.8,
                        format!(
                            "Display EDID looks like a dummy / virtual plug ({})",
                            edid.name.as_deref().unwrap_or(&edid.manufacturer)
                        ),
                    )
                    .detail("id", d.id.clone())
                    .detail("manufacturer", edid.manufacturer.clone()),
                );
            }
        }
    }

    findings.extend(duplicate_edid_findings(current));

    if let Some(base) = baseline {
        findings.extend(diff_baseline(base, current));
    }

    findings
}

fn adapter_looks_virtual(adapter: &str, name: &str) -> bool {
    let blob = format!("{adapter} {name}").to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "virtual display",
        "indirect display",
        "idd sample",
        "usbmmidd",
        "usb mobile monitor",
        "spacedesk",
        "parsec virtual",
        "sunshine",
        "microsoft remote display",
        "hyper-v video",
        "vmware svga",
        "virtualbox graphics",
        "qfhl",
        "mirage driver",
        "dummy",
    ];
    NEEDLES.iter().any(|n| blob.contains(n))
}

fn duplicate_edid_findings(displays: &[DisplayInfo]) -> Vec<Finding> {
    let mut groups: HashMap<String, Vec<&DisplayInfo>> = HashMap::new();
    for d in displays {
        if let Some(edid) = &d.edid {
            groups.entry(edid.identity_key()).or_default().push(d);
        }
    }
    let mut out = Vec::new();
    for (key, group) in groups {
        if group.len() < 2 {
            continue;
        }
        let unique = group
            .iter()
            .all(|d| d.edid.as_ref().is_some_and(|e| e.has_unique_serial()));
        let (severity, confidence, signal) = if unique {
            // Identical manufacturer+product+serial on two outputs is a cloned EDID.
            (Severity::High, 0.8, "display.cloned_edid")
        } else {
            // Two identical model panels with serial 0 is often just two of the same monitor.
            (Severity::Low, 0.35, "display.same_model")
        };
        out.push(
            Finding::new(
                Detector::Display,
                signal,
                severity,
                confidence,
                format!(
                    "{} displays share EDID identity {} ({})",
                    group.len(),
                    key,
                    group
                        .iter()
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .detail("count", group.len().to_string()),
        );
    }
    out
}

fn diff_baseline(baseline: &[DisplayInfo], current: &[DisplayInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for d in current {
        if !baseline.iter().any(|b| same_monitor(b, d)) {
            findings.push(
                Finding::new(
                    Detector::Display,
                    "display.added",
                    Severity::High,
                    0.75,
                    format!("Display appeared after baseline: {}", d.name),
                )
                .detail("id", d.id.clone())
                .detail("connector", format!("{:?}", d.connector)),
            );
        }
    }
    for b in baseline {
        if !current.iter().any(|d| same_monitor(b, d)) {
            findings.push(
                Finding::new(
                    Detector::Display,
                    "display.removed",
                    Severity::Medium,
                    0.7,
                    format!("Display disappeared after baseline: {}", b.name),
                )
                .detail("id", b.id.clone()),
            );
        }
    }
    findings
}

fn same_monitor(a: &DisplayInfo, b: &DisplayInfo) -> bool {
    if a.id == b.id {
        return true;
    }
    match (&a.edid, &b.edid) {
        (Some(x), Some(y)) if x.has_unique_serial() => x.identity_key() == y.identity_key(),
        _ => {
            a.name == b.name
                && a.connector == b.connector
                && a.width == b.width
                && a.height == b.height
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edid::EdidInfo;
    use crate::evidence::ConnectorKind;

    fn display(
        id: &str,
        name: &str,
        connector: ConnectorKind,
        edid: Option<EdidInfo>,
    ) -> DisplayInfo {
        DisplayInfo {
            id: id.into(),
            name: name.into(),
            connector,
            is_builtin: false,
            is_primary: id == "1",
            width: 1920,
            height: 1080,
            adapter: None,
            edid,
            clone_group: None,
        }
    }

    fn edid(mfg: &str, serial: u32) -> EdidInfo {
        EdidInfo {
            manufacturer: mfg.into(),
            product_code: 1,
            serial,
            serial_string: None,
            name: Some("Panel".into()),
            year: 2020,
            week: 1,
            checksum_ok: true,
        }
    }

    #[test]
    fn dual_physical_monitors_are_not_findings() {
        let cur = vec![
            display("1", "eDP", ConnectorKind::Internal, Some(edid("LGD", 1))),
            display("2", "HDMI", ConnectorKind::Hdmi, Some(edid("DEL", 2))),
        ];
        let f = analyze(&cur, None);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn virtual_connector_is_high() {
        let cur = vec![display("v", "IDD", ConnectorKind::IndirectVirtual, None)];
        let f = analyze(&cur, None);
        assert!(f.iter().any(|x| x.signal == "display.virtual"));
    }

    #[test]
    fn cloned_serial_is_high() {
        let e = edid("DEL", 0xABCDEF);
        let cur = vec![
            display("1", "HDMI-1", ConnectorKind::Hdmi, Some(e.clone())),
            display("2", "HDMI-2", ConnectorKind::Hdmi, Some(e)),
        ];
        let f = analyze(&cur, None);
        assert!(f.iter().any(|x| x.signal == "display.cloned_edid"));
    }

    #[test]
    fn new_monitor_after_baseline() {
        let base = vec![display(
            "1",
            "eDP",
            ConnectorKind::Internal,
            Some(edid("LGD", 1)),
        )];
        let cur = vec![
            display("1", "eDP", ConnectorKind::Internal, Some(edid("LGD", 1))),
            display("2", "HDMI", ConnectorKind::Hdmi, Some(edid("DEL", 9))),
        ];
        let f = analyze(&cur, Some(&base));
        assert!(f.iter().any(|x| x.signal == "display.added"));
    }
}
