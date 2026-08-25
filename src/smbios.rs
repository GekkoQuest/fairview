//! SMBIOS/DMI helpers: string extraction and guest-vs-host classification.
//!
//! Windows exposes the raw table via GetSystemFirmwareTable('RSMB').
//! Linux exposes decoded strings under /sys/class/dmi/id.

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FirmwareIdentity {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub bios_vendor: Option<String>,
    pub strings: Vec<String>,
}

/// Raw Windows RSMB blob: 8-byte header then SMBIOS table.
pub fn parse_windows_rsmb(blob: &[u8]) -> FirmwareIdentity {
    if blob.len() < 8 {
        return FirmwareIdentity::default();
    }
    // BYTE Used20CallingMethod, Major, Minor, DmiRevision, DWORD Length
    let length = u32::from_le_bytes(blob[4..8].try_into().unwrap_or([0; 4])) as usize;
    let table = &blob[8..blob.len().min(8 + length).max(8)];
    parse_smbios_table(table)
}

pub fn parse_smbios_table(table: &[u8]) -> FirmwareIdentity {
    let mut identity = FirmwareIdentity::default();
    let mut i = 0;
    while i + 4 <= table.len() {
        let typ = table[i];
        let len = table[i + 1] as usize;
        if len < 4 || i + len > table.len() {
            break;
        }
        let formatted = &table[i..i + len];
        let mut s = i + len;
        let mut strings = Vec::new();
        if s < table.len() && table[s] == 0 && s + 1 < table.len() && table[s + 1] == 0 {
            s += 2;
        } else {
            while s < table.len() {
                if table[s] == 0 {
                    if s + 1 < table.len() && table[s + 1] == 0 {
                        s += 2;
                        break;
                    }
                    s += 1;
                    continue;
                }
                let start = s;
                while s < table.len() && table[s] != 0 {
                    s += 1;
                }
                if let Ok(text) = std::str::from_utf8(&table[start..s]) {
                    let t = text.trim();
                    if !t.is_empty() {
                        strings.push(t.to_string());
                    }
                }
                s += 1;
            }
        }

        identity.strings.extend(strings.iter().cloned());

        // Type 0 BIOS Information: vendor at string index byte 4
        if typ == 0 && formatted.len() > 4 {
            identity.bios_vendor = string_at(&strings, formatted[4]);
        }
        // Type 1 System Information: manufacturer 4, product 5, version 6
        if typ == 1 && formatted.len() > 6 {
            identity.manufacturer = string_at(&strings, formatted[4]);
            identity.product = string_at(&strings, formatted[5]);
            identity.version = string_at(&strings, formatted[6]);
        }

        if typ == 127 {
            break;
        }
        i = s;
    }
    identity
}

fn string_at(strings: &[String], index: u8) -> Option<String> {
    if index == 0 {
        return None;
    }
    strings.get(index as usize - 1).cloned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentKind {
    /// No hypervisor bit, no VM SMBIOS.
    Physical,
    /// Microsoft Hv CPUID but SMBIOS is a real OEM (VBS / WSL2 / Hyper-V root).
    HypervisorRoot,
    /// SMBIOS or vendor leaf says this OS is a guest.
    VirtualGuest,
    /// Conflicting or weak signals (MAC OUI only, etc.).
    Inconclusive,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentClassification {
    pub kind: EnvironmentKind,
    pub hypervisor_vendor: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EnvironmentFacts {
    pub cpuid_hypervisor: bool,
    pub cpuid_vendor: Option<String>,
    pub firmware: FirmwareIdentity,
    /// Windows: HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters exists.
    pub hyperv_guest_parameters: bool,
    pub hostname: Option<String>,
    pub mac_vm_vendors: Vec<String>,
    pub hw_model: Option<String>,
}

pub fn classify(facts: &EnvironmentFacts) -> EnvironmentClassification {
    let mut reasons = Vec::new();
    let vendor = facts.cpuid_vendor.as_deref().unwrap_or("");
    let mfg = facts.firmware.manufacturer.as_deref().unwrap_or("");
    let product = facts.firmware.product.as_deref().unwrap_or("");
    let bios = facts.firmware.bios_vendor.as_deref().unwrap_or("");
    let blob = format!(
        "{mfg} {product} {bios} {}",
        facts.firmware.strings.join(" ")
    )
    .to_lowercase();

    if facts.cpuid_hypervisor {
        reasons.push("CPUID hypervisor presence bit is set".into());
        if !vendor.is_empty() {
            reasons.push(format!("CPUID hypervisor vendor: {vendor}"));
        }
    }
    if facts.hyperv_guest_parameters {
        reasons.push("Hyper-V guest parameter registry key is present".into());
    }
    if let Some(model) = &facts.hw_model {
        reasons.push(format!("Hardware model: {model}"));
    }
    for mac in &facts.mac_vm_vendors {
        reasons.push(format!("NIC OUI associated with {mac}"));
    }

    let smbios_guest = smbios_looks_like_guest(&blob, product, mfg);
    if smbios_guest {
        reasons.push(format!(
            "SMBIOS identity looks like a guest ({mfg} {product})"
        ));
    }

    let apple_vm = facts
        .hw_model
        .as_deref()
        .is_some_and(|m| m.to_lowercase().contains("virtual"));

    let kind = if facts.hyperv_guest_parameters || smbios_guest || apple_vm {
        EnvironmentKind::VirtualGuest
    } else if is_microsoft_hv(vendor) && looks_like_physical_oem(mfg, product) {
        EnvironmentKind::HypervisorRoot
    } else if facts.cpuid_hypervisor && is_unambiguous_guest_vendor(vendor) {
        EnvironmentKind::VirtualGuest
    } else if facts.cpuid_hypervisor && is_microsoft_hv(vendor) {
        // Hyper-V bit with empty/generic SMBIOS: could be guest with SMBIOS hidden
        // or a host we couldn't fingerprint. Do not call this a VM.
        EnvironmentKind::HypervisorRoot
    } else if facts.cpuid_hypervisor && !vendor.is_empty() && !is_microsoft_hv(vendor) {
        EnvironmentKind::VirtualGuest
    } else if !facts.mac_vm_vendors.is_empty() && !facts.cpuid_hypervisor && !smbios_guest {
        EnvironmentKind::Inconclusive
    } else if facts.cpuid_hypervisor {
        EnvironmentKind::Inconclusive
    } else {
        EnvironmentKind::Physical
    };

    EnvironmentClassification {
        kind,
        hypervisor_vendor: facts.cpuid_vendor.clone(),
        reasons,
    }
}

fn is_microsoft_hv(vendor: &str) -> bool {
    let v = vendor.to_lowercase();
    v.contains("microsoft") || v.contains("hyper-v") || v.contains("hyperv")
}

fn is_unambiguous_guest_vendor(vendor: &str) -> bool {
    let v = vendor.to_lowercase();
    [
        "vmware",
        "kvm",
        "vbox",
        "virtualbox",
        "xen",
        "bhyve",
        "parallels",
        "prl ",
        "qemu",
        "tcg",
        "acrn",
    ]
    .iter()
    .any(|p| v.contains(p))
}

fn smbios_looks_like_guest(blob: &str, product: &str, mfg: &str) -> bool {
    let product_l = product.to_lowercase();
    let mfg_l = mfg.to_lowercase();
    if mfg_l.contains("microsoft") && product_l.contains("virtual machine") {
        return true;
    }
    const GUEST: &[&str] = &[
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "kvm",
        "bochs",
        "xen",
        "innotek",
        "parallels",
        "bhyve",
        "amazon ec2",
        "google compute",
        "digitalocean",
        "openstack",
        "kubevirt",
        "virtual machine",
        "hvm domu",
        "standard pc (q35",
        "standard pc (i440fx",
    ];
    GUEST.iter().any(|p| blob.contains(p))
}

fn looks_like_physical_oem(mfg: &str, product: &str) -> bool {
    let m = mfg.to_lowercase();
    let p = product.to_lowercase();
    if m.contains("microsoft") && p.contains("virtual") {
        return false;
    }
    const OEMS: &[&str] = &[
        "dell",
        "lenovo",
        "hewlett-packard",
        "hp ",
        "hewlett packard",
        "asus",
        "acer",
        "msi",
        "gigabyte",
        "apple",
        "samsung",
        "toshiba",
        "sony",
        "framework",
        "system76",
        "purism",
        "razer",
        "alienware",
        "microsoft corporation",
        "lg electronics",
        "huawei",
        "xiaomi",
        "clevo",
        "tongfang",
        "intel",
        "ibm",
        "supermicro",
        "tyan",
        "fujitsu",
        "panasonic",
        "nec ",
    ];
    OEMS.iter()
        .any(|o| m.contains(o.trim()) || p.contains(o.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperv_host_with_vbs_is_root_not_guest() {
        let facts = EnvironmentFacts {
            cpuid_hypervisor: true,
            cpuid_vendor: Some("Microsoft Hv".into()),
            firmware: FirmwareIdentity {
                manufacturer: Some("Dell Inc.".into()),
                product: Some("XPS 15 9530".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let c = classify(&facts);
        assert_eq!(c.kind, EnvironmentKind::HypervisorRoot);
    }

    #[test]
    fn hyperv_guest_smbios() {
        let facts = EnvironmentFacts {
            cpuid_hypervisor: true,
            cpuid_vendor: Some("Microsoft Hv".into()),
            firmware: FirmwareIdentity {
                manufacturer: Some("Microsoft Corporation".into()),
                product: Some("Virtual Machine".into()),
                ..Default::default()
            },
            hyperv_guest_parameters: true,
            ..Default::default()
        };
        assert_eq!(classify(&facts).kind, EnvironmentKind::VirtualGuest);
    }

    #[test]
    fn vmware_guest() {
        let facts = EnvironmentFacts {
            cpuid_hypervisor: true,
            cpuid_vendor: Some("VMwareVMware".into()),
            firmware: FirmwareIdentity {
                manufacturer: Some("VMware, Inc.".into()),
                product: Some("VMware Virtual Platform".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(classify(&facts).kind, EnvironmentKind::VirtualGuest);
    }

    #[test]
    fn leftover_vbox_nic_alone_is_inconclusive() {
        let facts = EnvironmentFacts {
            mac_vm_vendors: vec!["VirtualBox".into()],
            firmware: FirmwareIdentity {
                manufacturer: Some("Lenovo".into()),
                product: Some("ThinkPad T14".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(classify(&facts).kind, EnvironmentKind::Inconclusive);
    }

    #[test]
    fn bare_metal() {
        let facts = EnvironmentFacts {
            firmware: FirmwareIdentity {
                manufacturer: Some("Framework".into()),
                product: Some("Laptop 13".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(classify(&facts).kind, EnvironmentKind::Physical);
    }

    #[test]
    fn parses_type1_strings() {
        // Minimal SMBIOS: type 1 with two strings.
        let mut table = vec![1u8, 8, 0, 0, 1, 2, 0, 0];
        table.extend_from_slice(b"VMware, Inc.\0VMware7,1\0\0");
        table.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
        let id = parse_smbios_table(&table);
        assert_eq!(id.manufacturer.as_deref(), Some("VMware, Inc."));
        assert_eq!(id.product.as_deref(), Some("VMware7,1"));
    }
}
