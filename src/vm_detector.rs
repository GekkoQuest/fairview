use sysinfo::{System, Networks};
use raw_cpuid::CpuId;
use serde::Serialize;

pub struct VmDetector;

#[derive(Debug, Clone, Serialize)]
pub struct VmCheckResult {
    pub is_vm: bool,
    pub reasons: Vec<String>,
    pub confidence_score: f64,
}

impl VmDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self) -> VmCheckResult {
        let mut reasons = Vec::new();
        let mut confidence: f64 = 0.0;

        let cpuid = CpuId::new();
        let hypervisor_present = cpuid.get_feature_info()
            .map(|info| info.has_hypervisor())
            .unwrap_or(false);

        if hypervisor_present {
            confidence += 0.1; 
            reasons.push("CPUID hypervisor bit set".to_string());

            if let Some(hv_info) = cpuid.get_hypervisor_info() {
                 let vendor_enum = hv_info.identify();
                 let vendor_str = format!("{:?}", vendor_enum);
                 
                 if vendor_str.contains("HyperV") || vendor_str.contains("Microsoft") {
                     // Microsoft Hyper-V is inconclusive on its own (could be Host or Guest)
                     // We only add a small amount of risk; we need DMI/MAC to confirm.
                     confidence += 0.2; 
                     reasons.push(format!("Hypervisor Vendor: {} (Ambiguous - could be WSL2/Host)", vendor_str));
                 } else {
                     confidence += 0.8; 
                     reasons.push(format!("Hypervisor Vendor detected: {}", vendor_str));
                 }
            }
        }

        if let Some(name) = System::name() {
            let name_lower = name.to_lowercase();
            if self.is_suspicious_system_string(&name_lower) {
                reasons.push(format!("Suspicious System Model: {}", name));
                confidence += 0.6; 
            }
        }
        
        if let Some(host_name) = System::host_name() {
             let host_lower = host_name.to_lowercase();
             if host_lower.contains("virtual") || host_lower.contains("qemu") {
                 reasons.push(format!("Suspicious Hostname: {}", host_name));
                 confidence += 0.3;
             }
        }

        let mac_reasons = self.check_mac_addresses();
        if !mac_reasons.is_empty() {
            confidence += 0.5;
            reasons.extend(mac_reasons);
        }

        let is_vm = confidence > 0.7; 

        VmCheckResult {
            is_vm,
            reasons,
            confidence_score: confidence.min(1.0),
        }
    }

    fn is_suspicious_system_string(&self, s: &str) -> bool {
        let patterns = [
            "virtualbox", "vmware", "qemu", "kvm", 
            "oracle", "innotek", "xen", "bochs", 
            "parallels", "bhyve", 
            "virtual machine", "hvm dom" 
        ];
        patterns.iter().any(|p| s.contains(p))
    }

    fn check_mac_addresses(&self) -> Vec<String> {
        let mut detected = Vec::new();
        let networks = Networks::new_with_refreshed_list();
        
        let vm_ouis = [
            ("00:05:69", "VMware"), ("00:0C:29", "VMware"), ("00:1C:14", "VMware"), ("00:50:56", "VMware"),
            ("08:00:27", "VirtualBox"),
            ("52:54:00", "QEMU/KVM"),
            ("00:16:3E", "Xen"),
            ("00:1C:42", "Parallels"),
        ];

        for (interface_name, data) in &networks {
            let mac = data.mac_address().to_string().to_uppercase();
            for (prefix, vendor) in vm_ouis.iter() {
                if mac.starts_with(prefix) {
                    detected.push(format!("VM Network Adapter ({}) detected on {}", vendor, interface_name));
                }
            }
        }
        detected
    }
}