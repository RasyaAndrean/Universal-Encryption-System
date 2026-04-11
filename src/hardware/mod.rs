use sha2::{Digest, Sha256};
use sysinfo::{CpuExt, DiskExt, NetworkExt, System, SystemExt};

#[derive(Debug, thiserror::Error)]
pub enum HardwareError {
    #[error("Failed to get system information: {0}")]
    SystemInfo(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceFingerprint {
    pub cpu_id: String,
    pub hostname: String,
    pub os_name: String,
    pub machine_id: String,
}

impl DeviceFingerprint {
    pub fn new() -> Result<Self, HardwareError> {
        let mut system = System::new_all();
        system.refresh_all();

        let cpu_id = system
            .cpus()
            .first()
            .map(|cpu| cpu.vendor_id().to_string())
            .ok_or_else(|| HardwareError::SystemInfo("No CPU found".to_string()))?;

        let hostname = system
            .host_name()
            .ok_or_else(|| HardwareError::SystemInfo("Hostname not available".to_string()))?;

        let os_name = system
            .long_os_version()
            .ok_or_else(|| HardwareError::SystemInfo("OS version not available".to_string()))?;

        let machine_id = Self::compute_machine_id(&cpu_id, &hostname, &system)?;

        Ok(DeviceFingerprint {
            cpu_id,
            hostname,
            os_name,
            machine_id,
        })
    }

    /// Builds a deterministic machine identifier from stable hardware properties.
    fn compute_machine_id(
        cpu_id: &str,
        hostname: &str,
        system: &System,
    ) -> Result<String, HardwareError> {
        let mut hasher = Sha256::new();
        hasher.update(cpu_id.as_bytes());
        hasher.update(hostname.as_bytes());

        let total_mem = system.total_memory();
        hasher.update(total_mem.to_le_bytes());

        let cpu_count = system.cpus().len() as u64;
        hasher.update(cpu_count.to_le_bytes());

        // Include MAC addresses for additional uniqueness
        let networks = system.networks();
        let mut macs: Vec<String> = Vec::new();
        for (_name, data) in networks {
            let mac = data.mac_address().to_string();
            if mac != "00:00:00:00:00:00" && !mac.is_empty() {
                macs.push(mac);
            }
        }
        macs.sort();
        for mac in &macs {
            hasher.update(mac.as_bytes());
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    pub fn from_string(s: &str) -> Result<Self, HardwareError> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err(HardwareError::SystemInfo(
                "Invalid fingerprint format".to_string(),
            ));
        }

        Ok(DeviceFingerprint {
            cpu_id: parts[0].to_string(),
            hostname: parts[1].to_string(),
            os_name: parts[2].to_string(),
            machine_id: parts[3].to_string(),
        })
    }
}

impl std::fmt::Display for DeviceFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.cpu_id, self.hostname, self.os_name, self.machine_id
        )
    }
}

pub fn get_device_fingerprint() -> Result<String, HardwareError> {
    let fingerprint = DeviceFingerprint::new()?;
    Ok(fingerprint.to_string())
}

pub fn validate_device_fingerprint(stored: &str) -> Result<bool, HardwareError> {
    let current = get_device_fingerprint()?;
    Ok(current == stored)
}

pub fn get_mac_addresses() -> Result<Vec<String>, HardwareError> {
    let system = System::new_all();
    let networks = system.networks();

    let mut mac_addresses = Vec::new();
    for (_interface_name, network_data) in networks {
        let mac = network_data.mac_address().to_string();
        if mac != "00:00:00:00:00:00" && !mac.is_empty() {
            mac_addresses.push(mac);
        }
    }

    Ok(mac_addresses)
}

/// Retrieve a disk identifier. Uses a hash of the disk name, mount point,
/// and total size as a stable identifier since raw serial numbers require
/// elevated privileges on most platforms.
pub fn get_disk_serial() -> Result<String, HardwareError> {
    let system = System::new_all();
    let disks = system.disks();

    let disk = disks
        .first()
        .ok_or_else(|| HardwareError::SystemInfo("No disk found".to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(disk.name().to_string_lossy().as_bytes());
    hasher.update(disk.mount_point().to_string_lossy().as_bytes());
    hasher.update(disk.total_space().to_le_bytes());

    let result = hasher.finalize();
    Ok(format!("DISK_{}", hex::encode(&result[..8])))
}
