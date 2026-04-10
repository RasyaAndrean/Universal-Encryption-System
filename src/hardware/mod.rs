use sysinfo::{System, CpuExt, SystemExt};
use uuid::Uuid;
use std::net::{TcpStream, IpAddr};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub boot_time: u64,
    pub uuid: String,
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
        
        let boot_time = system.boot_time();
        
        let uuid = Uuid::new_v4().to_string();
        
        Ok(DeviceFingerprint {
            cpu_id,
            hostname,
            os_name,
            boot_time,
            uuid,
        })
    }
    
    pub fn to_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.cpu_id, self.hostname, self.os_name, self.boot_time, self.uuid
        )
    }
    
    pub fn from_string(s: &str) -> Result<Self, HardwareError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 5 {
            return Err(HardwareError::SystemInfo("Invalid fingerprint format".to_string()));
        }
        
        Ok(DeviceFingerprint {
            cpu_id: parts[0].to_string(),
            hostname: parts[1].to_string(),
            os_name: parts[2].to_string(),
            boot_time: parts[3].parse().map_err(|_| HardwareError::SystemInfo("Invalid boot time".to_string()))?,
            uuid: parts[4].to_string(),
        })
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

// Additional hardware identification methods
pub fn get_mac_addresses() -> Result<Vec<String>, HardwareError> {
    let system = System::new_all();
    let networks = system.networks();
    
    let mut mac_addresses = Vec::new();
    for (_interface_name, network_data) in networks {
        let mac = network_data.mac_address();
        if !mac.is_empty() {
            mac_addresses.push(mac.to_string());
        }
    }
    
    Ok(mac_addresses)
}

pub fn get_disk_serial() -> Result<String, HardwareError> {
    // This is a simplified implementation
    // In practice, you'd need platform-specific code or external tools
    let system = System::new_all();
    let disks = system.disks();
    
    disks
        .first()
        .map(|disk| {
            let disk_name = disk.name().to_string_lossy();
            format!("DISK_SERIAL_{}", disk_name)
        })
        .ok_or_else(|| HardwareError::SystemInfo("No disk found".to_string()))
}