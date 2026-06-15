use anyhow::{bail, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::time::Duration;

const SERVICE_TYPE: &str = "_nullseal._tcp.local.";
const INSTANCE_NAME: &str = "nullseal-share";

/// Broadcast a share URL on the local network via mDNS.
/// Returns a guard that unregisters the service when dropped.
pub fn broadcast(share_url: &str) -> Result<BroadcastGuard> {
    let mdns = ServiceDaemon::new()?;

    let host = format!("nullseal-{}.local.", std::process::id());
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        INSTANCE_NAME,
        &host,
        "",
        0,
        [("url", share_url)].as_slice(),
    )?;

    mdns.register(info)?;
    eprintln!("\x1b[1;34m📡\x1b[0m Broadcasting on local network…");

    Ok(BroadcastGuard { mdns })
}

/// Discover a nullseal share on the local network via mDNS.
/// Waits up to `timeout` for a broadcast, returns the share URL.
pub fn discover(timeout: Duration) -> Result<String> {
    let mdns = ServiceDaemon::new()?;
    let receiver = mdns.browse(SERVICE_TYPE)?;

    eprintln!("\x1b[1;34m📡\x1b[0m Searching for shares on local network…");

    let deadline = std::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            mdns.shutdown().ok();
            bail!("No share found on local network (timed out after {}s).", timeout.as_secs());
        }

        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(url) = info.get_property_val_str("url") {
                    eprintln!(
                        "\x1b[1;32m✓\x1b[0m Found share from {}",
                        info.get_hostname().trim_end_matches('.')
                    );
                    mdns.shutdown().ok();
                    return Ok(url.to_owned());
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
}

pub struct BroadcastGuard {
    mdns: ServiceDaemon,
}

impl Drop for BroadcastGuard {
    fn drop(&mut self) {
        self.mdns.shutdown().ok();
    }
}

/// Broadcast a local signaling address (ip:port) on the local network via mDNS.
pub fn broadcast_addr(ip: &str, port: u16) -> Result<BroadcastGuard> {
    let mdns = ServiceDaemon::new()?;

    let host = format!("nullseal-{}.local.", std::process::id());
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        INSTANCE_NAME,
        &host,
        "",
        0,
        [("ip", ip), ("port", &port.to_string())].as_slice(),
    )?;

    mdns.register(info)?;
    eprintln!("\x1b[1;34m📡\x1b[0m Broadcasting on local network…");

    Ok(BroadcastGuard { mdns })
}

/// Discover a local signaling address (ip:port) on the local network via mDNS.
pub fn discover_addr(timeout: Duration) -> Result<String> {
    let mdns = ServiceDaemon::new()?;
    let receiver = mdns.browse(SERVICE_TYPE)?;

    eprintln!("\x1b[1;34m📡\x1b[0m Searching for shares on local network…");

    let deadline = std::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            mdns.shutdown().ok();
            bail!("No share found on local network (timed out after {}s).", timeout.as_secs());
        }

        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let ip = info.get_property_val_str("ip");
                let port = info.get_property_val_str("port");
                if let (Some(ip), Some(port)) = (ip, port) {
                    eprintln!(
                        "\x1b[1;32m✓\x1b[0m Found share from {}",
                        info.get_hostname().trim_end_matches('.')
                    );
                    mdns.shutdown().ok();
                    return Ok(format!("{ip}:{port}"));
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
}
