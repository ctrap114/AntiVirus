//! Process-wide runtime switches for the two real-time protection layers.
//!
//! The settings are intentionally separate from the driver protocol.  This
//! lets the user-mode R3 layer keep working when the optional driver is not
//! installed, while the UI can still report the actual effective state.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static R3_ENABLED: AtomicBool = AtomicBool::new(true);
static DRIVER_ENABLED: AtomicBool = AtomicBool::new(false);
// Every protection-policy change gets a new epoch. Scan-cache entries carry
// the epoch at which they were produced, so a policy update cannot leave an
// older clean verdict reusable.
static POLICY_EPOCH: AtomicU64 = AtomicU64::new(1);

pub fn set_modes(r3_enabled: bool, driver_enabled: bool) {
    R3_ENABLED.store(r3_enabled, Ordering::Release);
    DRIVER_ENABLED.store(driver_enabled, Ordering::Release);
    POLICY_EPOCH.fetch_add(1, Ordering::AcqRel);
}

pub fn set_r3_enabled(enabled: bool) {
    R3_ENABLED.store(enabled, Ordering::Release);
    POLICY_EPOCH.fetch_add(1, Ordering::AcqRel);
}

pub fn set_driver_enabled(enabled: bool) {
    DRIVER_ENABLED.store(enabled, Ordering::Release);
    POLICY_EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// Return the current protection-policy epoch for security-sensitive cache
/// validation and event correlation.
pub fn policy_epoch() -> u64 {
    POLICY_EPOCH.load(Ordering::Acquire)
}

pub fn r3_enabled() -> bool {
    R3_ENABLED.load(Ordering::Acquire)
}

pub fn driver_enabled() -> bool {
    DRIVER_ENABLED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_modes_are_independent() {
        set_modes(true, false);
        assert!(r3_enabled());
        assert!(!driver_enabled());
        set_driver_enabled(true);
        assert!(r3_enabled());
        assert!(driver_enabled());
        set_r3_enabled(false);
        assert!(!r3_enabled());
        set_modes(true, false);
    }
}
