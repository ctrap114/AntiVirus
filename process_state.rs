use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    Observed,
    Monitored,
    Suspicious,
    Instrumented,
    Malicious,
    Blocked,
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Observed => write!(f, "observed"),
            ProcessState::Monitored => write!(f, "monitored"),
            ProcessState::Suspicious => write!(f, "suspicious"),
            ProcessState::Instrumented => write!(f, "instrumented"),
            ProcessState::Malicious => write!(f, "malicious"),
            ProcessState::Blocked => write!(f, "blocked"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessStateTransition {
    pub pid: u32,
    pub previous: ProcessState,
    pub current: ProcessState,
    pub reason: String,
    pub timestamp_ms: u128,
}

#[derive(Default)]
pub struct ProcessStateMachine {
    states: HashMap<u32, ProcessState>,
    history: HashMap<u32, Vec<ProcessStateTransition>>,
}

impl ProcessStateMachine {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            history: HashMap::new(),
        }
    }

    pub fn update_state(
        &mut self,
        pid: u32,
        event_kind: crate::layers::behavior::BehaviorEventKind,
        detail: &str,
    ) -> ProcessStateTransition {
        let previous = self
            .states
            .get(&pid)
            .cloned()
            .unwrap_or(ProcessState::Observed);
        let mut current = previous.clone();
        let reason;

        match event_kind {
            crate::layers::behavior::BehaviorEventKind::ProcessCreate => {
                if previous == ProcessState::Observed {
                    current = ProcessState::Monitored;
                    reason = "process created".to_string();
                } else {
                    reason = "process created while already tracked".to_string();
                }
            }
            crate::layers::behavior::BehaviorEventKind::SuspiciousApiCall
            | crate::layers::behavior::BehaviorEventKind::ProcessInject => {
                current = ProcessState::Malicious;
                reason = format!("suspicious API: {}", detail);
            }
            crate::layers::behavior::BehaviorEventKind::RegistryWrite
            | crate::layers::behavior::BehaviorEventKind::PersistenceChange
            | crate::layers::behavior::BehaviorEventKind::SuspiciousPersistence
            | crate::layers::behavior::BehaviorEventKind::SuspiciousModuleLoad => {
                if previous == ProcessState::Suspicious {
                    current = ProcessState::Malicious;
                    reason = format!("persistence activity after suspicious behavior: {}", detail);
                } else {
                    current = ProcessState::Instrumented;
                    reason = format!("persistence activity: {}", detail);
                }
            }
            crate::layers::behavior::BehaviorEventKind::NetworkConnect => {
                if previous == ProcessState::Suspicious {
                    current = ProcessState::Malicious;
                    reason = format!("network contact after suspicious behavior: {}", detail);
                } else {
                    current = ProcessState::Monitored;
                    reason = format!("network connection: {}", detail);
                }
            }
            crate::layers::behavior::BehaviorEventKind::FileWrite => {
                if previous == ProcessState::Suspicious {
                    current = ProcessState::Malicious;
                    reason = format!("file write after suspicious behavior: {}", detail);
                } else {
                    current = ProcessState::Monitored;
                    reason = format!("file write: {}", detail);
                }
            }
            crate::layers::behavior::BehaviorEventKind::DnsQuery => {
                current = ProcessState::Monitored;
                reason = format!("dns query: {}", detail);
            }
            crate::layers::behavior::BehaviorEventKind::CredentialAccess
            | crate::layers::behavior::BehaviorEventKind::ServiceTampering
            | crate::layers::behavior::BehaviorEventKind::BackupDeletion
            | crate::layers::behavior::BehaviorEventKind::RansomwareEncryption => {
                current = ProcessState::Malicious;
                reason = format!("high-confidence malicious behavior: {}", detail);
            }
        }

        if current == ProcessState::Malicious {
            current = ProcessState::Blocked;
        }

        self.states.insert(pid, current.clone());
        let transition = ProcessStateTransition {
            pid,
            previous,
            current: current.clone(),
            reason,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default(),
        };

        self.history
            .entry(pid)
            .or_default()
            .push(transition.clone());
        transition
    }

    pub fn get_state(&self, pid: u32) -> Option<&ProcessState> {
        self.states.get(&pid)
    }

    pub fn history_for(&self, pid: u32) -> Option<&Vec<ProcessStateTransition>> {
        self.history.get(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::behavior::BehaviorEventKind;

    #[test]
    fn test_process_state_machine_transition() {
        let mut sm = ProcessStateMachine::new();
        let t1 = sm.update_state(123, BehaviorEventKind::ProcessCreate, "cmd.exe");
        assert_eq!(t1.previous, ProcessState::Observed);
        assert_eq!(t1.current, ProcessState::Monitored);

        let t2 = sm.update_state(
            123,
            BehaviorEventKind::SuspiciousApiCall,
            "CreateRemoteThread",
        );
        assert_eq!(t2.current, ProcessState::Blocked);
    }
}
