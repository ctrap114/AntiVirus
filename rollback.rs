use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub enum RollbackAction {
    DeleteFile(PathBuf),
    DeleteRegistryKey(String),
    KillProcess(u32),
    RestoreFile { path: PathBuf, backup_path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct RollbackExecutor {
    pub dry_run: bool,
    pub allow_restore: bool,
}

impl RollbackExecutor {
    pub fn new(dry_run: bool, allow_restore: bool) -> Self {
        Self {
            dry_run,
            allow_restore,
        }
    }

    pub fn execute(&self, record: &RollbackRecord) -> Vec<Result<String, String>> {
        record
            .actions
            .iter()
            .map(|action| self.execute_action(action))
            .collect()
    }

    fn execute_action(&self, action: &RollbackAction) -> Result<String, String> {
        if self.dry_run {
            return Ok(format!("dry-run: {:?}", action));
        }

        match action {
            RollbackAction::DeleteFile(path) => {
                if path.exists() {
                    if path.is_dir() {
                        fs::remove_dir_all(path).map_err(|e| e.to_string())?;
                    } else {
                        fs::remove_file(path).map_err(|e| e.to_string())?;
                    }
                    Ok(format!("deleted file: {:?}", path))
                } else {
                    Ok(format!("file not found: {:?}", path))
                }
            }
            RollbackAction::DeleteRegistryKey(key) => {
                #[cfg(target_family = "windows")]
                {
                    let output = Command::new("reg")
                        .arg("delete")
                        .arg(key)
                        .arg("/f")
                        .output()
                        .map_err(|e| e.to_string())?;
                    if output.status.success() {
                        Ok(format!("deleted registry key: {}", key))
                    } else {
                        Err(String::from_utf8_lossy(&output.stderr).into_owned())
                    }
                }
                #[cfg(not(target_family = "windows"))]
                {
                    Err("registry delete unsupported on this platform".to_string())
                }
            }
            RollbackAction::KillProcess(pid) => {
                #[cfg(target_family = "windows")]
                {
                    let output = Command::new("taskkill")
                        .arg("/PID")
                        .arg(pid.to_string())
                        .arg("/T")
                        .arg("/F")
                        .output()
                        .map_err(|e| e.to_string())?;
                    if output.status.success() {
                        Ok(format!("killed process: {}", pid))
                    } else {
                        Err(String::from_utf8_lossy(&output.stderr).into_owned())
                    }
                }
                #[cfg(target_family = "unix")]
                {
                    let output = Command::new("kill")
                        .arg("-9")
                        .arg(pid.to_string())
                        .output()
                        .map_err(|e| e.to_string())?;
                    if output.status.success() {
                        Ok(format!("killed process: {}", pid))
                    } else {
                        Err(String::from_utf8_lossy(&output.stderr).into_owned())
                    }
                }
                #[cfg(not(any(target_family = "windows", target_family = "unix")))]
                {
                    Err("process kill unsupported on this platform".to_string())
                }
            }
            RollbackAction::RestoreFile { path, backup_path } => {
                if !self.allow_restore {
                    return Err("restore disabled".to_string());
                }
                if !backup_path.exists() {
                    return Err(format!("backup missing: {:?}", backup_path));
                }
                fs::copy(backup_path, path).map_err(|e| e.to_string())?;
                Ok(format!("restored file: {:?} from {:?}", path, backup_path))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RollbackRecord {
    pub target_pid: Option<u32>,
    pub actions: Vec<RollbackAction>,
    pub reason: String,
}

pub struct RollbackPlanner;

impl RollbackPlanner {
    pub fn from_sandbox_report(report: &crate::sandbox::SandboxReport) -> RollbackRecord {
        let mut actions = Vec::new();

        for file in report.files_changed.iter() {
            actions.push(RollbackAction::DeleteFile(file.clone()));
        }

        for key in report.registry_writes.iter() {
            actions.push(RollbackAction::DeleteRegistryKey(key.clone()));
        }

        if let Some(pid) = report.target_pid {
            if report.timed_out || !report.network_connections.is_empty() {
                actions.push(RollbackAction::KillProcess(pid));
            }
        }

        let reason = if report.timed_out {
            "sandbox timed out, rollback actions may be required".to_string()
        } else if !report.registry_writes.is_empty() {
            "registry or file modifications detected during sandbox execution".to_string()
        } else if !report.files_changed.is_empty() {
            "file modifications detected during sandbox execution".to_string()
        } else {
            "no rollback actions detected".to_string()
        };

        RollbackRecord {
            target_pid: report.target_pid,
            actions,
            reason,
        }
    }
}

impl RollbackRecord {
    pub fn summary(&self) -> String {
        let action_count = self.actions.len();
        format!(
            "rollback record for pid={:?}, actions={} reason={}",
            self.target_pid, action_count, self.reason
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxReport;

    #[test]
    fn test_rollback_planner_creates_delete_actions() {
        let report = SandboxReport {
            target: std::path::PathBuf::from("C:/temp/test.exe"),
            exit_code: Some(0),
            target_pid: Some(999),
            files_changed: vec![std::path::PathBuf::from("C:/temp/out.txt")],
            registry_writes: vec!["HKCU\\Software\\Bad".to_string()],
            network_connections: vec![],
            processes: Vec::new(),
            api_calls: Vec::new(),
            timed_out: false,
            isolation_backend: "windows_sandbox".to_string(),
            isolation_verified: true,
            cleanup_verified: true,
            resource_limits: Vec::new(),
            unpacking: crate::layers::memory_snapshot::SandboxUnpackingReport::default(),
            duration_ms: 0,
        };

        let record = RollbackPlanner::from_sandbox_report(&report);
        assert!(record
            .actions
            .iter()
            .any(|a| matches!(a, RollbackAction::DeleteFile(_))));
        assert!(record
            .actions
            .iter()
            .any(|a| matches!(a, RollbackAction::DeleteRegistryKey(_))));
    }

    #[test]
    fn test_rollback_executor_dry_run() {
        let record = RollbackRecord {
            target_pid: Some(999),
            actions: vec![
                RollbackAction::DeleteFile(std::path::PathBuf::from("C:/temp/out.txt")),
                RollbackAction::KillProcess(999),
            ],
            reason: "test".to_string(),
        };

        let executor = RollbackExecutor::new(true, false);
        let results = executor.execute(&record);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
        assert!(results[0].as_ref().unwrap().starts_with("dry-run:"));
    }
}
