use crate::layers::behavior::BehaviorEventKind;

#[derive(Debug, Clone)]
pub struct SequenceSignature {
    pub name: String,
    pub pattern: Vec<BehaviorEventKind>,
    /// Tolerant signatures are matched in order inside a bounded window,
    /// tolerating interleaved unrelated events. They represent multi-step
    /// correlation rather than the contiguous evidence of strict signatures,
    /// so fusion treats them as suspicious unless corroborated.
    pub tolerant: bool,
}

#[derive(Debug, Clone)]
pub struct SequenceMatch {
    pub signature_name: String,
    pub matched_at: usize,
    pub tolerant: bool,
}

pub struct SequenceMatcher {
    signatures: Vec<SequenceSignature>,
}

impl SequenceMatcher {
    pub fn new(signatures: Vec<SequenceSignature>) -> Self {
        Self { signatures }
    }

    /// Full signature table, used by tests and the attack-chain payload to
    /// render chain steps without duplicating the table.
    pub fn signatures(&self) -> &[SequenceSignature] {
        &self.signatures
    }
}

impl Default for SequenceMatcher {
    fn default() -> Self {
        let signatures = vec![
            SequenceSignature {
                name: "process_injection_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::SuspiciousApiCall,
                    BehaviorEventKind::ProcessInject,
                ],
            },
            SequenceSignature {
                name: "persistence_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::RegistryWrite,
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::ProcessCreate,
                ],
            },
            SequenceSignature {
                name: "network_dropper".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::NetworkConnect,
                ],
            },
            SequenceSignature {
                name: "credential_theft_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::CredentialAccess,
                    BehaviorEventKind::NetworkConnect,
                ],
            },
            SequenceSignature {
                name: "silverfox_attack_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::SuspiciousApiCall,
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::RegistryWrite,
                    BehaviorEventKind::NetworkConnect,
                ],
            },
            SequenceSignature {
                name: "silverfox_ctf_inject_selfdelete".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::RegistryWrite,
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::SuspiciousApiCall,
                    BehaviorEventKind::FileWrite,
                ],
            },
            SequenceSignature {
                name: "ransomware_impact_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::BackupDeletion,
                    BehaviorEventKind::RansomwareEncryption,
                ],
            },
            SequenceSignature {
                name: "service_persistence_chain".into(),
                tolerant: false,
                pattern: vec![
                    BehaviorEventKind::ServiceTampering,
                    BehaviorEventKind::SuspiciousPersistence,
                    BehaviorEventKind::ProcessCreate,
                ],
            },
            // Tolerant multi-step chains associate a loader/execution step
            // with later persistence or exfiltration. Missing or reordered
            // individual events no longer breaks the whole signature.
            SequenceSignature {
                name: "loader_module_codeexec_chain".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::SuspiciousModuleLoad,
                    BehaviorEventKind::SuspiciousApiCall,
                    BehaviorEventKind::ProcessInject,
                ],
            },
            SequenceSignature {
                name: "credential_exfil_chain".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::CredentialAccess,
                    BehaviorEventKind::SuspiciousApiCall,
                    BehaviorEventKind::NetworkConnect,
                ],
            },
            SequenceSignature {
                name: "dropper_c2_persist_chain".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::ProcessCreate,
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::NetworkConnect,
                    BehaviorEventKind::RegistryWrite,
                ],
            },
            SequenceSignature {
                name: "implant_post_injection_persistence".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::ProcessInject,
                    BehaviorEventKind::FileWrite,
                    BehaviorEventKind::SuspiciousPersistence,
                ],
            },
            SequenceSignature {
                name: "module_abuse_service_persist".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::SuspiciousModuleLoad,
                    BehaviorEventKind::ServiceTampering,
                    BehaviorEventKind::ProcessCreate,
                ],
            },
            SequenceSignature {
                name: "inject_browser_exfil_chain".into(),
                tolerant: true,
                pattern: vec![
                    BehaviorEventKind::ProcessInject,
                    BehaviorEventKind::CredentialAccess,
                    BehaviorEventKind::NetworkConnect,
                ],
            },
        ];
        Self { signatures }
    }
}

impl SequenceMatcher {
    pub fn match_sequence(&self, events: &[BehaviorEventKind]) -> Vec<SequenceMatch> {
        let mut matches = Vec::new();
        for signature in &self.signatures {
            if signature.tolerant {
                continue;
            }
            if let Some(idx) = find_subsequence(events, &signature.pattern) {
                matches.push(SequenceMatch {
                    signature_name: signature.name.clone(),
                    matched_at: idx,
                    tolerant: false,
                });
            }
        }
        matches
    }

    /// Match tolerant signatures in order within a bounded window. Each
    /// signature element may be separated by up to `max_gap` unrelated events,
    /// and the whole match must span at most `max_span` events.
    pub fn match_sequence_tolerant(
        &self,
        events: &[BehaviorEventKind],
        max_gap: usize,
        max_span: usize,
    ) -> Vec<SequenceMatch> {
        let mut matches = Vec::new();
        for signature in &self.signatures {
            if !signature.tolerant {
                continue;
            }
            if let Some(idx) = find_tolerant_subsequence(events, &signature.pattern, max_gap, max_span)
            {
                matches.push(SequenceMatch {
                    signature_name: signature.name.clone(),
                    matched_at: idx,
                    tolerant: true,
                });
            }
        }
        matches
    }
}

fn find_subsequence(haystack: &[BehaviorEventKind], needle: &[BehaviorEventKind]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    for start in 0..=haystack.len() - needle.len() {
        if haystack[start..start + needle.len()] == *needle {
            return Some(start);
        }
    }
    None
}

/// In-order subsequence search tolerating unrelated events between pattern
    /// elements. `max_gap` bounds unrelated events between consecutive pattern
    /// elements; `max_span` bounds the total window from first to last match.
    fn find_tolerant_subsequence(
        haystack: &[BehaviorEventKind],
        needle: &[BehaviorEventKind],
        max_gap: usize,
        max_span: usize,
    ) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }

        for start in 0..haystack.len() {
            if haystack[start] != needle[0] {
                continue;
            }
            let mut needle_index = 1;
            let mut gap_remaining = max_gap;
            for cursor in start + 1..haystack.len() {
                if cursor - start > max_span {
                    break;
                }
                if haystack[cursor] == needle[needle_index] {
                    needle_index += 1;
                    gap_remaining = max_gap;
                    if needle_index == needle.len() {
                        return Some(start);
                    }
                } else if gap_remaining == 0 {
                    break;
                } else {
                    gap_remaining -= 1;
                }
            }
        }
        None
    }

    /// Whether a chain name belongs to the gap-tolerant signature set. Used by
    /// the scan response to mark tolerant steps that were correlation-only.
    pub fn is_tolerant_chain(name: &str) -> bool {
        matches!(
            name,
            "loader_module_codeexec_chain"
                | "credential_exfil_chain"
                | "dropper_c2_persist_chain"
                | "implant_post_injection_persistence"
                | "module_abuse_service_persist"
                | "inject_browser_exfil_chain"
        )
    }

    /// Human-readable step labels for a known chain name, in chain order.
    /// Mirrors the default signature table used by [`SequenceMatcher::default`];
    /// `tests::chain_step_labels_match_default_signatures` keeps the two in
    /// sync so a rename cannot silently break the attack-chain payload.
    pub fn chain_step_labels(name: &str) -> Option<Vec<&'static str>> {
        use BehaviorEventKind as K;
        let kinds: &[K] = match name {
            "process_injection_chain" => &[K::ProcessCreate, K::SuspiciousApiCall, K::ProcessInject],
            "persistence_chain" => &[K::RegistryWrite, K::FileWrite, K::ProcessCreate],
            "network_dropper" => &[K::FileWrite, K::NetworkConnect],
            "credential_theft_chain" => {
                &[K::ProcessCreate, K::CredentialAccess, K::NetworkConnect]
            }
            "silverfox_attack_chain" => &[
                K::ProcessCreate,
                K::SuspiciousApiCall,
                K::FileWrite,
                K::RegistryWrite,
                K::NetworkConnect,
            ],
            "silverfox_ctf_inject_selfdelete" => &[
                K::FileWrite,
                K::RegistryWrite,
                K::ProcessCreate,
                K::SuspiciousApiCall,
                K::FileWrite,
            ],
            "ransomware_impact_chain" => {
                &[K::FileWrite, K::BackupDeletion, K::RansomwareEncryption]
            }
            "service_persistence_chain" => {
                &[K::ServiceTampering, K::SuspiciousPersistence, K::ProcessCreate]
            }
            "loader_module_codeexec_chain" => &[
                K::ProcessCreate,
                K::SuspiciousModuleLoad,
                K::SuspiciousApiCall,
                K::ProcessInject,
            ],
            "credential_exfil_chain" => {
                &[K::CredentialAccess, K::SuspiciousApiCall, K::NetworkConnect]
            }
            "dropper_c2_persist_chain" => &[
                K::ProcessCreate,
                K::FileWrite,
                K::NetworkConnect,
                K::RegistryWrite,
            ],
            "implant_post_injection_persistence" => {
                &[K::ProcessInject, K::FileWrite, K::SuspiciousPersistence]
            }
            "module_abuse_service_persist" => &[
                K::SuspiciousModuleLoad,
                K::ServiceTampering,
                K::ProcessCreate,
            ],
            "inject_browser_exfil_chain" => {
                &[K::ProcessInject, K::CredentialAccess, K::NetworkConnect]
            }
            _ => return None,
        };
        Some(kinds.iter().map(|kind| kind.as_str()).collect())
    }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::behavior::BehaviorEventKind;

    #[test]
    fn test_sequence_matcher_default() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::RegistryWrite,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::ProcessCreate,
        ];
        let matches = matcher.match_sequence(&events);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].signature_name, "persistence_chain");
    }

    #[test]
    fn chain_step_labels_match_default_signatures() {
        let matcher = SequenceMatcher::default();
        for signature in matcher.signatures() {
            let labels = chain_step_labels(&signature.name).unwrap_or_else(|| {
                panic!(
                    "chain_step_labels missing entry for default signature {}",
                    signature.name
                )
            });
            let expected: Vec<String> = signature
                .pattern
                .iter()
                .map(|kind| kind.as_str().to_string())
                .collect();
            assert_eq!(labels, expected, "steps drifted for {}", signature.name);
            let tolerant = matcher
                .signatures()
                .iter()
                .any(|s| s.name == signature.name && s.tolerant);
            assert_eq!(
                tolerant,
                super::is_tolerant_chain(&signature.name),
                "tolerant flag drifted for {}",
                signature.name
            );
        }
    }

    #[test]
    fn matches_high_confidence_impact_chains() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::BackupDeletion,
            BehaviorEventKind::RansomwareEncryption,
        ];
        let matches = matcher.match_sequence(&events);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].signature_name, "ransomware_impact_chain");
    }

    #[test]
    fn matches_silverfox_loader_chain() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::ProcessCreate,
            BehaviorEventKind::SuspiciousApiCall,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::RegistryWrite,
            BehaviorEventKind::NetworkConnect,
        ];
        let matches = matcher.match_sequence(&events);
        assert!(matches
            .iter()
            .any(|item| item.signature_name == "silverfox_attack_chain"));
    }

    #[test]
    fn matches_silverfox_ctf_selfdelete_chain() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::RegistryWrite,
            BehaviorEventKind::ProcessCreate,
            BehaviorEventKind::SuspiciousApiCall,
            BehaviorEventKind::FileWrite,
        ];
        let matches = matcher.match_sequence(&events);
        assert!(matches
            .iter()
            .any(|item| item.signature_name == "silverfox_ctf_inject_selfdelete"));
    }

    #[test]
    fn strict_matcher_ignores_tolerant_signatures() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::ProcessCreate,
            BehaviorEventKind::SuspiciousModuleLoad,
            BehaviorEventKind::SuspiciousApiCall,
            BehaviorEventKind::ProcessInject,
        ];
        let matches = matcher.match_sequence(&events);
        assert!(!matches
            .iter()
            .any(|item| item.signature_name == "loader_module_codeexec_chain"));
    }

    #[test]
    fn tolerant_matcher_tolerates_interspersed_noise() {
        let matcher = SequenceMatcher::default();
        let events = vec![
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::ProcessCreate,
            BehaviorEventKind::DnsQuery,
            BehaviorEventKind::ProcessInject,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::RegistryWrite,
            BehaviorEventKind::SuspiciousPersistence,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::SuspiciousApiCall,
            BehaviorEventKind::ProcessInject,
        ];
        let tolerant = matcher.match_sequence_tolerant(&events, 3, 16);
        assert!(tolerant
            .iter()
            .any(|item| item.signature_name == "implant_post_injection_persistence"));
        assert!(!tolerant
            .iter()
            .any(|item| item.signature_name == "process_injection_chain"));
        // Tolerant-only signatures never surface through the strict API.
        let strict = matcher.match_sequence(&events);
        assert!(!strict
            .iter()
            .any(|item| item.signature_name == "implant_post_injection_persistence"));
    }

    #[test]
    fn tolerant_matching_respects_gap_limit() {
        let matcher = SequenceMatcher::default();
        // Three unrelated events between CredentialAccess and NetworkConnect
        // exceed the max gap, so the chain must not match.
        let events = vec![
            BehaviorEventKind::CredentialAccess,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::FileWrite,
            BehaviorEventKind::NetworkConnect,
        ];
        let tolerant = matcher.match_sequence_tolerant(&events, 2, 12);
        assert!(!tolerant
            .iter()
            .any(|item| item.signature_name == "credential_exfil_chain"));
    }
}
