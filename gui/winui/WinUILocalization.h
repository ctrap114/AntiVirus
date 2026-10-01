#pragma once

#include <string>

namespace everbloom::gui {

enum class UiLanguage {
    English,
    SimplifiedChinese,
    TraditionalChinese,
    Japanese,
    Spanish,
};

struct UiStrings {
    // Branding and connection state.
    std::wstring app_subtitle{L"Endpoint security console"};
    std::wstring engine_connecting{L"Engine connecting..."};
    std::wstring engine_connected{L"Engine connected"};
    std::wstring engine_disconnected{L"Engine disconnected"};
    std::wstring engine_ready{L"Scanning engine is ready"};
    std::wstring engine_waiting{L"Waiting for scanning engine"};
    std::wstring ipc_connected{L"Engine IPC connected."};
    std::wstring ipc_disconnected{L"Engine IPC disconnected."};
    std::wstring engine_error_prefix{L"Engine error: "};
    std::wstring scan_cancel{L"Cancel scan"};
    std::wstring scan_cancelled{L"Scan cancelled"};
    std::wstring scan_completed{L"Scan completed"};
    std::wstring scanning_prefix{L"Scanning: "};
    std::wstring scan_progress_error_prefix{L"Scan progress error: "};
    std::wstring scan_batch_completed{L"Scan batch completed."};
    std::wstring malicious_result{L"malicious result"};
    std::wstring threat_prefix{L"Threat: "};
    std::wstring scan_error_prefix{L"Scan error: "};
    std::wstring config_reload_success{L"Configuration reload succeeded: "};
    std::wstring config_reload_failure{L"Configuration reload failed: "};

    // Navigation and dashboard.
    std::wstring appearance{L"Appearance"};
    std::wstring workspace{L"Workspace"};
    std::wstring dashboard{L"Dashboard"};
    std::wstring dashboard_header{L"Security Overview"};
    std::wstring dashboard_subtitle{L"Native WinUI controls for scanning, protection, threats, activity, settings, and updates."};
    std::wstring starting_bridge{L"Starting engine bridge..."};
    std::wstring files_processed{L"Files processed"};
    std::wstring threats{L"Threats"};
    std::wstring errors{L"Errors"};
    std::wstring overview_description{L"The WinUI client starts the local Rust engine, connects over a per-session named pipe, and keeps the kernel policy boundary outside the GUI process."};
    std::wstring protection_surface{L"Protection surface"};
    std::wstring ready{L"Ready"};
    std::wstring threats_this_session{L"Threats this session"};
    std::wstring engine_errors{L"Engine errors"};
    std::wstring recent_activity{L"Recent activity"};
    std::wstring application_started{L"WinUI application started."};
    std::wstring endpoint_prepared{L"Per-session engine endpoint prepared."};
    std::wstring engine_startup_prefix{L"Engine startup: "};

    // Scan.
    std::wstring scan{L"Scan"};
    std::wstring scan_subtitle{L"Run the same hash, YARA, heuristic, AI, and optional sandbox pipeline exposed by the Rust engine."};
    std::wstring path_placeholder{L"Folder or file path"};
    std::wstring yara{L"YARA"};
    std::wstring heuristic{L"Heuristic"};
    std::wstring ai{L"AI"};
    std::wstring sandbox{L"Sandbox"};
    std::wstring cloud_scan{L"Cloud scan (placeholder)"};
    std::wstring cloud_scan_description{L"Reserved for an authenticated cloud verdict; local scanning remains fully functional."};
    std::wstring cloud_placeholder_notice{L"Cloud service placeholder enabled. No file is uploaded; local engines remain authoritative."};
    std::wstring scan_progress_label{L"Progress"};
    std::wstring scan_elapsed_label{L"Elapsed"};
    std::wstring scan_files_label{L"Files"};
    std::wstring scan_stage_label{L"Stage"};
    std::wstring sandbox_analysis{L"Sandbox analysis"};
    std::wstring sandbox_status_label{L"Status"};
    std::wstring sandbox_snapshots_label{L"Snapshots"};
    std::wstring sandbox_candidates_label{L"PE candidates"};
    std::wstring sandbox_entry_points_label{L"Recovered entry points"};
    std::wstring sandbox_memory_label{L"Memory captured"};
    std::wstring scan_waiting_for_engine{L"Waiting for engine connection before starting scan..."};
    std::wstring scan_preparing{L"Preparing scan request..."};
    std::wstring scan_enumerating{L"Enumerating files..."};
    std::wstring no_scan{L"No scan is running."};
    std::wstring requested_suffix{L" requested..."};
    std::wstring quick_scan{L"Quick scan"};
    std::wstring full_scan{L"Full scan"};
    std::wstring custom_scan{L"Custom scan"};
    std::wstring scan_path{L"Scan path"};
    std::wstring quick_description{L"Quick scan covers Downloads and Desktop. Full scan uses the current user profile. Custom scan accepts files of any format or a folder."};
    std::wstring path_required{L"A scan path is required."};
    std::wstring custom_rejected{L"Custom scan rejected because the path is empty."};
    std::wstring pick_files_scan{L"Choose files to scan"};
    std::wstring pick_folder_scan{L"Choose folder to scan"};
    std::wstring background_image{L"Background image"};
    std::wstring choose_background{L"Choose background image"};
    std::wstring clear_background{L"Clear background image"};
    std::wstring accent_color{L"Accent color"};
    std::wstring context_menu{L"Explorer right-click scan"};
    std::wstring install_context_menu{L"Install right-click scan menu"};
    std::wstring remove_context_menu{L"Remove right-click scan menu"};
    std::wstring context_menu_installed{L"Right-click scan menu installed."};
    std::wstring context_menu_removed{L"Right-click scan menu removed."};

    // Protection.
    std::wstring protection{L"Protection"};
    std::wstring protection_subtitle{L"Review the user-mode bridge and the kernel policy contract without loading a driver from the GUI."};
    std::wstring realtime_protection{L"Real-time protection"};
    std::wstring r3_protection{L"R3 administrator protection"};
    std::wstring r3_protection_description{L"User-mode protection with optional administrator enforcement"};
    std::wstring driver_protection{L"Driver protection"};
    std::wstring driver_protection_description{L"Kernel callbacks for process, file, registry, MBR and network protection"};
    std::wstring driver_unavailable{L"Driver protection is unavailable or requires administrator access"};
    std::wstring paused{L"Paused"};
    std::wstring monitoring{L"Monitoring"};
    std::wstring protection_open_failed{L"Real-time protection could not open a monitored directory"};
    std::wstring protection_start_failed{L"Real-time protection could not start."};
    std::wstring protection_enabled{L"Real-time protection enabled"};
    std::wstring protection_paused{L"Real-time protection paused"};
    std::wstring monitoring_enabled{L"Real-time directory monitoring enabled."};
    std::wstring monitoring_paused{L"Real-time directory monitoring paused."};
    std::wstring kernel_policy{L"Kernel policy"};
    std::wstring kernel_description{L"Driver callback validation, process/file/network callbacks, rule matching, and rollback remain in the driver service boundary."};
    std::wstring profiles{L"Profiles: data/policy_rules.json and data/policy_rules.hpol"};
    std::wstring localized_rules{L"Localized rule aliases: process/file/network/block and 进程/文件/网络/阻断."};
    std::wstring realtime_intercept_title{L"Real-time protection blocked"};
    std::wstring realtime_intercept_notice{L"EverbloomSecurity detected behavior commonly associated with a trojan and paused the file action for your decision."};
    std::wstring intercept_type{L"Interception type"};
    std::wstring intercept_file{L"File interception"};
    std::wstring intercept_target{L"Target"};
    std::wstring remember_choice{L"Remember this choice"};
    std::wstring allow{L"Allow"};
    std::wstring block{L"Block"};
    std::wstring close{L"Close"};
    std::wstring realtime_block_requested{L"Block policy requested; enforcement depends on the loaded driver layer."};

    // Threats, activity and updates.
    std::wstring threats_subtitle{L"Malicious results and engine errors are collected here for this application session."};
    std::wstring scan_threats_detected{L"Detected threats"};
    std::wstring scan_threats_empty{L"No threats detected in the current scan."};
    std::wstring allow_selected_threats{L"Add selected to allowlist"};
    std::wstring clear_selected_threats{L"Quarantine selected threats"};
    std::wstring selected_threat_action_empty{L"No selected threats."};
    std::wstring selected_threats_allow_requested{L"Allow policy requested for selected threats: "};
    std::wstring selected_threats_clear_requested{L"Quarantine requested for selected threats: "};
    std::wstring quarantine{L"Quarantine"};
    std::wstring quarantine_empty{L"No quarantined items."};
    std::wstring restore_selected_quarantine{L"Restore selected"};
    std::wstring delete_selected_quarantine{L"Permanently delete selected"};
    std::wstring quarantine_action_empty{L"No selected quarantine items."};
    std::wstring restore_selected_quarantine_requested{L"Restore requested for quarantine items: "};
    std::wstring delete_selected_quarantine_requested{L"Permanent delete requested for quarantine items: "};
    std::wstring clear_threats{L"Clear threats"};
    std::wstring activity{L"Activity"};
    std::wstring activity_subtitle{L"A bounded event stream from the WinUI client and Rust engine."};
    std::wstring clear_activity{L"Clear activity"};
    std::wstring updates{L"Updates"};
    std::wstring updates_subtitle{L"Reload the local hash and threat-intelligence database through the engine IPC contract."};
    std::wstring reload_databases{L"Reload databases"};
    std::wstring database_reload_requested{L"Database reload requested."};
    std::wstring updates_description{L"The GUI does not write to the database directly. The engine validates and atomically replaces its in-memory matchers."};
    std::wstring import_hash_database{L"Import hash database"};
    std::wstring hash_database_import_description{L"Import CSV, TSV, JSON, JSONL, DAT, text, or SQLite hash databases into the running engine."};
    std::wstring hash_database_import_requested{L"Hash database import requested."};
    std::wstring ai_model_management{L"AI model management"};
    std::wstring import_ai_model{L"Import ONNX model"};
    std::wstring validate_ai_model{L"Validate ONNX model"};
    std::wstring ai_model_description{L"Import a validated ONNX model into the user model registry. Each model keeps its own feature-map sidecars."};
    std::wstring ai_model_import_requested{L"ONNX model import requested."};
    std::wstring ai_model_validation_requested{L"ONNX model validation requested."};
    std::wstring ai_model_validation_passed{L"ONNX model is compatible"};
    std::wstring ai_model_validation_failed{L"ONNX model is not compatible"};
    std::wstring ai_model_importing_validated{L"Validated ONNX model is being imported."};
    std::wstring ai_model_strategy{L"Aggregation strategy"};
    std::wstring strategy_weighted_mean{L"Weighted mean"};
    std::wstring strategy_max_risk{L"Max risk"};
    std::wstring strategy_majority_vote{L"Majority vote"};

    // AI training page.
    std::wstring ai_training{L"AI Training"};
    std::wstring ai_training_subtitle{
        L"Generate an inert synthetic corpus and train the local detector model."};
    std::wstring ai_training_description{
        L"Runs the engine trainer as a background process: it generates harmless "
        L"malware-looking PE samples (single-RET entry points, embedded safety "
        L"markers), compares a baseline model against a family-augmented one, and "
        L"exports the winner as ONNX. The trained model is offered for import when "
        L"the run completes."};
    std::wstring ai_training_start{L"Train on synthetic corpus"};
    std::wstring ai_training_cancel{L"Cancel training"};
    std::wstring ai_training_progress_label{L"Training progress"};
    std::wstring ai_training_status_idle{L"Idle. The engine keeps serving scans while training runs."};
    std::wstring ai_training_status_running{L"Training running..."};
    std::wstring ai_training_status_cancelled{L"Training cancelled."};
    std::wstring ai_training_completed_prefix{L"Training complete. Model exported: "};
    std::wstring ai_training_failed_prefix{L"Training failed: "};
    std::wstring ai_training_spawn_failed_prefix{L"Could not launch the trainer: "};
    std::wstring ai_training_import_requested{L"Validating trained model, import will follow if compatible."};

    // Settings and catalog names.
    std::wstring settings{L"Settings"};
    std::wstring settings_subtitle{L"WinUI-native appearance, language, engine switches, and runtime diagnostics."};
    std::wstring language{L"Language"};
    std::wstring scan_engine_switches{L"Scan engine switches"};
    std::wstring translucent_panels{L"Translucent panels"};
    std::wstring panel_transparency{L"Panel transparency"};
    std::wstring panel_transparency_description{L"0% is opaque; higher values reveal more of the background image."};
    std::wstring apply_transparency{L"Apply transparency"};
    std::wstring language_traditional_chinese{L"Traditional Chinese"};
    std::wstring start_with_windows{L"Start with Windows"};
    std::wstring notifications{L"Show threat notifications"};
    std::wstring runtime_diagnostics{L"Runtime diagnostics"};
    std::wstring ipc_endpoint_prefix{L"IPC endpoint: "};
    std::wstring not_configured{L"not configured"};
    std::wstring engine_launch_requested{L"Engine process: launch requested"};
    std::wstring engine_process_prefix{L"Engine process: "};
    std::wstring language_english{L"English"};
    std::wstring language_traditional{L"Traditional Chinese"};
    std::wstring language_chinese{L"简体中文"};
    std::wstring language_japanese{L"日本語"};
    std::wstring language_spanish{L"Español"};
    std::wstring style_fluent_light{L"Fluent Light"};
    std::wstring style_fluent_dark{L"Fluent Dark"};
    std::wstring style_aurora{L"Aurora"};
    std::wstring style_high_contrast{L"High Contrast"};

    // Attack chain visualization page: multi-step behavior correlation.
    std::wstring attack_chain{L"Attack Chains"};
    std::wstring attack_chain_header{L"Attack Chains"};
    std::wstring attack_chain_subtitle{
        L"Multi-step behavior chains matched in order or by bounded correlation "
        L"across process, file, registry, service and network activity."};
    std::wstring attack_chain_empty{L"No multi-step attack chains recorded yet."};
    std::wstring attack_chain_stage_intervene{L"Intervened"};
    std::wstring attack_chain_stage_correlate{L"Correlated"};
    std::wstring attack_chain_stage_observe{L"Observed"};
    std::wstring attack_chain_matched_strict{L"Strict match"};
    std::wstring attack_chain_matched_tolerant{L"Tolerant correlation"};
    std::wstring attack_chain_clear{L"Clear chains"};
    std::wstring attack_chain_step_file_write{L"Write File"};
    std::wstring attack_chain_step_registry_write{L"Write Registry"};
    std::wstring attack_chain_step_process_create{L"Create Process"};
    std::wstring attack_chain_step_network_connect{L"Connect Network"};
    std::wstring attack_chain_step_suspicious_api_call{L"Suspicious API Call"};
    std::wstring attack_chain_step_dns_query{L"DNS Query"};
    std::wstring attack_chain_step_process_inject{L"Process Injection"};
    std::wstring attack_chain_step_persistence_change{L"Persistence Change"};
    std::wstring attack_chain_step_credential_access{L"Credential Access"};
    std::wstring attack_chain_step_service_tampering{L"Service Tampering"};
    std::wstring attack_chain_step_backup_deletion{L"Backup Deletion"};
    std::wstring attack_chain_step_ransomware_encryption{L"Encryption"};
    std::wstring attack_chain_step_suspicious_persistence{L"Suspicious Persistence"};
    std::wstring attack_chain_step_suspicious_module_load{L"Anomalous Module Load"};

    // Window controls for the borderless caption strip.
    std::wstring window_minimize{L"Minimize"};
    std::wstring window_maximize{L"Maximize"};
    std::wstring window_restore{L"Restore"};
    std::wstring window_close{L"Close"};

    // Dashboard hero card.
    std::wstring protection_days{L"protected for"};
    std::wstring system_safe_status{L"System is secure"};
    std::wstring scan_history{L"Scan history"};
    std::wstring last_scan_prefix{L"Last scan: "};

    // Protection toggles (card-based).
    std::wstring protection_realtime{L"Real-time Protection"};
    std::wstring protection_driver_desc{L"Active defense provided by driver protection"};
    std::wstring protection_baseline{L"Baseline Protection"};
    std::wstring protection_baseline_desc{L"Local engine scans running programs (no driver needed)"};
    std::wstring protection_file{L"File Protection"};
    std::wstring protection_file_desc{L"Monitors file operations, blocks malicious file writes"};
    std::wstring protection_quiet_mode{L"Quiet Mode"};
    std::wstring protection_quiet_mode_desc{L"Auto-blocks threats without confirmation dialogs"};

    // Real-time threat dialog.
    std::wstring realtime_process_intercept{L"Process Interception"};
    std::wstring realtime_file_intercept{L"File Interception"};
    std::wstring realtime_allow{L"Allow"};
    std::wstring realtime_block{L"Block"};
    std::wstring realtime_seconds_suffix{L"s"};
    std::wstring realtime_detecting{L"Detecting threat, awaiting your decision"};
    std::wstring realtime_allow_desc{L"Allow this program to run"};
    std::wstring realtime_block_desc{L"Block and quarantine this program"};

    // Scan page cards.
    std::wstring scan_quick_title{L"Quick Scan"};
    std::wstring scan_quick_desc{L"Scans Downloads and Desktop"};
    std::wstring scan_full_title{L"Full Scan"};
    std::wstring scan_full_desc{L"Scans entire user profile"};
    std::wstring scan_custom_title{L"Custom Scan"};
    std::wstring scan_custom_desc{L"Scan any file or folder"};
    std::wstring scan_virus_title{L"Virus Scan"};
    std::wstring scan_virus_desc{L"Full threat system scan"};
    std::wstring scan_quarantine_title{L"Quarantine"};
    std::wstring scan_quarantine_desc{L"Manage quarantined threats"};

    // AI Training detailed progress.
    std::wstring training_epoch_label{L"Epoch"};
    std::wstring training_loss_label{L"Loss"};
    std::wstring training_accuracy_label{L"Accuracy"};
    std::wstring training_baseline_label{L"Baseline"};
    std::wstring training_augmented_label{L"Augmented"};
    std::wstring training_gain_label{L"Gain"};
    std::wstring training_selected_model{L"Selected model: "};
    std::wstring training_sample_count{L"Training samples"};
    std::wstring training_auto_stop{L"Auto-stop on plateau"};
    std::wstring training_pause{L"Pause"};
    std::wstring training_resume{L"Resume"};
    std::wstring training_status_paused{L"Training paused"};
    std::wstring training_comparison_title{L"Model Comparison"};
    std::wstring training_progress_bar{L"Training progress"};
    std::wstring training_time_elapsed{L"Elapsed"};
    std::wstring training_time_remaining{L"Remaining"};
    std::wstring training_stage_generating{L"Generating corpus"};
    std::wstring training_stage_loading{L"Loading features"};
    std::wstring training_stage_training{L"Training models"};
    std::wstring training_stage_exporting{L"Exporting ONNX"};

    // EDR attack chain visualization.
    std::wstring edr_behavior_chain{L"EDR Behavior Chain"};
    std::wstring edr_tree_legend{L"Legend"};
    std::wstring edr_high_risk{L"High-risk behavior"};
    std::wstring edr_medium_risk{L"Medium-risk behavior"};
    std::wstring edr_file_network{L"File/Network"};
    std::wstring edr_persistence{L"Persistence"};
    std::wstring edr_escalation{L"Escalation"};
    std::wstring edr_chain_detected{L"EDR has detected malicious behavior"};
    std::wstring edr_chain_blocked{L"This program has been terminated"};
};

UiStrings Strings(UiLanguage language);
std::wstring LanguageName(UiLanguage language);
UiLanguage DetectSystemLanguage();

} // namespace everbloom::gui
