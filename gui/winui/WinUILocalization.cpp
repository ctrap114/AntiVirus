#include "WinUILocalization.h"

#include <array>

#include <windows.h>

namespace everbloom::gui {
namespace {

void Chinese(UiStrings& s) {
    s.app_subtitle = L"终端安全控制台";
    s.engine_connecting = L"引擎连接中...";
    s.engine_connected = L"引擎已连接";
    s.engine_disconnected = L"引擎已断开";
    s.engine_ready = L"扫描引擎已就绪";
    s.engine_waiting = L"等待扫描引擎";
    s.ipc_connected = L"引擎 IPC 已连接。";
    s.ipc_disconnected = L"引擎 IPC 已断开。";
    s.engine_error_prefix = L"引擎错误：";
    s.scan_cancel = L"取消扫描";
    s.scan_cancelled = L"扫描已取消";
    s.scan_completed = L"扫描完成";
    s.scanning_prefix = L"正在扫描：";
    s.scan_progress_error_prefix = L"扫描进度错误：";
    s.scan_batch_completed = L"扫描批次完成。";
    s.malicious_result = L"恶意结果";
    s.threat_prefix = L"威胁：";
    s.scan_error_prefix = L"扫描错误：";
    s.config_reload_success = L"配置重载成功：";
    s.config_reload_failure = L"配置重载失败：";
    s.appearance = L"外观";
    s.workspace = L"工作区";
    s.dashboard = L"概览";
    s.dashboard_header = L"安全概览";
    s.dashboard_subtitle = L"使用原生 WinUI 控件管理扫描、防护、威胁、活动、设置和更新。";
    s.starting_bridge = L"正在启动引擎桥接...";
    s.files_processed = L"已处理文件";
    s.threats = L"威胁";
    s.errors = L"错误";
    s.overview_description = L"WinUI 客户端启动本地 Rust 引擎，通过独立会话命名管道连接，并将内核策略边界保持在 GUI 进程之外。";
    s.protection_surface = L"防护面";
    s.ready = L"就绪";
    s.threats_this_session = L"本次会话威胁";
    s.engine_errors = L"引擎错误";
    s.recent_activity = L"最近活动";
    s.application_started = L"WinUI 应用已启动。";
    s.endpoint_prepared = L"已准备独立会话引擎端点。";
    s.engine_startup_prefix = L"引擎启动：";
    s.scan = L"扫描";
    s.scan_subtitle = L"运行 Rust 引擎提供的哈希、YARA、启发式、AI 和可选沙箱分析流程。";
    s.path_placeholder = L"文件夹或文件路径";
    s.heuristic = L"启发式";
    s.ai = L"AI";
    s.sandbox = L"沙箱";
    s.cloud_scan = L"云端检测（占位）";
    s.cloud_scan_description = L"预留给需要认证的云端判定；本地扫描流程不受影响。";
    s.cloud_placeholder_notice = L"云端服务占位已启用：不会上传文件，本地引擎仍负责最终判定。";
    s.scan_progress_label = L"进度";
    s.scan_elapsed_label = L"耗时";
    s.scan_files_label = L"文件";
    s.scan_stage_label = L"阶段";
    s.sandbox_analysis = L"沙箱分析";
    s.sandbox_status_label = L"状态";
    s.sandbox_snapshots_label = L"快照轮次";
    s.sandbox_candidates_label = L"PE候选";
    s.sandbox_entry_points_label = L"恢复入口点";
    s.sandbox_memory_label = L"已采集内存";
    s.scan_waiting_for_engine = L"正在等待引擎连接，连接后将开始扫描...";
    s.scan_preparing = L"正在准备扫描请求...";
    s.scan_enumerating = L"正在枚举文件...";
    s.no_scan = L"当前没有正在运行的扫描。";
    s.requested_suffix = L"已请求...";
    s.quick_scan = L"快速扫描";
    s.full_scan = L"完整扫描";
    s.custom_scan = L"自定义扫描";
    s.scan_path = L"扫描路径";
    s.quick_description = L"快速扫描覆盖下载和桌面目录；完整扫描使用当前用户目录；自定义扫描接受单个路径。";
    s.path_required = L"必须提供扫描路径。";
    s.custom_rejected = L"自定义扫描已拒绝，因为路径为空。";
    s.protection = L"防护";
    s.protection_subtitle = L"查看用户态桥接和内核策略契约；GUI 不直接加载驱动。";
    s.realtime_protection = L"实时防护";
    s.r3_protection = L"R3 管理员防护";
    s.r3_protection_description = L"用户态防护，可使用管理员权限拦截";
    s.driver_protection = L"驱动防护";
    s.driver_protection_description = L"进程、文件、注册表、MBR 和网络内核回调防护";
    s.driver_unavailable = L"驱动防护不可用或需要管理员权限";
    s.paused = L"已暂停";
    s.monitoring = L"监控中";
    s.protection_open_failed = L"实时防护无法打开监控目录";
    s.protection_start_failed = L"实时防护启动失败。";
    s.protection_enabled = L"实时防护已启用";
    s.protection_paused = L"实时防护已暂停";
    s.monitoring_enabled = L"实时目录监控已启用。";
    s.monitoring_paused = L"实时目录监控已暂停。";
    s.kernel_policy = L"内核策略";
    s.kernel_description = L"驱动回调验证、进程/文件/网络回调、规则匹配和回滚仍由驱动服务边界负责。";
    s.profiles = L"策略文件：data/policy_rules.json 和 data/policy_rules.hpol";
    s.localized_rules = L"规则别名支持：process/file/network/block 以及 进程/文件/网络/阻断。";
    s.realtime_intercept_title = L"实时防护拦截";
    s.realtime_intercept_notice = L"EverbloomSecurity 检测到疑似木马行为，已暂停该文件操作，请选择处理方式。";
    s.intercept_type = L"拦截类型";
    s.intercept_file = L"文件拦截";
    s.intercept_target = L"拦截目标";
    s.remember_choice = L"记住此选择";
    s.allow = L"允许";
    s.block = L"拦截";
    s.close = L"\u5173\u95ed";
    s.realtime_block_requested = L"已请求拦截策略；最终执行取决于驱动防护是否已加载。";
    s.threats_subtitle = L"恶意结果和引擎错误会收集到本次应用会话中。";
    s.clear_threats = L"清空威胁";
    s.activity = L"活动";
    s.activity_subtitle = L"来自 WinUI 客户端和 Rust 引擎的有限事件流。";
    s.clear_activity = L"清空活动";
    s.updates = L"更新";
    s.updates_subtitle = L"通过引擎 IPC 契约重载本地哈希库和威胁情报库。";
    s.reload_databases = L"重载数据库";
    s.database_reload_requested = L"已请求重载数据库。";
    s.updates_description = L"GUI 不直接写入数据库；引擎负责校验并原子替换内存匹配器。";
    s.ai_model_management = L"AI 模型管理";
    s.import_ai_model = L"导入 ONNX 模型";
    s.ai_model_description = L"导入经过校验的 ONNX 模型到用户模型注册表；每个模型可使用独立的特征映射文件。";
    s.ai_model_import_requested = L"已请求导入 ONNX 模型。";
    s.ai_model_strategy = L"模型聚合策略";
    s.strategy_weighted_mean = L"加权平均";
    s.strategy_max_risk = L"最大风险";
    s.strategy_majority_vote = L"多数投票";
    s.ai_training = L"AI 训练";
    s.ai_training_subtitle = L"生成无害合成语料并训练本地检测模型。";
    s.ai_training_description =
        L"以后台进程运行引擎训练器：自动生成无害的\"恶意外观\"PE 样本（单条 RET 入口、"
        L"内置安全标记），对比基线模型与家族增强模型，并将优胜者导出为 ONNX。训练完成后"
        L"可一键导入该模型；训练期间引擎照常提供扫描服务。";
    s.ai_training_start = L"使用合成语料开始训练";
    s.ai_training_cancel = L"取消训练";
    s.ai_training_progress_label = L"训练进度";
    s.ai_training_status_idle = L"空闲。训练运行期间引擎照常扫描。";
    s.ai_training_status_running = L"训练进行中...";
    s.ai_training_status_cancelled = L"已取消训练。";
    s.ai_training_completed_prefix = L"训练完成，已导出模型：";
    s.ai_training_failed_prefix = L"训练失败：";
    s.ai_training_spawn_failed_prefix = L"无法启动训练进程：";
    s.ai_training_import_requested = L"正在校验训练得到的模型，兼容时将自动导入。";
    s.settings = L"设置";
    s.settings_subtitle = L"配置 WinUI 外观、语言、引擎开关和运行时诊断。";
    s.language = L"语言";
    s.scan_engine_switches = L"扫描引擎开关";
    s.translucent_panels = L"半透明面板";
    s.panel_transparency = L"面板透明度";
    s.panel_transparency_description = L"0% 为完全不透明，数值越高越能显示背景图片。";
    s.apply_transparency = L"应用透明度";
    s.start_with_windows = L"随 Windows 启动";
    s.notifications = L"显示威胁通知";
    s.runtime_diagnostics = L"运行时诊断";
    s.ipc_endpoint_prefix = L"IPC 端点：";
    s.not_configured = L"未配置";
    s.engine_launch_requested = L"引擎进程：已请求启动";
    s.engine_process_prefix = L"引擎进程：";
    s.language_english = L"English";
    s.language_chinese = L"简体中文";
    s.language_traditional = L"繁體中文";
    s.language_traditional_chinese = L"繁體中文";
    s.language_japanese = L"日本語";
    s.language_spanish = L"Español";
    s.style_fluent_light = L"Fluent 浅色";
    s.style_fluent_dark = L"Fluent 深色";
    s.style_high_contrast = L"高对比度";
    s.pick_files_scan = L"\u9009\u62e9\u6587\u4ef6\u626b\u63cf";
    s.pick_folder_scan = L"\u9009\u62e9\u6587\u4ef6\u5939\u626b\u63cf";
    s.background_image = L"\u80cc\u666f\u56fe\u7247";
    s.choose_background = L"\u9009\u62e9\u80cc\u666f\u56fe\u7247";
    s.clear_background = L"\u6e05\u9664\u80cc\u666f\u56fe\u7247";
    s.accent_color = L"\u4e3b\u8272";
    s.context_menu = L"\u8d44\u6e90\u7ba1\u7406\u5668\u53f3\u952e\u626b\u63cf";
    s.install_context_menu = L"\u5b89\u88c5\u53f3\u952e\u626b\u63cf\u83dc\u5355";
    s.remove_context_menu = L"\u79fb\u9664\u53f3\u952e\u626b\u63cf\u83dc\u5355";
    s.context_menu_installed = L"\u53f3\u952e\u626b\u63cf\u83dc\u5355\u5df2\u5b89\u88c5\u3002";
    s.context_menu_removed = L"\u53f3\u952e\u626b\u63cf\u83dc\u5355\u5df2\u79fb\u9664\u3002";
    s.scan_threats_detected = L"检测到的威胁";
    s.scan_threats_empty = L"当前扫描尚未检测到威胁。";
    s.allow_selected_threats = L"将选中项加入白名单";
    s.clear_selected_threats = L"\u9694\u79bb\u9009\u4e2d\u5a01\u80c1";
    s.selected_threat_action_empty = L"未选择威胁项。";
    s.selected_threats_allow_requested = L"已为选中威胁提交放行策略：";
    s.selected_threats_clear_requested = L"\u5df2\u4e3a\u9009\u4e2d\u5a01\u80c1\u63d0\u4ea4\u9694\u79bb\u8bf7\u6c42\uff1a";
    s.quarantine = L"\u9694\u79bb\u533a";
    s.quarantine_empty = L"\u9694\u79bb\u533a\u6682\u65e0\u6587\u4ef6\u3002";
    s.restore_selected_quarantine = L"\u6062\u590d\u9009\u4e2d\u9879";
    s.delete_selected_quarantine = L"\u6c38\u4e45\u5220\u9664\u9009\u4e2d\u9879";
    s.quarantine_action_empty = L"\u672a\u9009\u62e9\u9694\u79bb\u533a\u9879\u3002";
    s.restore_selected_quarantine_requested = L"\u5df2\u4e3a\u9694\u79bb\u533a\u9879\u63d0\u4ea4\u6062\u590d\u8bf7\u6c42\uff1a";
    s.delete_selected_quarantine_requested = L"\u5df2\u4e3a\u9694\u79bb\u533a\u9879\u63d0\u4ea4\u6c38\u4e45\u5220\u9664\u8bf7\u6c42\uff1a";
    s.validate_ai_model = L"\u68c0\u9a8c ONNX \u6a21\u578b";
    s.ai_model_validation_requested = L"\u5df2\u8bf7\u6c42\u68c0\u9a8c ONNX \u6a21\u578b\u3002";
    s.ai_model_validation_passed = L"ONNX \u6a21\u578b\u53ef\u88ab EverbloomSecurity \u4f7f\u7528";
    s.ai_model_validation_failed = L"ONNX \u6a21\u578b\u4e0d\u517c\u5bb9 EverbloomSecurity";
    s.ai_model_importing_validated = L"\u5df2\u901a\u8fc7\u68c0\u9a8c\uff0c\u6b63\u5728\u5bfc\u5165 ONNX \u6a21\u578b\u3002";
    s.quick_description = L"\u5feb\u901f\u626b\u63cf\u8986\u76d6\u4e0b\u8f7d\u548c\u684c\u9762\u76ee\u5f55\uff1b\u5b8c\u6574\u626b\u63cf\u4f7f\u7528\u5f53\u524d\u7528\u6237\u76ee\u5f55\uff1b\u81ea\u5b9a\u4e49\u626b\u63cf\u53ef\u9009\u62e9\u4efb\u610f\u683c\u5f0f\u6587\u4ef6\u6216\u6587\u4ef6\u5939\u3002";
    s.attack_chain = L"攻击链";
    s.attack_chain_header = L"攻击链";
    s.attack_chain_subtitle = L"按顺序或以有界相关性匹配的多步行为链，涵盖进程、文件、注册表、服务和网络活动。";
    s.attack_chain_empty = L"尚未记录多步攻击链。";
    s.attack_chain_stage_intervene = L"已拦截";
    s.attack_chain_stage_correlate = L"已关联";
    s.attack_chain_stage_observe = L"仅观察";
    s.attack_chain_matched_strict = L"严格顺序匹配";
    s.attack_chain_matched_tolerant = L"容忍关联";
    s.attack_chain_clear = L"清除攻击链";
    s.attack_chain_step_file_write = L"写入文件";
    s.attack_chain_step_registry_write = L"写入注册表";
    s.attack_chain_step_process_create = L"创建进程";
    s.attack_chain_step_network_connect = L"发起网络连接";
    s.attack_chain_step_suspicious_api_call = L"可疑 API 调用";
    s.attack_chain_step_dns_query = L"DNS 查询";
    s.attack_chain_step_process_inject = L"进程注入";
    s.attack_chain_step_persistence_change = L"持久化变更";
    s.attack_chain_step_credential_access = L"凭据访问";
    s.attack_chain_step_service_tampering = L"服务篡改";
    s.attack_chain_step_backup_deletion = L"删除备份";
    s.attack_chain_step_ransomware_encryption = L"加密行为";
    s.attack_chain_step_suspicious_persistence = L"可疑持久化";
    s.attack_chain_step_suspicious_module_load = L"异常模块加载";
    s.window_minimize = L"最小化";
    s.window_maximize = L"最大化";
    s.window_restore = L"还原";
    s.window_close = L"关闭";
    // Dashboard hero card.
    s.protection_days = L"已保护您的计算机";
    s.system_safe_status = L"系统处于安全状态";
    s.scan_history = L"扫描记录";
    s.last_scan_prefix = L"上次扫描：";
    // Protection toggles.
    s.protection_realtime = L"实时防护";
    s.protection_driver_desc = L"由驱动防护提供的主动防御";
    s.protection_baseline = L"基础防护";
    s.protection_baseline_desc = L"注册到该引擎调度，使用本地引擎扫描运行中的程序（无需驱动）";
    s.protection_file = L"文件防护";
    s.protection_file_desc = L"监控文件操作，拦截恶意文件写入";
    s.protection_quiet_mode = L"静默模式";
    s.protection_quiet_mode_desc = L"开启后驱动防护将自动拦截威胁，不再弹出确认窗口";
    // Real-time threat dialog.
    s.realtime_process_intercept = L"进程拦截";
    s.realtime_file_intercept = L"文件拦截";
    s.realtime_allow = L"允许";
    s.realtime_block = L"拦截";
    s.realtime_seconds_suffix = L"秒";
    s.realtime_detecting = L"检测到可疑操作，等待您的决策";
    s.realtime_allow_desc = L"允许该程序运行";
    s.realtime_block_desc = L"拦截并隔离该程序";
    // Scan page cards.
    s.scan_quick_title = L"快速扫描";
    s.scan_quick_desc = L"扫描下载和桌面目录";
    s.scan_full_title = L"全盘扫描";
    s.scan_full_desc = L"扫描整个用户配置文件";
    s.scan_custom_title = L"自定义扫描";
    s.scan_custom_desc = L"扫描任意文件或文件夹";
    s.scan_virus_title = L"病毒扫描";
    s.scan_virus_desc = L"全面威胁系统扫描";
    s.scan_quarantine_title = L"隔离区";
    s.scan_quarantine_desc = L"管理隔离的威胁文件";
    // AI Training.
    s.training_epoch_label = L"训练轮次";
    s.training_loss_label = L"损失值";
    s.training_accuracy_label = L"准确率";
    s.training_baseline_label = L"基准模型";
    s.training_augmented_label = L"增强模型";
    s.training_gain_label = L"提升";
    s.training_selected_model = L"选定模型：";
    s.training_sample_count = L"训练样本数";
    s.training_auto_stop = L"自动停止（收敛时）";
    s.training_pause = L"暂停";
    s.training_resume = L"继续";
    s.training_status_paused = L"训练已暂停";
    s.training_comparison_title = L"模型对比";
    s.training_progress_bar = L"训练进度";
    s.training_time_elapsed = L"已用时";
    s.training_time_remaining = L"预计剩余";
    s.training_stage_generating = L"生成合成语料";
    s.training_stage_loading = L"加载特征";
    s.training_stage_training = L"训练模型";
    s.training_stage_exporting = L"导出 ONNX";
    // EDR attack chain.
    s.edr_behavior_chain = L"EDR 行为链拓扑";
    s.edr_tree_legend = L"图例";
    s.edr_high_risk = L"高危行为";
    s.edr_medium_risk = L"中危行为";
    s.edr_file_network = L"文件/网络";
    s.edr_persistence = L"持久化";
    s.edr_escalation = L"提权";
    s.edr_chain_detected = L"EDR 已检测到威胁行为";
    s.edr_chain_blocked = L"该程序已被自动终止";
}

void TraditionalChinese(UiStrings& s) {
    // Start from the complete Simplified Chinese catalog so newly added
    // strings remain visible, then override the user-facing labels with
    // Traditional Chinese wording.
    Chinese(s);
    s.app_subtitle = L"端點安全控制台";
    s.engine_connecting = L"正在連線引擎...";
    s.engine_connected = L"引擎已連線";
    s.engine_disconnected = L"引擎已中斷連線";
    s.engine_ready = L"掃描引擎已就緒";
    s.engine_waiting = L"正在等待掃描引擎";
    s.scan_cancel = L"取消掃描";
    s.scan_cancelled = L"掃描已取消";
    s.scan_completed = L"掃描完成";
    s.scanning_prefix = L"正在掃描：";
    s.scan_progress_error_prefix = L"掃描進度錯誤：";
    s.scan_batch_completed = L"掃描批次已完成。";
    s.malicious_result = L"惡意結果";
    s.threat_prefix = L"威脅：";
    s.scan_error_prefix = L"掃描錯誤：";
    s.appearance = L"外觀";
    s.workspace = L"工作區";
    s.dashboard = L"總覽";
    s.dashboard_header = L"安全性總覽";
    s.dashboard_subtitle = L"使用原生 WinUI 控制項管理掃描、防護、威脅、活動、設定與更新。";
    s.files_processed = L"已處理檔案";
    s.threats = L"威脅";
    s.errors = L"錯誤";
    s.ready = L"就緒";
    s.scan = L"掃描";
    s.scan_subtitle = L"執行 Rust 引擎提供的雜湊、YARA、啟發式、AI 與可選沙箱分析流程。";
    s.path_placeholder = L"資料夾或檔案路徑";
    s.heuristic = L"啟發式";
    s.sandbox = L"沙箱";
    s.cloud_scan = L"雲端偵測（佔位）";
    s.cloud_scan_description = L"預留給需要驗證的雲端判定；本機掃描流程不受影響。";
    s.cloud_placeholder_notice = L"雲端服務佔位已啟用：不會上傳檔案，本機引擎仍負責最終判定。";
    s.scan_progress_label = L"進度";
    s.scan_elapsed_label = L"耗時";
    s.scan_files_label = L"檔案";
    s.scan_stage_label = L"階段";
    s.sandbox_analysis = L"沙箱分析";
    s.sandbox_status_label = L"狀態";
    s.sandbox_snapshots_label = L"快照輪次";
    s.sandbox_candidates_label = L"PE候選";
    s.sandbox_entry_points_label = L"恢復入口點";
    s.sandbox_memory_label = L"已擷取記憶體";
    s.scan_waiting_for_engine = L"正在等待引擎連線，連線後將開始掃描...";
    s.scan_preparing = L"正在準備掃描請求...";
    s.scan_enumerating = L"正在列舉檔案...";
    s.no_scan = L"目前沒有正在執行的掃描。";
    s.quick_scan = L"快速掃描";
    s.full_scan = L"完整掃描";
    s.custom_scan = L"自訂掃描";
    s.scan_path = L"掃描路徑";
    s.protection = L"防護";
    s.protection_subtitle = L"檢視使用者模式橋接與核心原則契約；GUI 不會直接載入驅動程式。";
    s.realtime_protection = L"即時防護";
    s.r3_protection = L"R3 管理員防護";
    s.r3_protection_description = L"使用者模式防護，可搭配管理員權限攔截";
    s.driver_protection = L"驅動程式防護";
    s.driver_protection_description = L"程序、檔案、登錄、MBR 與網路核心回呼防護";
    s.paused = L"已暫停";
    s.monitoring = L"監控中";
    s.protection_enabled = L"即時防護已啟用";
    s.protection_paused = L"即時防護已暫停";
    s.monitoring_enabled = L"即時目錄監控已啟用。";
    s.monitoring_paused = L"即時目錄監控已暫停。";
    s.settings = L"設定";
    s.settings_subtitle = L"設定 WinUI 外觀、語言、引擎開關與執行階段診斷。";
    s.language = L"語言";
    s.scan_engine_switches = L"掃描引擎開關";
    s.translucent_panels = L"半透明面板";
    s.panel_transparency = L"面板透明度";
    s.panel_transparency_description = L"0% 為完全不透明，數值越高越能顯示背景圖片。";
    s.apply_transparency = L"套用透明度";
    s.start_with_windows = L"隨 Windows 啟動";
    s.notifications = L"顯示威脅通知";
    s.language_chinese = L"簡體中文";
    s.language_traditional = L"繁體中文";
    s.language_traditional_chinese = L"繁體中文";
    s.language_japanese = L"日本語";
    s.language_spanish = L"Español";
    s.style_fluent_light = L"Fluent 淺色";
    s.style_fluent_dark = L"Fluent 深色";
    s.style_high_contrast = L"高對比度";
    // Dashboard.
    s.protection_days = L"已保護您的電腦";
    s.system_safe_status = L"系統處於安全狀態";
    s.scan_history = L"掃描紀錄";
    s.last_scan_prefix = L"上次掃描：";
    // Protection toggles.
    s.protection_realtime = L"即時防護";
    s.protection_driver_desc = L"由驅動防護提供的主動防禦";
    s.protection_baseline = L"基礎防護";
    s.protection_baseline_desc = L"註冊到該引擎排程，使用本地引擎掃描執行中的程式（無需驅動）";
    s.protection_file = L"檔案防護";
    s.protection_file_desc = L"監控檔案操作，攔截惡意檔案寫入";
    s.protection_quiet_mode = L"靜默模式";
    s.protection_quiet_mode_desc = L"開啟後驅動防護將自動攔截威脅，不再彈出確認視窗";
    // Real-time dialog.
    s.realtime_process_intercept = L"程序攔截";
    s.realtime_file_intercept = L"檔案攔截";
    s.realtime_allow = L"允許";
    s.realtime_block = L"攔截";
    s.realtime_seconds_suffix = L"秒";
    s.realtime_detecting = L"偵測到可疑操作，等待您的決策";
    s.realtime_allow_desc = L"允許該程式執行";
    s.realtime_block_desc = L"攔截並隔離該程式";
    // AI Training.
    s.training_epoch_label = L"訓練輪次";
    s.training_loss_label = L"損失值";
    s.training_accuracy_label = L"準確率";
    s.training_baseline_label = L"基準模型";
    s.training_augmented_label = L"增強模型";
    s.training_gain_label = L"提升";
    s.training_selected_model = L"選定模型：";
    s.training_sample_count = L"訓練樣本數";
    s.training_auto_stop = L"自動停止（收斂時）";
    s.training_pause = L"暫停";
    s.training_resume = L"繼續";
    s.training_status_paused = L"訓練已暫停";
    s.training_comparison_title = L"模型對比";
    s.training_stage_generating = L"生成合成語料";
    s.training_stage_loading = L"載入特徵";
    s.training_stage_training = L"訓練模型";
    s.training_stage_exporting = L"匯出 ONNX";
    // EDR.
    s.edr_behavior_chain = L"EDR 行為鏈拓撲";
    s.edr_chain_detected = L"EDR 已偵測到威脅行為";
    s.edr_chain_blocked = L"該程式已被自動終止";
}

void Japanese(UiStrings& s) {
    s.app_subtitle = L"エンドポイントセキュリティコンソール";
    s.engine_connecting = L"エンジンに接続しています...";
    s.engine_connected = L"エンジン接続済み";
    s.engine_disconnected = L"エンジン切断";
    s.engine_ready = L"スキャンエンジンの準備が完了しました";
    s.engine_waiting = L"スキャンエンジンを待機中";
    s.ipc_connected = L"エンジン IPC に接続しました。";
    s.ipc_disconnected = L"エンジン IPC が切断されました。";
    s.engine_error_prefix = L"エンジンエラー: ";
    s.scan_cancel = L"スキャンをキャンセル";
    s.scan_cancelled = L"スキャンをキャンセルしました";
    s.scan_completed = L"スキャン完了";
    s.scanning_prefix = L"スキャン中: ";
    s.scan_progress_error_prefix = L"スキャン進行状況エラー: ";
    s.scan_batch_completed = L"スキャンバッチが完了しました。";
    s.malicious_result = L"悪意のある結果";
    s.threat_prefix = L"脅威: ";
    s.scan_error_prefix = L"スキャンエラー: ";
    s.config_reload_success = L"設定の再読み込みに成功しました: ";
    s.config_reload_failure = L"設定の再読み込みに失敗しました: ";
    s.appearance = L"外観";
    s.workspace = L"ワークスペース";
    s.dashboard = L"ダッシュボード";
    s.dashboard_header = L"セキュリティ概要";
    s.dashboard_subtitle = L"スキャン、防御、脅威、アクティビティ、設定、更新をネイティブ WinUI で管理します。";
    s.starting_bridge = L"エンジンブリッジを起動しています...";
    s.files_processed = L"処理済みファイル";
    s.threats = L"脅威";
    s.errors = L"エラー";
    s.overview_description = L"WinUI クライアントはローカル Rust エンジンを起動し、セッションごとの名前付きパイプで接続します。カーネルポリシー境界は GUI の外部に保たれます。";
    s.protection_surface = L"保護状態";
    s.ready = L"準備完了";
    s.threats_this_session = L"このセッションの脅威";
    s.engine_errors = L"エンジンエラー";
    s.recent_activity = L"最近のアクティビティ";
    s.application_started = L"WinUI アプリケーションを起動しました。";
    s.endpoint_prepared = L"セッション専用のエンドポイントを準備しました。";
    s.engine_startup_prefix = L"エンジン起動: ";
    s.scan = L"スキャン";
    s.scan_subtitle = L"Rust エンジンのハッシュ、YARA、ヒューリスティック、AI、任意のサンドボックス処理を実行します。";
    s.path_placeholder = L"フォルダーまたはファイルのパス";
    s.heuristic = L"ヒューリスティック";
    s.ai = L"AI";
    s.sandbox = L"サンドボックス";
    s.cloud_scan = L"クラウドスキャン（プレースホルダー）";
    s.cloud_scan_description = L"認証済みクラウド判定用の予約領域です。ローカルスキャンは通常どおり動作します。";
    s.cloud_placeholder_notice = L"クラウドサービスのプレースホルダーを有効にしました。ファイルはアップロードされません。";
    s.scan_waiting_for_engine = L"エンジン接続を待っています。接続後にスキャンを開始します...";
    s.scan_preparing = L"スキャン要求を準備しています...";
    s.scan_enumerating = L"ファイルを列挙しています...";
    s.no_scan = L"実行中のスキャンはありません。";
    s.requested_suffix = L"を要求しました...";
    s.quick_scan = L"クイックスキャン";
    s.full_scan = L"完全スキャン";
    s.custom_scan = L"カスタムスキャン";
    s.scan_path = L"パスをスキャン";
    s.quick_description = L"クイックスキャンは Downloads と Desktop を対象にします。完全スキャンは現在のユーザープロファイルを対象にします。カスタムスキャンは 1 つのパスを受け取ります。";
    s.path_required = L"スキャンパスが必要です。";
    s.custom_rejected = L"パスが空のため、カスタムスキャンを拒否しました。";
    s.protection = L"保護";
    s.protection_subtitle = L"GUI からドライバーを読み込まずに、ユーザーモードブリッジとカーネルポリシーを確認します。";
    s.realtime_protection = L"リアルタイム保護";
    s.paused = L"一時停止";
    s.monitoring = L"監視中";
    s.protection_open_failed = L"監視対象のディレクトリを開けませんでした";
    s.protection_start_failed = L"リアルタイム保護を開始できませんでした。";
    s.protection_enabled = L"リアルタイム保護を有効にしました";
    s.protection_paused = L"リアルタイム保護を一時停止しました";
    s.monitoring_enabled = L"リアルタイムディレクトリ監視を有効にしました。";
    s.monitoring_paused = L"リアルタイムディレクトリ監視を一時停止しました。";
    s.kernel_policy = L"カーネルポリシー";
    s.kernel_description = L"ドライバーコールバックの検証、プロセス/ファイル/ネットワークコールバック、ルール照合、ロールバックはドライバーサービス境界で処理されます。";
    s.profiles = L"プロファイル: data/policy_rules.json と data/policy_rules.hpol";
    s.localized_rules = L"ルールエイリアス: process/file/network/block と 進程/文件/网络/阻断。";
    s.realtime_intercept_title = L"リアルタイム保護によるブロック";
    s.realtime_intercept_notice = L"トロイの木馬に関連する動作を検出しました。ファイル操作を一時停止しています。";
    s.intercept_type = L"ブロックの種類";
    s.intercept_file = L"ファイルブロック";
    s.intercept_target = L"対象";
    s.remember_choice = L"この選択を記憶";
    s.allow = L"許可";
    s.block = L"ブロック";
    s.close = L"\u9589\u3058\u308b";
    s.realtime_block_requested = L"ブロックポリシーを要求しました。実行にはドライバー層が必要です。";
    s.threats_subtitle = L"悪意のある結果とエンジンエラーをこのアプリケーションセッションに収集します。";
    s.clear_threats = L"脅威をクリア";
    s.activity = L"アクティビティ";
    s.activity_subtitle = L"WinUI クライアントと Rust エンジンからの上限付きイベントストリームです。";
    s.clear_activity = L"アクティビティをクリア";
    s.updates = L"更新";
    s.updates_subtitle = L"エンジン IPC を通じてローカルハッシュと脅威インテリジェンスデータベースを再読み込みします。";
    s.reload_databases = L"データベースを再読み込み";
    s.database_reload_requested = L"データベースの再読み込みを要求しました。";
    s.updates_description = L"GUI はデータベースに直接書き込みません。エンジンが検証し、メモリ上のマッチャーをアトミックに置き換えます。";
    s.settings = L"設定";
    s.settings_subtitle = L"WinUI の外観、言語、エンジン設定、ランタイム診断を構成します。";
    s.language = L"言語";
    s.start_with_windows = L"Windows と同時に起動";
    s.notifications = L"脅威通知を表示";
    s.runtime_diagnostics = L"ランタイム診断";
    s.ipc_endpoint_prefix = L"IPC エンドポイント: ";
    s.not_configured = L"未構成";
    s.engine_launch_requested = L"エンジンプロセス: 起動を要求しました";
    s.engine_process_prefix = L"エンジンプロセス: ";
    s.language_english = L"English";
    s.language_chinese = L"简体中文";
    s.language_japanese = L"日本語";
    s.language_spanish = L"Español";
    s.style_fluent_light = L"Fluent ライト";
    s.style_fluent_dark = L"Fluent ダーク";
    s.style_high_contrast = L"ハイコントラスト";
}

void Spanish(UiStrings& s) {
    s.app_subtitle = L"Consola de seguridad de endpoints";
    s.engine_connecting = L"Conectando con el motor...";
    s.engine_connected = L"Motor conectado";
    s.engine_disconnected = L"Motor desconectado";
    s.engine_ready = L"El motor de análisis está listo";
    s.engine_waiting = L"Esperando al motor de análisis";
    s.ipc_connected = L"IPC del motor conectado.";
    s.ipc_disconnected = L"IPC del motor desconectado.";
    s.engine_error_prefix = L"Error del motor: ";
    s.scan_cancel = L"Cancelar escaneo";
    s.scan_cancelled = L"Análisis cancelado";
    s.scan_completed = L"Análisis completado";
    s.scanning_prefix = L"Analizando: ";
    s.scan_progress_error_prefix = L"Error de progreso del análisis: ";
    s.scan_batch_completed = L"Lote de análisis completado.";
    s.malicious_result = L"resultado malicioso";
    s.threat_prefix = L"Amenaza: ";
    s.scan_error_prefix = L"Error de análisis: ";
    s.config_reload_success = L"Configuración recargada correctamente: ";
    s.config_reload_failure = L"No se pudo recargar la configuración: ";
    s.appearance = L"Apariencia";
    s.workspace = L"Espacio de trabajo";
    s.dashboard = L"Panel";
    s.dashboard_header = L"Resumen de seguridad";
    s.dashboard_subtitle = L"Controles WinUI nativos para análisis, protección, amenazas, actividad, configuración y actualizaciones.";
    s.starting_bridge = L"Iniciando el puente del motor...";
    s.files_processed = L"Archivos procesados";
    s.threats = L"Amenazas";
    s.errors = L"Errores";
    s.overview_description = L"El cliente WinUI inicia el motor Rust local, se conecta mediante una tubería con nombre por sesión y mantiene el límite de política del kernel fuera del proceso GUI.";
    s.protection_surface = L"Superficie de protección";
    s.ready = L"Listo";
    s.threats_this_session = L"Amenazas de esta sesión";
    s.engine_errors = L"Errores del motor";
    s.recent_activity = L"Actividad reciente";
    s.application_started = L"Aplicación WinUI iniciada.";
    s.endpoint_prepared = L"Punto final del motor preparado para esta sesión.";
    s.engine_startup_prefix = L"Inicio del motor: ";
    s.scan = L"Análisis";
    s.scan_subtitle = L"Ejecuta el flujo de hashes, YARA, heurística, IA y sandbox opcional del motor Rust.";
    s.path_placeholder = L"Ruta de carpeta o archivo";
    s.heuristic = L"Heurística";
    s.ai = L"IA";
    s.sandbox = L"Sandbox";
    s.cloud_scan = L"Análisis en la nube (placeholder)";
    s.cloud_scan_description = L"Reserva para un veredicto en la nube autenticado; el análisis local sigue funcionando.";
    s.cloud_placeholder_notice = L"Placeholder de nube activado. No se suben archivos; los motores locales siguen siendo la autoridad.";
    s.scan_waiting_for_engine = L"Esperando la conexión del motor antes de iniciar el análisis...";
    s.scan_preparing = L"Preparando la solicitud de análisis...";
    s.scan_enumerating = L"Enumerando archivos...";
    s.no_scan = L"No hay ningún análisis en ejecución.";
    s.requested_suffix = L" solicitado...";
    s.quick_scan = L"Análisis rápido";
    s.full_scan = L"Análisis completo";
    s.custom_scan = L"Análisis personalizado";
    s.scan_path = L"Analizar ruta";
    s.quick_description = L"El análisis rápido cubre Descargas y Escritorio. El análisis completo usa el perfil del usuario actual. El análisis personalizado acepta una sola ruta.";
    s.path_required = L"Se requiere una ruta de análisis.";
    s.custom_rejected = L"Análisis personalizado rechazado porque la ruta está vacía.";
    s.protection = L"Protección";
    s.protection_subtitle = L"Revisa el puente de usuario y el contrato de política del kernel sin cargar un controlador desde la GUI.";
    s.realtime_protection = L"Protección en tiempo real";
    s.paused = L"Pausada";
    s.monitoring = L"Supervisando";
    s.protection_open_failed = L"La protección en tiempo real no pudo abrir un directorio supervisado";
    s.protection_start_failed = L"No se pudo iniciar la protección en tiempo real.";
    s.protection_enabled = L"Protección en tiempo real activada";
    s.protection_paused = L"Protección en tiempo real pausada";
    s.monitoring_enabled = L"Supervisión de directorios activada.";
    s.monitoring_paused = L"Supervisión de directorios pausada.";
    s.kernel_policy = L"Política del kernel";
    s.kernel_description = L"La validación de callbacks, los callbacks de procesos/archivos/red, las reglas y la reversión permanecen en el límite del servicio del controlador.";
    s.profiles = L"Perfiles: data/policy_rules.json y data/policy_rules.hpol";
    s.localized_rules = L"Alias de reglas: process/file/network/block y 进程/文件/网络/阻断.";
    s.realtime_intercept_title = L"Protección en tiempo real bloqueada";
    s.realtime_intercept_notice = L"EverbloomSecurity detectó un comportamiento asociado a un troyano y pausó la operación.";
    s.intercept_type = L"Tipo de bloqueo";
    s.intercept_file = L"Bloqueo de archivo";
    s.intercept_target = L"Objetivo";
    s.remember_choice = L"Recordar esta elección";
    s.allow = L"Permitir";
    s.block = L"Bloquear";
    s.close = L"Cerrar";
    s.realtime_block_requested = L"Solicitud de bloqueo enviada; requiere la capa de controlador para aplicarse.";
    s.threats_subtitle = L"Los resultados maliciosos y errores del motor se recopilan durante esta sesión.";
    s.clear_threats = L"Borrar amenazas";
    s.activity = L"Actividad";
    s.activity_subtitle = L"Flujo de eventos limitado del cliente WinUI y del motor Rust.";
    s.clear_activity = L"Borrar actividad";
    s.updates = L"Actualizaciones";
    s.updates_subtitle = L"Recarga la base de hashes y la inteligencia de amenazas mediante IPC del motor.";
    s.reload_databases = L"Recargar bases de datos";
    s.database_reload_requested = L"Recarga de bases de datos solicitada.";
    s.updates_description = L"La GUI no escribe directamente en la base de datos. El motor valida y reemplaza atómicamente sus coincidencias en memoria.";
    s.settings = L"Configuración";
    s.settings_subtitle = L"Configura la apariencia WinUI, el idioma, los motores y el diagnóstico de ejecución.";
    s.language = L"Idioma";
    s.start_with_windows = L"Iniciar con Windows";
    s.notifications = L"Mostrar notificaciones de amenazas";
    s.runtime_diagnostics = L"Diagnóstico de ejecución";
    s.ipc_endpoint_prefix = L"Punto final IPC: ";
    s.not_configured = L"no configurado";
    s.engine_launch_requested = L"Proceso del motor: inicio solicitado";
    s.engine_process_prefix = L"Proceso del motor: ";
    s.language_english = L"English";
    s.language_chinese = L"简体中文";
    s.language_japanese = L"日本語";
    s.language_spanish = L"Español";
    s.style_fluent_light = L"Fluent claro";
    s.style_fluent_dark = L"Fluent oscuro";
    s.style_high_contrast = L"Contraste alto";
    s.pick_files_scan = L"Seleccionar archivos para analizar";
    s.pick_folder_scan = L"Seleccionar carpeta para analizar";
    s.background_image = L"Imagen de fondo";
    s.choose_background = L"Elegir imagen de fondo";
    s.clear_background = L"Quitar imagen de fondo";
    s.accent_color = L"Color de acento";
    s.context_menu = L"Analisis desde el menu contextual";
    s.install_context_menu = L"Instalar menu contextual de analisis";
    s.remove_context_menu = L"Quitar menu contextual de analisis";
    s.context_menu_installed = L"Menu contextual de analisis instalado.";
    s.context_menu_removed = L"Menu contextual de analisis quitado.";
}

} // namespace

void ApplyHashDatabaseStrings(UiStrings& strings, UiLanguage language) {
    if (language == UiLanguage::SimplifiedChinese) {
        strings.import_hash_database = L"\u5bfc\u5165\u54c8\u5e0c\u6570\u636e\u5e93";
        strings.hash_database_import_description = L"\u5bfc\u5165 CSV\u3001TSV\u3001JSON\u3001JSONL\u3001DAT\u3001\u6587\u672c\u6216 SQLite \u54c8\u5e0c\u5e93\u5230\u5f53\u524d\u5f15\u64ce";
        strings.hash_database_import_requested = L"\u5df2\u8bf7\u6c42\u5bfc\u5165\u54c8\u5e0c\u6570\u636e\u5e93\u3002";
    } else if (language == UiLanguage::TraditionalChinese) {
        strings.import_hash_database = L"\u532f\u5165\u96dc\u6e05\u8cc7\u6599\u5eab";
        strings.hash_database_import_description = L"\u532f\u5165 CSV\u3001TSV\u3001JSON\u3001JSONL\u3001DAT\u3001\u6587\u672c\u6216 SQLite \u96dc\u6e05\u8cc7\u6599\u5eab\u5230\u7576\u524d\u5f15\u64ce";
        strings.hash_database_import_requested = L"\u5df2\u8acb\u6c42\u532f\u5165\u96dc\u6e05\u8cc7\u6599\u5eab\u3002";
    }
}

UiStrings Strings(UiLanguage language) {
    UiStrings result;
    switch (language) {
    case UiLanguage::SimplifiedChinese:
        Chinese(result);
        break;
    case UiLanguage::TraditionalChinese:
        TraditionalChinese(result);
        break;
    case UiLanguage::Japanese:
        Japanese(result);
        break;
    case UiLanguage::Spanish:
        Spanish(result);
        break;
    case UiLanguage::English:
    default:
        break;
    }
    if (language == UiLanguage::Japanese) {
        result.quick_description = L"\u30af\u30a4\u30c3\u30af\u30b9\u30ad\u30e3\u30f3\u306f Downloads \u3068 Desktop \u3092\u5bfe\u8c61\u306b\u3057\u307e\u3059\u3002\u5b8c\u5168\u30b9\u30ad\u30e3\u30f3\u306f\u73fe\u5728\u306e\u30e6\u30fc\u30b6\u30fc\u30d7\u30ed\u30d5\u30a1\u30a4\u30eb\u3092\u5bfe\u8c61\u306b\u3057\u307e\u3059\u3002\u30ab\u30b9\u30bf\u30e0\u30b9\u30ad\u30e3\u30f3\u3067\u306f\u4efb\u610f\u306e\u5f62\u5f0f\u306e\u30d5\u30a1\u30a4\u30eb\u307e\u305f\u306f\u30d5\u30a9\u30eb\u30c0\u30fc\u3092\u9078\u629e\u3067\u304d\u307e\u3059\u3002";
    } else if (language == UiLanguage::Spanish) {
        result.quick_description = L"El an\u00e1lisis r\u00e1pido cubre Descargas y Escritorio. El an\u00e1lisis completo usa el perfil del usuario actual. El an\u00e1lisis personalizado permite elegir archivos de cualquier formato o una carpeta.";
    }
    ApplyHashDatabaseStrings(result, language);
    return result;
}

std::wstring LanguageName(UiLanguage language) {
    switch (language) {
    case UiLanguage::SimplifiedChinese: return L"简体中文";
    case UiLanguage::TraditionalChinese: return L"繁體中文";
    case UiLanguage::Japanese: return L"日本語";
    case UiLanguage::Spanish: return L"Español";
    case UiLanguage::English:
    default: return L"English";
    }
}

UiLanguage DetectSystemLanguage() {
    std::array<wchar_t, LOCALE_NAME_MAX_LENGTH> locale{};
    if (GetUserDefaultLocaleName(locale.data(), static_cast<int>(locale.size())) == 0) {
        return UiLanguage::English;
    }
    const std::wstring name(locale.data());
    if (name.rfind(L"zh-TW", 0) == 0
        || name.rfind(L"zh-HK", 0) == 0
        || name.rfind(L"zh-MO", 0) == 0) {
        return UiLanguage::TraditionalChinese;
    }
    if (name.rfind(L"zh", 0) == 0) return UiLanguage::SimplifiedChinese;
    if (name.rfind(L"ja", 0) == 0) return UiLanguage::Japanese;
    if (name.rfind(L"es", 0) == 0) return UiLanguage::Spanish;
    return UiLanguage::English;
}

} // namespace everbloom::gui
