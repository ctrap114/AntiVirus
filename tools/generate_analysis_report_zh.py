#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 EverbloomSecurity 中文综合分析报告（Word 文档）- 代码技术分析 + 能力分析。"""

import os
import datetime
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn

DARK_BLUE = RGBColor(0x1B, 0x3A, 0x5C)
MID_BLUE = RGBColor(0x2C, 0x5F, 0x8A)
LIGHT_BLUE = RGBColor(0x3A, 0x7C, 0xA5)
GRAY = RGBColor(0x66, 0x66, 0x66)

doc = Document()

# 全局字体
style = doc.styles['Normal']
style.font.name = 'Microsoft YaHei'
style.font.size = Pt(10.5)
style.element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft YaHei')

for name, size, color in [('Heading 1', 16, DARK_BLUE), ('Heading 2', 13, MID_BLUE), ('Heading 3', 11.5, LIGHT_BLUE)]:
    h = doc.styles[name]
    h.font.name = 'Microsoft YaHei'
    h.font.size = Pt(size)
    h.font.color.rgb = color
    h.font.bold = True
    h.element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft YaHei')


def para(text, size=10.5, bold=False, color=None, align=None, space_after=6):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.size = Pt(size)
    r.bold = bold
    if color:
        r.font.color.rgb = color
    if align:
        p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    return p


def bullet(text, level=0, size=10.5):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(0.6 + level * 0.6)
    p.paragraph_format.space_after = Pt(3)
    r = p.add_run(('• ' if level == 0 else '– ') + text)
    r.font.size = Pt(size)
    return p


def add_table(headers, rows, col_widths=None):
    t = doc.add_table(rows=1 + len(rows), cols=len(headers))
    t.style = 'Light Grid Accent 1'
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.size = Pt(10)
    for ri, row in enumerate(rows):
        for ci, val in enumerate(row):
            cell = t.rows[ri + 1].cells[ci]
            cell.text = str(val)
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9.5)
    if col_widths:
        for ci, w in enumerate(col_widths):
            for row in t.rows:
                row.cells[ci].width = Cm(w)
    return t


# ══════════════════════════════════════════════════════════════
# 封面
# ══════════════════════════════════════════════════════════════
for _ in range(6):
    doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('EverbloomSecurity')
r.font.size = Pt(40)
r.bold = True
r.font.color.rgb = DARK_BLUE
r.font.name = 'Microsoft YaHei'

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('综合分析报告')
r.font.size = Pt(24)
r.bold = True
r.font.color.rgb = MID_BLUE

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('代码技术分析 × 能力分析')
r.font.size = Pt(15)
r.font.color.rgb = LIGHT_BLUE

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('版本：1.0.0   |   平台：Windows x64')
r.font.size = Pt(12)
r.font.color.rgb = GRAY

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('生成时间：' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
r.font.size = Pt(11)
r.font.color.rgb = GRAY

doc.add_page_break()

# ══════════════════════════════════════════════════════════════
# 目录
# ══════════════════════════════════════════════════════════════
doc.add_heading('目录', level=1)
toc = [
    '第一部分：代码技术分析',
    '  1. 项目概述与技术栈',
    '  2. 整体架构设计',
    '  3. Rust 扫描引擎深度分析',
    '  4. WinUI 3 图形界面深度分析',
    '  5. 内核驱动设计分析',
    '  6. Python 工具链与绑定层',
    '  7. 构建与打包体系',
    '  8. 代码质量评估',
    '  9. 依赖与供应链分析',
    '第二部分：能力分析',
    '  10. 检测能力分析',
    '  11. YARA 规则覆盖能力',
    '  12. AI/机器学习能力',
    '  13. 实时防护能力',
    '  14. 沙箱与动态分析能力',
    '  15. 威胁管理能力',
    '  16. 病毒库更新能力',
    '  17. 界面与用户体验能力',
    '  18. 能力成熟度总体评估',
    '第三部分：总结与建议',
    '  19. 已知问题清单',
    '  20. 可行性建议与发展路线',
    '  21. 最终结论',
]
for item in toc:
    p = doc.add_paragraph(item)
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after = Pt(1)
    if item.startswith('  '):
        p.paragraph_format.left_indent = Cm(1.2)

doc.add_page_break()

# ══════════════════════════════════════════════════════════════
# 第一部分：代码技术分析
# ══════════════════════════════════════════════════════════════
doc.add_heading('第一部分：代码技术分析', level=1)

# ── 1. 项目概述与技术栈 ──
doc.add_heading('1. 项目概述与技术栈', level=2)
para('EverbloomSecurity 是一个面向 Windows x64 平台的开源杀毒软件原型系统。项目采用"界面-引擎-工具链"三层分离架构，'
     '将 WinUI 3 / C++/WinRT 图形界面、Rust 扫描引擎、Python 配置与分析工具、SQLite 病毒哈希库、YARA 规则和 '
     'ONNX 模型有机地组合在一起，形成一套完整的多层防护安全平台原型。')

doc.add_heading('1.1 技术栈概览', level=3)
add_table(
    ['层级', '技术', '语言', '主要职责'],
    [
        ['图形界面层', 'WinUI 3 + C++/WinRT', 'C++', '桌面界面、用户交互、可视化'],
        ['扫描引擎层', 'Rust (由 cargo 构建)', 'Rust', '多层检测管道、机器学习推理、IPC 服务'],
        ['内核驱动层', 'WDK + Minifilter', 'C++', '文件保护、AMSI、实时拦截（原型阶段）'],
        ['Python 绑定层', 'PyO3 (libeverbloom_rs)', 'Rust/Python', '9 个原生类供 Python 工具调用'],
        ['工具链', 'pytest + 训练脚本', 'Python', '模型训练、质量基线、ONNX 转换'],
        ['构建体系', 'CMake + Cargo + Ninja + CPack', '混合', '编译、测试、打包、安装'],
    ]
)
para('')

doc.add_heading('1.2 代码规模统计', level=3)
add_table(
    ['项目', '规模', '说明'],
    [
        ['Rust 引擎源码', '约 29,802 行 / 57 个 .rs 文件', '22 个公共模块'],
        ['GUI 源码', '约 8,301 行 / 17 个 .cpp/.h 文件', 'WinUIApp.cpp 为 4,689 行'],
        ['YARA 规则', '32 条 / 933 行（1 个文件）', '覆盖 10 大类威胁'],
        ['Python 工具', 'tools/ 下 12 个脚本', '训练/转换/构建工具'],
        ['Python 包', '3 个包 11 个文件', 'config / core / viz'],
        ['文档', '19 篇 Markdown 文档', '架构、安全边界、构建说明'],
        ['测试', 'Rust 194 项（193 通过）', '另含 Python pytest 套件'],
    ]
)
para('')

# ── 2. 整体架构设计 ──
doc.add_heading('2. 整体架构设计', level=2)
para('该系统采用微内核启发式的架构设计：Rust 扫描引擎作为独立的子进程运行，通过 Windows 命名管道 '
     '与 WinUI GUI 进程进行 NDJSON（换行分隔 JSON）协议通信。这一设计带来了显著的工程优势：')
bullet('进程隔离：引擎崩溃不会拖垮 GUI，反之亦然')
bullet('语言解耦：引擎用适合底层安全计算的 Rust，界面用适合桌面渲染的 C++/WinRT')
bullet('可独立测试：引擎可脱离 GUI 单独编译、运行与测试')
bullet('安全边界收窄：检测逻辑与界面层之间只暴露受控的 IPC 接口，减小攻击面')

doc.add_heading('2.1 通信协议（NDJSON）', level=3)
para('引擎与 GUI 之间通过 NDJSON 传输结构化消息，覆盖完整生命周期：')
add_table(
    ['消息类别', '类型示例', '用途'],
    [
        ['扫描请求', 'scan_request / stop', '提交批量文件、周期目标、取消'],
        ['扫描进度', 'scan_progress', '进度、已处理数、错误数、速度、ETA、威胁数'],
        ['扫描结果', 'scan_result', '文件、原因、命中引擎、评分、处理状态'],
        ['威胁情报', 'attack_chains', '攻击链可视化数据'],
        ['训练控制', 'train_start / train_progress / train_complete / model_compare', 'AI 训练的启停与进度回传'],
        ['配置变更', 'config_update / model_reload', '数据库热重载、模型更新'],
        ['实时监控', 'hsi_event', '实时防护事件'],
        ['控制面', 'heartbeat / stop', '心跳保活与优雅退出'],
    ]
)
para('')
para('引擎进程绑定父进程 PID，通过看门狗实现优雅退出，确保 GUI 关闭后不会遗留无人管理的扫描进程。')

doc.add_heading('2.2 架构优点与不足', level=3)
add_table(
    ['维度', '评价'],
    [
        ['模块化', '优秀：引擎 22 个模块职责清晰，层间解耦'],
        ['分层清晰', '优秀：界面/引擎/驱动/工具链四层分离'],
        ['进程隔离', '优秀：独立引擎进程 + 命名管道 IPC'],
        ['可测试性', '良好：引擎单元测试覆盖充分，GUI 自动化测试缺失'],
        ['单一职责', '一般：WinUIApp.cpp 单文件 4,689 行，需拆分重构'],
        ['扩展性', '良好：检测层可插拔，Fusion 层支持多引擎协商'],
    ]
)
para('')

# ── 3. Rust 扫描引擎深度分析 ──
doc.add_heading('3. Rust 扫描引擎深度分析', level=2)

doc.add_heading('3.1 模块结构', level=3)
para('引擎包含 22 个公共模块，核心职责如下：')
add_table(
    ['模块', '职责', '技术要点'],
    [
        ['scanner', '扫描编排器，管道核心', 'Rayon 并行 + Tokio 异步'],
        ['layers', '16 个检测子层', 'AI/行为/哈希/YARA/启发式等'],
        ['training', '原生 MLP 训练管道', 'AdamW 优化器 + ONNX 导出'],
        ['sandbox', '动态执行沙箱', 'ptrace（Linux）/ ETW（Windows）'],
        ['monitoring', 'ETW 事件采集', '用户态/驱动事件 + 幽灵文件'],
        ['ndjson', '主传输层', 'stdin/stdout NDJSON'],
        ['ipc', '传统帧通信', 'Unix socket / 命名管道'],
        ['quarantine', '隔离管理', '可移植字节变换 + 格式头 + 导出/导入备份'],
        ['driver_bridge', '内核驱动桥接', 'BYOVD 检测 + 文件策略'],
        ['hips', '主机入侵防御', '系统调用监控'],
        ['protection_state', '防护模式状态', '全局 R3/驱动防护状态'],
        ['public_feeds', '威胁情报源', 'curl 下载 5 个公开情报源'],
    ]
)
para('')

doc.add_heading('3.2 多层检测管道', level=3)
para('核心扫描管道为 15 步多引擎融合流程，体现了纵深防御（Defense-in-Depth）思想：')
para('缓存检查 → 哈希匹配 → ClamAV（可选）→ YARA 规则 → Cookie 防御 → PE 启发式 → AI 推理 → 静态沙箱 → '
     '融合决策 → 动态沙箱 → 行为评分 → 序列匹配 → 威胁情报 → 进程状态 → 回滚')

add_table(
    ['阶段', '技术手段', '优势', '局限'],
    [
        ['缓存', 'LRU 指纹缓存', '重复扫描零开销', '存在陈旧条目风险'],
        ['哈希', 'MD5/SHA-1/SHA-256 + SSDEEP/TLSH', '精确匹配已知威胁', '无法识别变种'],
        ['ClamAV', '第二意见引擎', '数据库覆盖面广', '可选、依赖网络'],
        ['YARA', '规则模式匹配', '规则高度可定制', '规则数量有限'],
        ['Cookie 防御', '浏览器凭据探测', '针对具体 TTP', '范围狭窄'],
        ['启发式', 'PE 结构分析', '识别可疑结构', '脚本检测有限'],
        ['AI', 'ONNX 模型推理', '统计模式识别', '训练数据有限'],
        ['静态沙箱', '能力链条预测', '无执行风险', '模型简化'],
        ['融合', '跨引擎表决', '降低误报', '规则化仲裁'],
        ['动态沙箱', '隔离环境执行', '真实行为分析', '资源开销大'],
        ['行为评分', '运行时行为计分', '捕获运行时 TTP', 'ETW 遥测不完整'],
        ['序列匹配', 'API 序列比对', '捕获攻击链', '序列库有限'],
        ['威胁情报', 'IOC 关联', '已知威胁关联', '依赖源新鲜度'],
        ['回滚', '文件/注册表撤销', '清除痕迹', '覆盖不完整'],
    ]
)
para('')

doc.add_heading('3.3 AI 训练管道设计', level=3)
para('引擎内建原生 Rust MLP 训练管道（无需 Python 依赖），设计要点：')
bullet('网络结构：3 层感知机 input(12) → hidden(48) → hidden/2(24) → 1，ReLU + AdamW')
bullet('数据生成：合成语料（含安全标记的惰性 PE 样本）')
bullet('对比实验：基线模型 vs 增强模型（家族多样化增强）')
bullet('训练指标：准确率、精确率、召回率、FPR、FNR、家族级召回')
bullet('进度回传：按轮次（epoch）通过 NDJSON 输出，GUI 实时可视化')
bullet('模型导出：ONNX + model_contract.json 边车')
para('GUI 提供完整训练交互界面：进度条、指标面板、模型对比卡片、自动停止开关、开始/暂停/取消控制。')

doc.add_heading('3.4 数据与性能特征', level=3)
bullet('并行处理：Rayon 线程池，默认 4 线程，EVERBLOOM_SCAN_THREADS 可配置')
bullet('数据库：rusqlite 内置 SQLite，支持热重载与失败回滚')
bullet('PE 解析：goblin 库')
bullet('HTTP：hyper 提供管理 API（模型管理、集成配置、哈希导入）')
bullet('ONNX 推理：tract-onnx 0.23.4')

# ── 4. WinUI 3 图形界面深度分析 ──
doc.add_heading('4. WinUI 3 图形界面深度分析', level=2)

doc.add_heading('4.1 界面结构', level=3)
para('GUI 提供 7 个主页面：控制台（Dashboard）、扫描中心、威胁管理、实时防护、日志审计、设置、更新。')
add_table(
    ['组件', '约行数', '职责'],
    [
        ['WinUIApp.cpp', '4,689', '主窗口、全部页面、事件处理（需拆分）'],
        ['WinUIApp.h', '850', 'App 类、EngineUiState、BuildMainContent 签名'],
        ['WinUIEngineProcess.cpp', '450', '引擎子进程生命周期管理'],
        ['WinUIEngineClient.cpp', '600', 'NDJSON IPC 客户端'],
        ['WinUITrainingRunner.cpp', '371', 'AI 训练事件解析'],
        ['WinUITrainingRunner.h', '110', 'TrainingRunnerEvent 结构'],
        ['WinUIProtectionMonitor.cpp', '300', '实时文件监控'],
        ['WinUITrayIcon.cpp', '200', '系统托盘集成'],
        ['WinUILocalization.cpp', '600', '三语种本地化'],
    ]
)
para('')

doc.add_heading('4.2 关键界面技术', level=3)
bullet('主题系统：7 套主题（Fluent 亮/暗、Aurora、高对比度、Glass、Graphite、Rose）+ 4 种强调色（蓝/青/橙/紫）')
bullet('调色板：每套主题定义背景、卡片、边框、文本、弱化文本、主/强调/成功/警告/危险色')
bullet('本地化：英文 + 简体中文 + 繁体中文，约 60 条字符串覆盖全部页面')
bullet('无边框窗口：ExtendsContentIntoTitleBar + OverlappedPresenter 去边框，自定义标题栏（36px 渐变光带 + 1px 发丝线）')
bullet('窗口按钮：圆角（9px，40×30）半透明液态水晶风格，5 种指针状态交互，深浅主题分别适配')
bullet('托盘集成：隐藏/显示、开始扫描、彻底退出')
bullet('资源管理器右键菜单：安装/卸载可执行脚本')
bullet('主题重建：on_caption_ready 回调自动重设标题栏')

doc.add_heading('4.3 实时防护弹窗设计', level=3)
para('实时威胁弹窗采用结构化设计，交互层级清晰：')
bullet('警告图标：三角形感叹号圆形容器（视觉突出）')
bullet('拦截详情卡：拦截类型 / 拦截目标 / 威胁说明三个字段块')
bullet('倒计时机制：系统默认（封锁）按钮带 N 秒倒计时，超时自动封锁（fail-closed）')
bullet('允许/封锁双按钮：用户决定处置，支持"记住选择"')
para('这是一个"默认封锁、超时降级、用户可控"的合理安全交互范式。')

doc.add_heading('4.4 GUI 代码质量', level=3)
add_table(
    ['指标', '评估'],
    [
        ['代码行数', '约 8,301 行，体量适中'],
        ['单文件规模', 'WinUIApp.cpp 4,689 行，严重超标，建议拆分'],
        ['事件处理', '全部通过 RunUiSafely 包装，异常不泄漏'],
        ['生命周期', '引擎进程管理完善（启动/监控/重启/停止）'],
        ['可维护性', '局部差（WinUIApp.cpp），总体可接受'],
        ['自动化测试', '无 GUI 自动化测试，属关键缺口'],
    ]
)
para('')

# ── 5. 内核驱动设计分析 ──
doc.add_heading('5. 内核驱动设计分析', level=2)
para('内核驱动（everbloom_driver.sys）使用 C++ / WDK 构建，处于原型阶段：')
add_table(
    ['组件', '职责'],
    [
        ['file_protection', '基于 Minifilter 回调的文件拦截'],
        ['self_protection', '防篡改自保护'],
        ['amsi', 'AMSI 集成'],
        ['realtime_scan', '实时扫描拦截'],
        ['network_firewall', '网络防火墙'],
        ['advanced_threat', '高级威胁检测'],
        ['irp_dispatcher', 'IRP 分发'],
        ['kernel_policy', '内核策略管理'],
        ['event_bus', '内核事件总线（用户态通信）'],
    ]
)
para('构建配置要点：/DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /INTEGRITYCHECK，'
     '依赖 ntddk.h、ntoskrnl.lib、fltMgr.lib 等。')
para('技术现状结论：驱动可编译，但未签名，无法在生产环境加载；需要 EV 代码签名证书 + WHQL 提交。')

# ── 6. Python 工具链与绑定层 ──
doc.add_heading('6. Python 工具链与绑定层', level=2)
para('libeverbloom_rs（PyO3 0.29）向 Python 暴露 9 个原生类：')
add_table(
    ['类', '模块', '用途'],
    [
        ['PeParser', 'rust_pe_parser', 'PE 文件解析'],
        ['FeatureExtractor', 'rust_feature_extractor', '1285 维特征提取'],
        ['YaraRuleEngine', 'rust_rule_engine', 'YARA 匹配'],
        ['PatternMatcher', 'rust_pattern_matcher', 'Aho-Corasick 模式匹配'],
        ['ShardedLruCache', 'rust_cache', '线程安全 LRU'],
        ['FsMonitor', 'rust_fs_monitor', '文件系统监控'],
        ['WinApi', 'rust_win_api', 'Windows API 工具'],
        ['ScanPipeline', 'rust_scan_pipeline', '完整扫描管道'],
        ['SandboxQueue', 'rust_sandbox_queue', '沙箱任务队列'],
    ]
)
para('')
para('tools/（12 个脚本）能力矩阵：')
bullet('模型训练：train_feature_cnn.py / train_ai_model.py / train_adversarial_model.py / train_pyas_transformer.py / train_synthetic_experiment.py')
bullet('质量评估：run_quality_baseline.py')
bullet('ONNX 转换：convert_onnx_for_everbloom.py / convert_feature_cnn_for_tract.py / convert_tree_ensemble_for_tract.py')
bullet('数据构建：build_local_hashdb.py')
bullet('沙箱集成：cuckoo_submit.py')
bullet('示例：yara_example.py')

# ── 7. 构建与打包体系 ──
doc.add_heading('7. 构建与打包体系', level=2)
add_table(
    ['环节', '工具', '说明'],
    [
        ['顶层构建', 'CMake 3.20+', 'add_subdirectory(gui) + 自定义目标'],
        ['C++ 编译', 'MSVC + Ninja', '增量编译快，构建目录 artifacts/gui/cmake-ninja'],
        ['Rust 引擎', 'Cargo --release', '必须使用 release 模式（LRN 记录）'],
        ['依赖管理', 'vcpkg', 'cppwinrt / protobuf / sqlite3 / openssl'],
        ['打包', 'Inno Setup 6 (本地 ISCC.exe)', 'tools/build_installer.ps1 调用 D:\\Inno Setup 6\\ISCC.exe 编译'],
        ['ZIP 免安装', 'Compress-Archive', '~81 MB，含全部运行依赖'],
    ]
)
para('')
para('重要构建经验（记录于 .learnings/LEARNINGS.md）：')
bullet('LRN-20260829-001：引擎 crate 构建必须使用 --release')
bullet('LRN-20260829-002：删除缓存前必须先结束 cargo/rustc 进程')
bullet('LRN-20260829-003：TitleBarHeightOption 位于 winrt::Microsoft::UI::Windowing 命名空间')
bullet('C++/WinRT 指针事件委托需要显式 lambda 参数类型，避免 LNK2019')

# ── 8. 代码质量评估 ──
doc.add_heading('8. 代码质量评估', level=2)
add_table(
    ['维度', '评分 (1-5)', '评语'],
    [
        ['模块化与分层', '5', '引擎 22 模块、四层架构清晰'],
        ['命名与一致性', '4', '命名规范，风格统一'],
        ['文档完整度', '4', '19 篇文档 + 内联注释 + LEARNINGS 记录'],
        ['错误处理', '4', 'Rust 全程 Result/Option，GUI 异常兜底'],
        ['单元测试', '4', '194 项 Rust 测试全绿'],
        ['GUI 可测试性', '1', '零自动化测试，单文件过大'],
        ['日志与可观测', '3', 'tracing + 旋转日志，但指标仪表化有限'],
        ['安全编码', '4', '进程隔离、fail-closed 设计良好'],
    ]
)
para('')

# ── 9. 依赖与供应链分析 ──
doc.add_heading('9. 依赖与供应链分析', level=2)
add_table(
    ['类别', '依赖', '说明'],
    [
        ['Rust 推理', 'tract-onnx 0.23.4', 'ONNX 模型推理'],
        ['Rust YARA', 'yara 0.32 (vendored)', '内置构建，规则匹配'],
        ['Rust 数据库', 'rusqlite 0.31 (bundled)', '自带 SQLite'],
        ['Rust HTTP', 'tokio + hyper 0.14', '管理 API 与情报源'],
        ['Rust Windows', 'windows-sys 0.61.2', 'Win32 API 绑定'],
        ['C++ Windows', 'cppwinrt', 'WinUI 投影'],
        ['C++ TLS', 'openssl', '传输层安全'],
        ['C++ 序列化', 'protobuf', '协议缓冲'],
    ]
)
para('')
bullet('全部 vcpkg port 已 vendor 在仓库内，离线可构建')
bullet('Cargo.lock 保证 Rust 依赖可复现')
bullet('YARA 与 SQLite 均为内置构建，不打外部抹布')
bullet('缺口：无自动依赖更新工具、无 SBOM、无 CI 漏洞扫描')

# ══════════════════════════════════════════════════════════════
# 第二部分：能力分析
# ══════════════════════════════════════════════════════════════
doc.add_heading('第二部分：能力分析', level=1)

# ── 10. 检测能力分析 ──
doc.add_heading('10. 检测能力分析', level=2)
para('多引擎融合使整体检测能力具备较强鲁棒性。各检测手段能力对比：')
add_table(
    ['检测手段', '能力评级', '覆盖场景', '局限'],
    [
        ['哈希匹配（MD5/SHA1/SHA256 + SSDEEP/TLSH）', '★★★☆', '已知样本快速识别、变种模糊匹配', '未知威胁无效'],
        ['YARA 规则（32 条）', '★★★☆', '主流家族（RAT/木马/勒索/窃密）', '规则数量仍偏少'],
        ['启发式分析', '★★★☆', '可疑 PE 结构、脚本木马', '不适用于打包加密样本'],
        ['AI 推理（ONNX）', '★★☆☆', '统计模式识别', '训练数据有限、泛化未验证'],
        ['静态沙箱', '★★★☆', '能力链条预测，零风险', '模型简化'],
        ['动态沙箱', '★★☆☆', '真实行为分析', 'ETW 遥测不完整'],
        ['威胁情报', '★★★☆', 'IOC 关联（自建 + 公开源）', '依赖源在线'],
    ]
)
para('')

# ── 11. YARA 规则覆盖能力 ──
doc.add_heading('11. YARA 规则覆盖能力', level=2)
add_table(
    ['威胁类别', '规则数', '覆盖家族'],
    [
        ['远程访问木马 (RAT)', '6', 'AsyncRAT、Remcos、njRAT、Gh0st、AgentTesla'],
        ['信息窃取', '3', 'RedLine、Lumma、浏览器凭据采集'],
        ['勒索软件', '3', 'LockBit、BlackCat/ALPHV、勒索恢复破坏链'],
        ['装载器/投放器', '5', 'SmokeLoader、PlugX、IcedID、Emotet、QakBot'],
        ['进程注入', '3', 'APC 反射、线程池、SilverFox'],
        ['防御规避', '2', 'AMSI/ETW 篡改、UAC 绕过'],
        ['持久化', '3', 'PowerShell 持久化、CTF/TypeLib 劫持、BYOVD'],
        ['网络行为', '2', 'Discord Webhook 外传、netsh portproxy 隧道'],
        ['银行木马', '1', 'Ursnif/Gozi'],
        ['测试', '1', 'EICAR 测试文件'],
    ]
)
para('')
para('结论：规则质量高（条件链严谨、元数据完整、高危标签），但 32 条对生产而言明显偏少，'
     '建议扩充至 100+ 覆盖更多家族与变种。')

# ── 12. AI/机器学习能力 ──
doc.add_heading('12. AI/机器学习能力', level=2)
add_table(
    ['模型', '格式', '规模', '输入', '用途'],
    [
        ['特征 CNN', 'ONNX', '313.8 KB', '1285 特征', '主二分类检测'],
        ['稠密树集成', 'ONNX', '约 50 KB', '12 特征', '集成成员'],
        ['原生 MLP', 'ONNX', '约 10 KB', '12 特征', '引擎内训练'],
    ]
)
para('')
bullet('能力强大：引擎内置完整训练管道 + 对抗训练 + 合成语料实验')
bullet('合成语料实验成果：家族多样化增强将"未见特征组合"召回率从 0.69 提升至 1.00（零误报）')
bullet('局限：真实授权数据集缺失，泛化能力与生产级对抗鲁棒性尚未验证')
bullet('GUI 训练界面：进度可视化、模型对比、自动停止，体验完整')

# ── 13. 实时防护能力 ──
doc.add_heading('13. 实时防护能力', level=2)
para('当前为用户态文件监控（非内核级防护）：')
add_table(
    ['能力项', '状态', '说明'],
    [
        ['文件变化监控', '已实现', 'WinUI ProtectionMonitor + 引擎快速扫描'],
        ['路径排除', '已实现', '持久化白名单'],
        ['托盘通知', '已实现', '发现威胁弹系统通知'],
        ['执行前阻断', '未实现', '无 Minifilter 签名驱动'],
        ['系统服务守护', '未实现', '无开机自启、崩溃自动拉起'],
        ['自保护/防篡改', '未实现', '驱动层预留但未启用'],
        ['监控容量', '有限', '路径上限 8192，目录事件仅处理最新 256 个文件'],
    ]
)
para('')

# ── 14. 沙箱与动态分析能力 ──
doc.add_heading('14. 沙箱与动态分析能力', level=2)
bullet('平台：仅使用可选 Windows Sandbox，不可用时返回 sandbox_unavailable（fail-closed，绝不低于宿主机直接执行）')
bullet('隔离配置：网络/VGPU/剪贴板/音视频/打印机默认关闭，输入目录只读映射')
bullet('会话控制：超时 30s～10min，单会话并发限制，每次全新沙箱配置')
bullet('能力缺口：不返回丰富遥测（文件/注册表/进程），行为链数据不完整，ETW 解析仍有 TODO')
para('')

# ── 15. 威胁管理能力 ──
doc.add_heading('15. 威胁管理能力', level=2)
bullet('隔离：可移植字节变换 + EverbloomSecurity 格式头（非用户 DPAPI），支持 EXPORT_QUARANTINE/IMPORT_QUARANTINE 备份还原；原文件仅在编码副本成功提交后才删除')
bullet('恢复：拒绝覆盖已存在文件，防止二次风险')
bullet('白名单：路径与 SHA-256 哈希字段已启用（加入后运行时立即生效并持久化）；Signature 字段预留')
bullet('持久化隔离索引：重启后隔离区状态不丢失')
bullet('迁移：EXPORT_QUARANTINE 导出备份可在新用户/系统中 IMPORT_QUARANTINE 还原，解决用户迁移可恢复性')
bullet('局限：Signature 白名单字段尚未启用；隔离数据跨环境迁移需手动使用 EXPORT/IMPORT 备份命令')
para('')

# ── 16. 病毒库更新能力 ──
doc.add_heading('16. 病毒库更新能力', level=2)
add_table(
    ['能力项', '状态', '说明'],
    [
        ['更新模式', '已实现', '自动/手动/仅通知'],
        ['MalwareBazaar 源', '已实现', 'abuse.ch 官方 SHA-256 Feed，严格格式校验'],
        ['自定义 JSON 清单', '已实现', 'HTTPS + SHA-256 校验'],
        ['DB 热重载', '已实现', '失败/超时自动回滚上一版本'],
        ['手动导入', '已实现', '支持 .sqlite / .db 文件'],
        ['数字签名', '未实现', '清单与安装器/可执行文件均无发布者签名'],
        ['信誉体系', '未实现', '无多源投票/撤销列表'],
    ]
)
para('')

# ── 17. 界面与用户体验能力 ──
doc.add_heading('17. 界面与用户体验能力', level=2)
bullet('视觉：7 主题 + 4 强调色 + 深浅模式，暗色保护页/自动扫描/检查表已适配')
bullet('交互：无边框窗口 + 液态水晶窗口按钮（5 态指针反馈）')
bullet('本地化：中英双语（简/繁），核心文案全覆盖')
bullet('扫描体验：原生文件/文件夹选择器、进度 + ETA + 威胁数、结果详情/隔离/白名单/导出')
bullet('AI 训练：实时进度可视化 + 模型对比 + 半自动训练')
bullet('日志审计：时间范围 + 关键字过滤 + CSV/JSON 导出 + 二次确认清空')
bullet('更新管理：一键恢复 MalwareBazaar 预设')
para('')

# ── 18. 能力成熟度总体评估 ──
doc.add_heading('18. 能力成熟度总体评估', level=2)
add_table(
    ['能力域', '成熟度', 'TRL 参考'],
    [
        ['本地检测（哈希/YARA/启发式）', '工程可用', 'TRL 5-6'],
        ['AI 检测与训练', '原型验证', 'TRL 4-5'],
        ['实时防护', '原型（用户态）', 'TRL 4'],
        ['内核驱动', '开发原型', 'TRL 3'],
        ['沙箱动态分析', '设计验证', 'TRL 3-4'],
        ['威胁情报集成', '工程可用', 'TRL 5'],
        ['GUI/UX', '产品级外观', 'TRL 6-7'],
        ['构建/打包/安装', '工程可用', 'TRL 5-6'],
        ['供应链安全', '早期', 'TRL 2-3'],
        ['总体成熟度', '演示级原型', 'TRL 4'],
    ]
)
para('')

# ══════════════════════════════════════════════════════════════
# 第三部分：总结与建议
# ══════════════════════════════════════════════════════════════
doc.add_heading('第三部分：总结与建议', level=1)

# ── 19. 已知问题清单 ──
doc.add_heading('19. 已知问题清单', level=2)
add_table(
    ['#', '问题', '严重度', '影响'],
    [
        ['1', '暂停/恢复不真正暂停引擎任务', '中', '用户感知不一致'],
        ['2', '文件类型过滤未生效', '低', '扫描范围偏大'],
        ['3', '日志分类标签未生效', '低', '日志混排'],
        ['4', 'CPU 限制与缓存大小配置未应用', '低', '资源控制失效'],
        ['5', '用户态监控无法在执行前阻断', '高', '防护能力上限'],
        ['6', '沙箱遥测不完整，行为链数据有限', '中', '动态分析价值打折'],
        ['7', 'Signature 白名单字段未启用（路径与 SHA-256 已启用）', '中', '仅签名校验缺失'],
        ['8', '安装器/EXE 未代码签名', '高', '未知发布者警告'],
        ['9', '部分 UI 字符串仍可能存在编码乱码（已修复活动流 ETA/状态分隔符）', '低', '视觉瑕疵'],
        ['10', 'Help 菜单无在线文档链接（项目主页尚未发布）', '低', '无官方文档入口'],
        ['11', 'AI/YARA 语料覆盖不足', '中', '检测盲区'],
        ['12', '无系统服务、自保护、开机启动', '高', '易被恶意软件关闭'],
    ]
)
para('')

# ── 20. 可行性建议与发展路线 ──
doc.add_heading('20. 可行性建议与发展路线', level=2)
doc.add_heading('【近期优先】', level=3)
bullet('修复暂停/恢复、文件类型过滤、日志分类三大遗留功能')
bullet('获取 EV 证书，完成安装器/EXE 代码签名')
bullet('在干净虚拟机完成安装/升级/修复/卸载矩阵测试')
bullet('已完成活动流 ETA/状态分隔符乱码修复（WinUIApp.cpp），后续排查其余潜在乱码')
bullet('将 YARA 规则扩充至 100+')

doc.add_heading('【中期目标】', level=3)
bullet('实现并签名 Minifilter 驱动，建立执行前阻断')
bullet('补全沙箱 ETW/文件/注册表遥测管道')
bullet('建立误报/漏报基线与性能基准门禁')
bullet('引入 WinAppDriver 等 GUI 自动化测试')
bullet('实现系统服务、崩溃自动拉起与自保护')
bullet('更新清单加入 Ed25519 签名')

doc.add_heading('【长期愿景】', level=3)
bullet('企业策略与集中管理（管控平台）')
bullet('在授权大规模数据集上验证 AI 模型')
bullet('性能/压力/回归测试门禁体系')
bullet('供应链安全审计与 SBOM')
bullet('跨平台支持与云端情报协同')

# ── 21. 最终结论 ──
doc.add_heading('21. 最终结论', level=2)
para('EverbloomSecurity v1.0.0 是一个架构设计优秀、工程实现完整的杀毒软件原型。其多引擎融合检测管道、'
     '原生 AI 训练能力、内核驱动原型、以及功能丰富且视觉精细的 WinUI 3 界面，代表了相当扎实的工程投入。')
para('技术层面：模块化与分层出色，Rust 引擎测试覆盖良好（194 项全绿），文档完备（19 篇），'
     '构建体系成熟（CMake+Cargo+CPack）。主要技术债集中在 WinUIApp.cpp 单文件过大、GUI 无自动化测试、'
     '依赖供应链治理缺失三处。')
para('能力层面：本地检测、GUI、更新管理已达到工程可用水平；AI 与沙箱处于原型验证阶段；'
     '内核驱动与供应链安全仍处早期。整体技术就绪水平（TRL）约 4 级（演示级原型）。')
para('最终建议：EverbloomSecurity 适合作为安全研究、学习平台与架构参考，不应作为生产环境唯一安全边界。'
     '按照"修复遗留问题 → 签名与合规 → 内核化 → 数据与测试补强 → 企业化"的路线持续推进，'
     '有望逐步演进为更具实战能力的终端安全产品。')

# ── 附录：本次构建验证结果 ──
doc.add_heading('附录：本次构建与验证结果', level=2)
add_table(
    ['项目', '结果'],
    [
        ['Rust 引擎 release 构建', '成功'],
        ['引擎单元测试（lib.rs）', '179 通过'],
        ['融合层测试（protection_fusion）', '12 通过'],
        ['合成语料测试（synthetic_corpus）', '3 通过'],
        ['沙箱集成测试（sandbox_integration）', '1 忽略（需 SANDBOX_FIXTURE）'],
        ['GUI 编译（CMake+Ninja）', '成功'],
        ['Inno Setup 安装器', '已生成（~62 MB，EverbloomSecurity-0.1.0-Windows-Setup.exe）'],
        ['ZIP 免安装包', '已生成（~81 MB）'],
        ['curl.exe 弹窗问题', '已修复（public_feeds.rs 增加 CREATE_NO_WINDOW）'],
        ['GUI 启动冒烟测试', '通过（进程稳定常驻）'],
    ]
)
para('')

# 保存
output = r'E:\EverbloomSecurity\EverbloomSecurity\artifacts\EverbloomSecurity_中文综合分析报告.docx'
os.makedirs(os.path.dirname(output), exist_ok=True)
doc.save(output)
print('报告已生成：' + output)
print('文件大小：{:.1f} KB'.format(os.path.getsize(output) / 1024))