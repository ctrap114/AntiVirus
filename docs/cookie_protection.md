# Browser Cookie Protection

Everbloom Security 的 Cookie 防护由扫描层、用户态 HIPS 和可选内核文件过滤器共同组成。

## 扫描层

- 识别 Chromium 系列的 `Network\Cookies` 以及 Firefox 的 `cookies.sqlite`、`-wal`、`-shm` 存储路径。
- 对可执行文件和脚本进行多信号关联：浏览器数据库引用、SQLite/`DPAPI`/`CryptUnprotectData`、本地复制或读取、压缩以及 HTTP/网络外传迹象。
- 单独出现 `Cookies` 路径、`DPAPI` 或普通网络库不会直接判恶；达到多信号高置信度后才生成 `cookie_theft_detected`。
- 扫描浏览器数据库时只做路径元数据分类，不读取 Cookie 行、值或加密内容，也不会把这些内容写入日志、缓存或云占位接口。

## 主防层

- HIPS 对新启动的进程镜像做有上限的静态检查，并识别少量明确的浏览器数据工具名称；事件只记录稳定的指标标签。
- 高置信度事件进入现有驱动审查队列，与现有的进程注入、RWX、API Patch 和侧加载信号一起交给融合层。
- 内核 minifilter 在驱动防护开启时，对非浏览器、非 EverbloomSecurity/Defender 进程打开浏览器 Cookie 数据库的读请求返回拒绝；浏览器正常访问和 Everbloom Security 扫描保留在豁免名单内。

## 边界与建议

没有驱动时，用户态 HIPS 不能证明每一次底层文件读取，只能根据进程镜像和其他行为做关联；驱动安装并成功加载后，Cookie 数据库读打开才有内核级拒绝能力。重命名、内存驻留或通过已被允许的浏览器进程执行的窃取行为仍需要结合进程句柄、脚本命令行和网络关联继续增强。
