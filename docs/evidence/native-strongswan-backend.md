# Native strongSwan 后端：数据面打通记录（2026-10-17）

结论：用本仓库补丁版 strongSwan 6.0.7 自己的 charon（kernel-libipsec + VICI）
替代厂商 x86_64 helper 连接 NC 资源，在打开 `charon.leadsec_new_client_vid`
后稳定可用：A/B 对照补 VID 6/6、不补 0/6，随后连续 10/10，每次都 `ssh` 成功并收到回程 ESP。

下面先记录 2026-10-17 的隔离实验；当时正式 CLI 仍走厂商 helper。
2026-10-18 的产品接入与后续 review 验证单独记录，不能把旧实验当成新版 helper 的 E2E。

## 组成

| 层 | 位置 | 作用 |
|---|---|---|
| Portal → VICI 映射 | `Sources/PowerVPNCore/NativeTrialMaterial.swift`、`Sources/PowerVPNProduct/NativeTrialPortalBridge.swift` | 把 Portal 下发的 NC 资源翻译成 VICI `load-shared` / `load-conn`：PSK、IKEv1 Main Mode、remote TS `0.0.0.0/0`、ADDRULE 私有信封、proposal number 0 |
| 实验驱动 | `Sources/PowerVPNNativeTrial/`（`powervpn-native-trial`） | 登录 Portal，连接隔离的 charon VICI socket，发起 CHILD，做 SSH/UDP 探测并输出 JSON 证据 |
| charon 补丁 | `patches/strongswan-6.0.7/0004-…patch`，清单 `native-series.json` | child 级 ADDRULE 与 proposal number、Quick Mode 发送 ADDRULE、NC IPv4 与 `NEW CLIENT` Vendor ID、VIP 归属保护 |

## 根因：缺 `NEW CLIENT` Vendor ID

厂商客户端在 Main Mode 第一个包里发 7 个 Vendor ID，native 只发 6 个，少的是
`NEW CLIENT`（`90fba3cf65e311f629e71f2603530b87`）。线上表现为 MM1 长度
217 字节对 197 字节，相差的 20 字节就是这一个 VID 加 payload 头。

缺这个 VID 时，网关照常完成 IKE 和 Quick Mode，CHILD 也能装好，**入向流量会被解密并转发**
（UDP 探针 50/50 到达目标机），但网关**从不向虚拟 IP 回发 ESP**（Mac 端
0 个入向 ESP）。补上之后回程立即恢复。

| 测试 | SSH 成功 | 回程 ESP |
|---|---:|---:|
| 不补 VID | 0/6 | 0 |
| 补 VID（与不补交替） | 6/6 | 141 包 |
| 补 VID（连续复验） | 10/10 | 229 包 |

样本只计 Portal 有效的会话。Portal 偶发 `integration_info_missing` 时直接重试，这些会话不计入。

## 已排除的方向

在 vendor 基线 8/8、native 0/24 的同时段对照下，下列方向都单独测过，与成败无关：

- Quick Mode proposal number（0/1）和 SA lifetime
- 本地端口浮动（50020→50021）对比单端口
- QM3 之后首包延迟（固定等 2 秒：0/8）
- SPI 取值、local/remote TS（`/32` 与 `0.0.0.0/0`）、ADDRULE 条数和字段
- 网关残留会话：native 断开时确实发出了 IKE/ESP DELETE

QM1–QM3 明文在 VIP 字段归一化后，与 vendor 逐字节一致，所以排查最后落到 Main Mode 上。

## 验证方式与边界

- 隔离运行：charon 跑在独立前缀和 VICI socket 上，只接管目标的 `/32` 路由；
  每次窗口前后都校验默认路由、DNS 和 utun 回到基线。
- 判据：外层 en0 抓包按本次协商的 SPI 统计入/出 ESP，排除 NAT keepalive；
  内层以 `ssh <target> true` 或带序号的 UDP 回显为准。
- 已知缺口：A/B 和复验都用单端口客户端；补 VID 之后“端口浮动”这一格没有单独复测。
- 未解释：早期少数不补 VID 也成功的样本，可能是网关上同一 VIP 的残留绑定，没有验证。
- 不在仓库里：原始抓包、Portal 返回内容和测试用的特权 runner。

## 2026-10-18：接进 run / up / ssh

- 运行时由 `scripts/native/build_runtime.sh` 从官方 strongSwan 6.0.7 加 `0001`–`0004` 补丁重新构建，
  安装到 `/Library/PrivilegedHelperTools/com.hhh2210.powervpn-native/`，由 root helper（LaunchDaemon）常驻运行。
- helper 只接受 `status`、`route-add`、`route-delete` 三种请求。`route-add` 只有在指定的 IKE SA 已经
  ESTABLISHED 且有 INSTALLED 的 child 时才加路由，接口取自该 SA 的虚拟 IP 所在的 utun。每 5 秒核对一次，SA 没了就删路由。
- 实测（thu52、thu21，Surge Enhanced Mode 开着）：
  - 冷启动 `powervpn run thu52 -- hostname` 用时 1.5 s，复用会话 0.11 s；
  - 目标 `/32` 走 native 的 utun，默认路由仍是 Surge 的 utun；
  - `powervpn down` 用时 0.6 s，核对通过：路由删除、SA 清空、helper 名下无路由；
  - thu21 第一次连接遇到 Portal 资源目录不完整（已知的间歇问题），现在 open 内会重新登录重试，最多 3 次。
- child SA 的生存期是 1 小时。现在在到期前 5 分钟 rekey；rekey 是否被网关接受，见下面的长连接记录。

### 15:57 旧版 child rekey 观察

此结果属于已安装的 `c26d94d` 构建，**不代表下节 review 修复后的新版已通过 E2E**。
2026-10-18 15:57:21（Asia/Taipei）的 `swanctl --list-sas` 与随后同会话命令显示：

- IKE `powervpn-thu21-99dc6eab` 仍为 ESTABLISHED，已建立 3434 秒，没有重建 IKE。
- 旧 child #3 为 REKEYED，距硬到期还有 166 秒；新 child #4 为 INSTALLED，已建立 134 秒，
  下一次 rekey 还有 3166 秒。由 `3434 - 134 = 3300` 可见首次 rekey 落在 3600 秒 lifetime 前 300 秒。
- 新 child 已有双向数据：入 9 包、出 18 包。旧 child 最后流量在 146 秒前；观察时新旧 SA 重叠存在，
  支持此次 make-before-break 成功。
- `powervpn run thu21 -- 'echo post-rekey-ok'` 返回 `post-rekey-ok`、`run_exit=0`；目标路由仍在 `utun9`。

证据边界：一次旧版 child rekey 与续传成功。新版仍需重测；sleep/wake、网络切换和 8 小时 IKE rekey 未覆盖。

## 2026-10-18：PR #3 review 修复

上节 live 数字来自 `c26d94d` 及其前置构建，不是本节新版 helper 的验证结果。

- charon VICI 移到 root-only 目录；用户通过 peer UID 检查的代理，逐帧校验命令、事件和连接字段。
  安装时移除 ACL，校验运行时树、链接和权限；OpenSSL engine/provider 搜索路径固定到 root 空目录。
  路由只允许安装时从 targets.json 固定下来的 host。
- SA 查询不再使用 `noblock`；超时/未知不作为删除证据。shutdown 核实 SA、连接和共享密钥，保留失败结果。
  Portal 超时或旧 owner 退出后，只能报告本地恢复；未确认的 Portal 登出记录保留/归档。
- 会话持久化 backend；恢复持有 mutation lease 到状态提交，迟到 proxy 在取得 lease 后再次检查 owner。
  Portal 传输/目录失败与认证拒绝分开，native 清理不确定的启动也受两次重试上限约束。
  VIP 调试输出改为 trial 显式 sink，产品不读取调试环境变量。
- 本机隔离全量测试 991 个通过；复审追加修复后针对 Native / Proxy / UserProduct / ProductPersistent 的
  134 个测试通过。独立 Codex 静态复审的两个追加 finding 已关闭，无剩余已证实 finding。
- 后续安装与短程 E2E 记录见下节；未覆盖 sleep/wake、网络切换、新版长周期 child rekey 和 8 小时 IKE rekey。
  全程未改 Surge 配置，未读取厂商敏感日志。

## 2026-10-18：新版安装与 Portal 登出证据

安装后的 raw VICI 位于 root-only 目录，普通用户连接返回 EACCES；用户代理的 version/list-sas 请求可用，禁止的命令被关闭连接。
新版 thu21 连接和同会话复用成功，复用约 0.12 秒；thu52 新连接约 1.58 秒。目标流量走 native utun，默认路由与 DNS 未变。

首次 `down` 暴露了原有 Portal 证据缺口：本地 route/SA/connection/shared key 都已删除，但 logout 被记为 transport_failed。
通过在进程内提前构造同一 cookie generation 的三份 sealed request（只读 session check / logout / 只读 session check），
在 thu21 与 thu52 两个新会话上观察到相同结果：

| 阶段 | HTTP / transport | Portal 结果 |
|---|---|---|
| 登出前，只读探测 | HTTP 200 | `RESULT/@code=0`，会话有效 |
| 登出 POST | HTTP 302，curl code 0，OS errno 0 | 客户端禁止重定向，归类为 redirect_rejected |
| 同一 cookie 登出后，只读探测 | HTTP 200 | `RESULT/@code=0x80000014`，会话已失效 |

因此本次并非连接超时、TLS 失败或会话泄漏：网关完成登出后返回重定向，旧逻辑将其笼统归为传输失败。
`c26d94d` 的 NativeTunnel 只检查 logout status accepted，而 AuthenticatedPortalLease 会把非取消的传输错误转换为 accepted；
该代码遇到这类 302 会误称已验证。旧版 15:00 前后的具体登出没有保存传输分类，不能追溯断言每一次旧报告都是 302。

修复保留“不跟随重定向”，以原 cookie 的后置失效证据确认 Portal 清理。HTTP 302 本身、请求已发出、网络/解析错误都不能算确认。
探测严格识别 RESULT/@code（兼容历史测试的 RESULT/code 文本），未知 code/歧义字段 fail closed；超时保留已完成的 post 证据。
只记录数值/枚举，不记录 cookie、凭据、请求/响应正文；所有 sealed request 在结束时擦除。

新版 `down` 已返回 exit 0、`Cleanup: verified`。独立检查 helper 名下路由为空，目标路由恢复，默认路由与 DNS 和基线相同。
如果以后 post 明确仍有效，自动重连保持隔离；操作人确实在 Portal 结束会话后，可用显式 acknowledgement 配合本地实测解除重连限制，
原始回执和 cleanupVerified=false 仍保留，不冒充服务端失效证明。

### native status 的 vendor 历史误报

错误 warning 来自 `SystemInspector` 读取的 vendor LaunchDaemon 历史计数（14 次 crash、last signal），不是 recovery archive。
status 原来无条件运行该 inspector；现在只对活动/未解除隔离会话的 backend 做对应诊断，已完成的记录按当前配置选择诊断来源。
native status/doctor 不再读取 vendor 日志或展示 vendor 历史 crash。真实未清理的 vendor session 仍明确命名 vendor 并要求实测恢复。
21 份旧 recovery archive 保留，不将历史归档等同于当前故障。
