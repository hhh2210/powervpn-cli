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

## 2026-10-18：PR #3 review 修复（待安装验证）

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
- 尚未验证：新版特权 helper 安装/升级时序、新版连接/断开 E2E、sleep/wake、网络切换、8 小时 IKE rekey。
  本轮没有替换已安装 helper 或 CLI，没有改 Surge 配置，也没有读取厂商敏感日志。
