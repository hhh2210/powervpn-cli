---
title: PowerVPN Apple Silicon 原生协议核心（strongSwan 6.0.7）
status: ready-for-codex-goal
updated: 2026-08-08
goal_type: long-running, evidence-driven prototype
repository: /Users/larry_1/Opensource/powervpn-cli
scratch_root: /Users/larry_1/scratch-data/powervpn-strongswan
upstream_target: strongSwan 6.0.7
vendor_compatibility_baseline: strongSwan 5.8.0
current_checkpoint: 3-oracle-safety-and-schema
primary_platform: Apple Silicon macOS 27 beta
---

# PowerVPN Apple Silicon 原生协议核心：Codex Goal

## 启动方式

把本文件复制到仓库根目录并命名为 `GOAL.md`，从
`/Users/larry_1/Opensource/powervpn-cli` 启动：

```text
/goal Implement GOAL.md. Continue checkpoint by checkpoint until Success Path A or Evidence-Complete Blocked Path B is fully satisfied. Treat the verified baseline in GOAL.md as already completed work; do not repeat it without a concrete verification reason. Update docs/progress/GOAL_STATUS.md after every checkpoint. Pause only at the explicit approval gates.
```

若 `/goal` 尚未启用：

```bash
codex features enable goals
```

## 1. Durable objective

在**不修改服务端、不绕过正常认证、不依赖厂商 x86_64 helper、不把
watchdog 或重启 GUI 包装成修复**的前提下，在当前 Apple Silicon Mac 上
构建一个可回滚、可验证的 PowerVPN 原生协议核心：

1. 用厂商 strongSwan 5.8.0 fork 作为行为和 wire-contract oracle；
2. 用 upstream strongSwan 6.0.7 作为唯一产品 runtime 基线；
3. 复现标准 IKEv1 Main Mode / Quick Mode 基础；
4. 在 6.0.7 上重写最小 ADDRULE/DELRULE resource-rule 扩展；
5. 复现合法控制面，使动态认证材料和资源元数据进入受控 runtime；
6. 用正交、事件驱动状态机避免假在线；
7. 与 Surge 共存，只安装目标资源的精确路由；
8. 最终建立至少一个已授权资源的原生 tunnel，或者对第一个不可兼容点
   给出证据完整、可继续工程化的阻塞结论。

核心问题已经从“`leadsecbridge` 是否私有”收敛为：

> 如何在 upstream strongSwan 6.0.7 上，以最小可维护 patch 复现厂商
> ADDRULE/DELRULE payload、IKEv1 task 时序和 resource data path？

“只编译出 strongSwan”不是完成条件。

## 2. Verifiable stopping conditions

Goal 只能在下列两个终态之一完全满足后结束。

### Success Path A：原生单资源 tunnel 成功

必须同时满足：

- strongSwan 6.0.7 的 `charon`、VICI 和实际使用的数据面后端均为
  `arm64`；
- runtime 不运行厂商 `charon-xpc`、`ipsec-xpc`、`sh-xpc`，不依赖
  Rosetta；
- 使用用户合法持有的认证材料，不绕过服务端认证；
- 标准 IKEv1 Main Mode、base Quick Mode/CHILD_SA 与私有 ADDRULE 均完成；
- 至少一个已授权 resource 的 desired/observed state 一致；
- 该 resource 的精确 `/32` route/policy 可结构化检查；
- 全新 TCP 连接收到目标 SSH banner；
- Surge 仍运行，默认路由和 DNS 未被原型接管；
- 停止原型后不残留 SA、route、policy、utun、VICI socket 或 secret file；
- `pvnative status --json` 或等价命令分别报告 control session、tunnel、
  path generation、resource 和 end-to-end probe，不能只给一个
  `connected` 布尔量；
- 一次经批准的路径变化后，原型能有界恢复或明确进入 degraded/blocked，
  不产生假在线；
- 所有构建、启动、停止、验证和回滚步骤可重复；
- Git、日志和 fixtures 中没有密码、session ID、PSK、token、cookie、
  私钥或可重放 payload。

### Evidence-Complete Blocked Path B：阻塞结论完整

若 Success Path A 无法达到，必须同时满足：

- 6.0.7 arm64 build、测试和候选 backend 证据完整；
- 对厂商 5.8.0 行为基线有至少两类独立证据；
- 明确记录最后一个成功状态与第一个失败事件；
- 阻塞点精确落入下列一层或多层：
  - portal/control-plane schema 或动态材料来源；
  - session-to-PSK/VIP/resource binding；
  - ADDRULE/DELRULE body codec；
  - IKEv1 payload ordering、HASH、message ID 或 Vendor ID；
  - 5.8.0 → 6.0.7 task/plugin API 语义变化；
  - PF_KEY/PF_ROUTE SA 或 route 安装；
  - kernel-libipsec/utun 数据路径；
  - Surge 共存；
  - 客户端完整性或签名校验；
- 每个已排除假设都有命令、结构化日志、pcap 摘要、VICI event、
  disassembly fact 或最小 fixture；
- raw secret/capture 不进入 Git；
- 下一项最小工程任务有明确输入、输出和验收条件；
- 没有为了完成 Goal 而退回厂商 helper、GUI 自动重启、无界 watchdog、
  服务端改造或中转 gateway。

## 3. 2026-08-08 verified baseline

以下事实已由本机文件、符号、允许列表日志、官方 source 和真实构建验证。
后续 agent 不得把它们降级为猜测，也不得无目的重复调查。

### 3.1 Vendor baseline

- PowerVPN 为 3.2.1 build 24572，主程序和特权 helper 为纯 x86_64；
- `charon-xpc` 的未剥离 OSO/SO 路径明确包含：
  - `strongswan/lib5.8.0/libcharon.a(...)`；
  - `strongswan-5.8.0/src/...`；
- 因此厂商 upstream baseline 为 **strongSwan 5.8.0 confirmed**，不是按
  日期猜测；
- vendor patch level 仍是 unknown；
- `leadsecbridge` 以 critical plugin 身份加载，并提供
  `CUSTOM:kernel-ipsec`；
- 二进制包含 `vpn_kernel_ipsec_register`、`ncv1_add_policy`、
  macOS utun/kernel-libipsec 路径；
- 成功会话明确生成 IKEv1 QUICK_MODE `[HASH ADDRULE]`；
- 二进制同时含 ADDRULE、DELRULE、`expandrule_payload_create`、
  `expandrule_notify_create` 和 Quick Mode task 接线；
- 因此 `leadsecbridge` 分类是 **B + C confirmed**：
  - B：自定义 strongSwan plugin/kernel backend；
  - C：私有 IKEv1 resource-rule wire extension；
- 它不是只把 JSON 翻译为标准 swanctl/VICI config 的 A-only 层；是否还
  同时承担部分 A 职责可以保持 unknown，但不影响 B+C 结论。

### 3.2 Negotiated protocol facts

- IKE 为 IKEv1 Main Mode；
- machine authentication 有 PSK 证据；
- 已观察 IKE proposal：
  `AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024`；
- 已观察 ESP proposal：`AES_CBC_128/HMAC_SHA1_96/NO_EXT_SEQ`；
- 标准 IKE_SA 和 base CHILD_SA 先建立，随后发送 ADDRULE；
- 当前成功日志没有观察到 XAuth 或 Mode Config transaction；
- 二进制中存在 XAuth/Mode Config code 只代表 static capability，不能写成
  negotiated behavior；
- 不得擅自强化 proposal。服务端不变时，第一轮 interop 必须精确复现
  观察到的兼容参数。

### 3.3 Network/data-plane facts

- 历史成功连接由 PowerVPN 创建 `utun9`；
- 当前 `utun8` 是 Surge Enhanced Mode 的 packet tunnel，地址空间为
  `198.18.0.1/15`；
- 把 `utun8` 写成 PowerVPN interface 是已纠正的旧错误；
- upstream 6.0.7 自带 macOS utun 创建代码，kernel-libipsec 可直接使用，
  暂不需要自写 PacketTunnelProvider 或 packetFlow adapter；
- Apple built-in VPN/PacketTunnelProvider 可能禁用其他 app 的 VPN config，
  不能作为无副作用的便宜实验；
- 目标共存形态是：

  ```text
  Surge system extension -> utun8 / default route
  PowerVPNNative daemon  -> independent backend/utun / exact resource routes
  ```

### 3.4 strongSwan 6.0.7 build facts

- 官方 tag：`6.0.7`；commit：
  `5973ff8e41deef4e015e1138a2de688acedf6f75`；
- tag commit 时间为 2026-06-07；GitHub release publishedAt 为
  2026-06-08T13:30:38Z；
- source：
  `/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7`；
- build：
  `/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-arm64`；
- scratch prefix：
  `/Users/larry_1/scratch-data/powervpn-strongswan/install-6.0.7-arm64`；
- `charon`、`swanctl`、VICI、PF_KEY、PF_ROUTE、kernel-libipsec plugin 均为
  Mach-O arm64；
- `make -j8`、scratch-prefix `make install`、`make check -j8` 均 exit 0；
- libstrongswan、libipsec、VICI/libcharon 和 exchange test suites PASS；
- 非 root random-port smoke 中，PF_ROUTE/VICI/crypto/control plugins 成功
  加载；
- PF_KEY 与 kernel-libipsec 分别准确停在 `CAP_NET_ADMIN` gate；
- 这证明 build、link 和插件 ABI 可行，尚未证明 privileged runtime、SA
  安装、Surge 共存或服务端 interop；
- 6.0.3+ 强制 plugin version matching，厂商 5.8.0 plugin 不可直接加载到
  6.0.7；最终目标本来也禁止依赖 vendor x86 object。

### 3.5 Repository facts

- 当前仓库：`/Users/larry_1/Opensource/powervpn-cli`；
- 本地 `main` 无 remote/upstream，不得声称已同步远端；
- 现有 SwiftPM product 为 `powervpn`，library 为 `PowerVPNCore`；
- `reconnect` / `PowerVPNController` 已从当前未提交实现中移除；
- 新增只读 oracle、TunnelSpec redacted gate 和 historical-log 修正；
- vendor log 现由 FileHandle 分块逐行 allowlist，完整敏感日志不再被解码为
  String；
- TunnelSpec 已加入 VIP、NAT-T、session binding reference、map ID、
  tunnel/resource identifiers、routes、credential reference 和
  ADDRULE/DELRULE operations；
- XAuth/Mode Config oracle evidence 已明确标为 static compiled capability，
  不是 negotiated behavior；
- 当前 Swift 验证为 19 tests PASS、arm64 build PASS、live oracle/status PASS、
  `git diff --check` PASS；
- 当前 helper not running 时，旧 CLI 曾把历史 CHILD_SA 误报 healthy；新实现
  已返回 stopped，running 时也只把旧日志称为 historical hint；
- `/var/log/vsgvpn.log` 已知含敏感认证材料。已实现的流式 allowlist 是必须
  保持的安全回归条件；
- 当前 repo 改动尚未提交，Goal 启动时必须先审计并保留这些改动。

## 4. Version and patch strategy

### 4.1 5.8.0 的角色

允许：

- 作为 vendor behavior/wire oracle；
- 对照 payload、task、plugin API 和 object boundaries；
- 构建 clean upstream 5.8.0 以帮助最小化 6.0.7 patch；
- 只读分析 vendor 符号和受保护 capture。

禁止：

- 作为最终 runtime；
- 直接加载 vendor proprietary object/plugin；
- 长期保留一个“先能用再说”的 5.8.0 产品分支；
- 复制、发布或重新分发厂商二进制/反编译源码。

clean 5.8.0 build 是有价值的对照任务，但不得为了勾选“双版本构建”而
阻塞已经确认的 6.0.7 主线；只有当 API/wire diff 需要它时才继续。

### 4.2 6.0.7 的角色

- 唯一 native runtime 目标；
- 所有 payload/task patch、VICI adapter、daemon 和 state machine 的目标；
- 所有最终验收命令的目标版本；
- strongSwan patch set 必须独立、可审计、可针对 upstream tag 重放；
- 不把完整 strongSwan source tree vendoring 到 MIT Swift 仓库；
- 保留 strongSwan GPLv2/商业许可边界，Swift lab 的 MIT 许可不覆盖 upstream。

### 4.3 最小预期 patch surface

只实现观察到的行为：

1. `expandrule` 纯数据模型和严格 codec；
2. ADDRULE/DELRULE private payload 的 encode/decode/verify；
3. IKEv1 Quick Mode message rule/order；
4. 初始 base Quick Mode 后的 resource-rule task 调度；
5. 必要的 payload factory、task manager 和 bus/VICI adapter 接线；
6. 对 malformed length、unknown operation、duplicate rule 的负向测试；
7. 优先使用 upstream PF_KEY/PF_ROUTE；只有共存或 SA 安装证据失败时才切
   upstream kernel-libipsec + native utun。

不要移植：vendor GUI/XPC surface、helper 名称、更新逻辑、空恢复回调、
SM3/SM4、XAuth/Mode Config。后四项只有新 capture 证明服务端实际要求时
才进入 patch。

## 5. Scope

### 本 Goal 包含

- vendor app/helper/Mach-O/plugin inventory；
- control-plane、XPC、IKE 三边界的脱敏协议证据；
- TunnelSpec 与 strict redacted fixture gate；
- upstream 6.0.7 arm64 build、tests 和候选 backend 验证；
- 最小 ADDRULE/DELRULE patch；
- VICI-based native harness；
- 正交状态机与 deterministic tests；
- 经批准的一次标准 SA、一次单 resource 和一次恢复测试；
- Surge 共存、完整 teardown 和回滚；
- 最终可行性报告。

### 本 Goal 不包含

- SwiftUI/MenuBarExtra；
- App Store、notarization、正式安装包；
- 持久 LaunchDaemon 产品化；
- NetworkExtension/PacketTunnelProvider 产品化；
- 多用户、通用客户端或多个 resource 并发；
- 管理员、服务端、gateway 或中转机方案；
- vendor app/helper patch、重签名或永久 injection；
- 绕过认证、伪造 session、提取他人凭据；
- watchdog 或 GUI restart automation。

## 6. Safety and invariants

1. 不修改 `/Applications/PowerVPN.app`、其签名或
   `/Library/PrivilegedHelperTools/com.leadsec.*`。
2. 不执行 system-prefix `make install`，不安装持久 kext、LaunchDaemon 或
   system extension。
3. upstream source/build/prefix 保持在
   `/Users/larry_1/scratch-data/powervpn-strongswan`；大体积 tree 不进入仓库。
4. raw capture 另放 mode-700 scratch directory；Git 只保留脱敏 schema、
   manifest 和事实表。
5. 密码、PSK、session、cookie、token、私钥不得出现在 CLI output、Git、
   progress log 或普通临时文件。
6. 读取 vendor log 时先 allowlist 行，再组成 String；禁止完整读取后筛选。
7. 不关闭 SIP、Gatekeeper、hardened runtime 或系统安全策略。
8. 不把 TCP connect、GUI 开关、历史 CHILD_SA 或 route 单独当作 health。
9. 不用单一 `isConnected` 代表 control/session/tunnel/resource/path。
10. recovery 必须 single-flight、有 generation、有上限、有 cooldown。
11. manual disconnect 必须抑制自动恢复。
12. 任何停止厂商 VPN、启动 root daemon、绑定 500/4500、创建 SA/route、
    切网络或影响 Surge 的操作都属于 live approval gate。
13. 本机权限只能通过 macOS 原生授权对话框请求，不读取或代输密码。
14. 不在未批准窗口中测试 Apple built-in VPN/PacketTunnelProvider，因为它
    可能禁用 Surge 的 VPN configuration。

## 7. State and truth model

不得使用原稿中的单线状态机。至少保持以下正交维度：

```text
ControlSessionState
  signedOut / authenticating / ready / reconnecting / expired / failed

TunnelState
  idle / negotiating / established / degraded / recovering / backoff / blocked

PathGeneration
  monotonic generation + satisfied/unsatisfied + stable interface identity

ResourceState per resource
  desired(inactive|active) + observed(inactive|activating|active|failed|unknown)

UserIntent
  connect / disconnect
```

规则：

- WebSocket 断开不等于 SA 失效；
- SA 失效不等于 session 过期；
- path change 只触发 generation bump/debounce，不直接宣称 tunnel dead；
- IKEv1 无 MOBIKE 时，对旧 generation 做 single-flight teardown/re-initiate；
- 旧 callback/timer 不得覆盖新 generation；
- `Established/active` 只能由同一 generation 的 IKE_SA、base CHILD_SA、
  resource ADDRULE、精确 route/policy 和 SSH banner 联合确认；
- 缺少任一层时只能报告 degraded/unknown/failed。

## 8. Required repository artifacts

必须复用当前 SwiftPM 结构，不创建平行的 `src/` tree：

```text
README.md
Package.swift
Sources/
  PowerVPNCore/
  PowerVPNCLI/
Tests/
  PowerVPNCoreTests/
docs/
  2026-08-08-native-replacement-plan.md
  protocol-control-plane.md
  protocol-xpc.md
  protocol-ike.md
  strongswan-6.0.7-arm64.md
  progress/GOAL_STATUS.md
  evidence/
  architecture/
  reports/final-feasibility-report.md
fixtures/
  redacted/
captures/
  README.md
patches/
  strongswan-6.0.7/
scripts/
  build_strongswan.sh
  verify_no_secrets.sh
  run_native_charon.sh       # live gate 前才创建
  stop_native_charon.sh      # live gate 前才创建
```

规则：

- 已有同义文档直接更新，不复制到新目录；
- `scripts/` 只做参数解析、构建/启动编排和调用 library logic；
- 第二次重复的手工构建流程才固化为 script；
- patch 文件只包含对官方 6.0.7 的最小差异；
- raw captures、generated build、prefix、secrets 不进入 Git。

至少 gitignore：

```text
.build/
.swiftpm/
build/
prefix/
captures/raw/
fixtures/private/
secrets/
*.pcap
*.pcapng
*.keylog
*.key
*.p12
*.mobileconfig
```

## 9. Checkpoint plan

### Checkpoint 0 — boundary and rollback baseline — PASS

已验证：

- 仓库、分支、无 remote、初始 commit 和 dirty state；
- vendor app/helper 未修改；
- 旧 CLI 只是 diagnostic harness；
- 新路线排除 gateway、服务端管理员、厂商更新、watchdog 和 GUI restart。

Goal 启动时只需把证据摘要写入 `GOAL_STATUS.md`，不要重复全盘调查。

### Checkpoint 1 — vendor 5.8.0 + B/C classification — PASS

已验证：

- 5.8.0 debug/archive path；
- loaded plugin allowlist；
- custom `CUSTOM:kernel-ipsec`；
- ADDRULE/DELRULE/expandrule/Quick Mode markers；
- IKE/ESP proposal；
- PowerVPN utun9 与 Surge utun8 纠错。

仍需产出 commit-safe `vendor-inventory.json`，只含 marker 和 hash，不含 raw
symbol/log lines。

### Checkpoint 2 — upstream 6.0.7 arm64 baseline — PASS for build

已完成：official tag/commit、configure、arm64 build、scratch install、
`make check`、artifact `file`、PF_KEY/PF_ROUTE/kernel-libipsec/VICI load smoke。

未完成且不得混淆：privileged backend startup、SA install、utun lifecycle、
Surge coexistence、server interoperability。

下一步只需把现有手工命令固化成可重放 build script 和 evidence manifest；
不要重新下载或重新编译 6.0.7，除非 script forward-test 需要。

### Checkpoint 3 — oracle safety and TunnelSpec — PARTIAL

已完成并验证：

- 完成只读 `powervpn oracle inventory --json`；
- 文件读取已改为先逐行 allowlist，不把完整敏感 vendor log 载入 String；
- 将 XAuth/Mode Config 标为 static capability，而非 negotiated；
- historical log 只能叫 hint；helper generation 不一致时不能报 healthy；
- TunnelSpec 已表达：
  - endpoint/gateway reference；
  - IKE/ESP proposal；
  - authentication category 与 credential reference；
  - session binding reference；
  - NAT-T observation；
  - virtual IP；
  - map ID/tunnel name/resource identifier；
  - route/traffic selector；
  - ADDRULE/DELRULE capability；
  - tri-state unknown/observed/unsupported，而不是误用 Bool；
- `spec validate-redacted` 拒绝真实 secret、endpoint、resource name 与 CIDR，
  且错误报告不回显原值；
- secret-leak、partial-tail、strict schema negative tests 已通过；
- 当前共 19 tests PASS，arm64 build 和 live oracle/status PASS。

尚未完成：

- 创建 `fixtures/redacted/tunnel-spec.example.json`；
- 用 CLI 对该落盘 fixture 做一次 forward validation；
- 将 commit-safe oracle inventory 和 test summary 写入 evidence；
- 审计、拆分并提交当前 dirty worktree。

验收：

```bash
swift test
swift build --arch arm64
swift run powervpn oracle inventory --json
swift run powervpn spec validate-redacted fixtures/redacted/tunnel-spec.example.json
```

四条命令 PASS；源码无 reconnect/terminate/relaunch；oracle output 无 secret。

### Checkpoint 4 — offline expandrule contract and codec — NEXT

任务：

1. 从受保护 oracle/capture 恢复 ADDRULE/DELRULE body 的字段边界；
2. 标记每个字段 confirmed/inferred/unknown；
3. 确认 payload type、length、byte order、operation、resource/map binding；
4. 创建不含真实 endpoint/resource 的 synthetic golden fixtures；
5. 在独立 6.0.7 patch worktree 实现纯 codec；
6. 做 encode/decode byte-for-byte round trip；
7. 拒绝 malformed length、unknown op、oversize、duplicate rule；
8. 不启动网络、不连接服务端。

验收：offline tests 全部 PASS，且另一名工程师仅凭 schema/tests 能解释
payload，不需要查看 raw secret capture。

### Checkpoint 5 — control-plane and XPC oracle

经用户合法登录或复用合法现有 session，只记录：

- HTTPS method/path/status、field name/type/length；
- session check state transition；
- WebSocket message type/order/keepalive/resume；
- resource list/activation/deactivation schema；
- GUI↔helper XPC key/type/order；
- portal session 如何关联 PSK、VIP、mapID、tunnel/resource metadata。

禁止保存 header value、cookie、PSK、session、identity、raw body、TLS key log。
动态注入只能作为实验显微镜，不进入产品。

验收：三边界文档分开，字段均标 confirmed/inferred/unknown；raw capture 在
mode-700 scratch，Git 仅有脱敏 schema。

### Checkpoint 6 — 6.0.7 patch skeleton + VICI dry run

任务：

- 建立可针对 official 6.0.7 重放的最小 patch series；
- 加入 payload factory/message rules/task skeleton；
- 将 synthetic TunnelSpec 转为结构化 VICI load-conn；
- 不解析人类可读 `swanctl` 输出作为核心 API；
- random ports + scratch VICI socket；
- credential reference 缺失时安全失败；
- round-trip proposal、identity、selector 和 resource rule metadata；
- dry run 不创建 SA、route、utun。

验收：codec/tests 和 VICI dry run PASS，或精确定位第一个 6.0.7 API 阻塞。

### Live Approval Gate

执行下列任一动作前必须暂停并请求用户明确批准：

- 停止/退出当前 PowerVPN；
- 启动 root charon 或触发 macOS 权限对话框；
- 绑定 UDP 500/4500；
- 创建/删除 SA、policy、route、utun；
- 切换 Wi-Fi/热点、睡眠唤醒；
- 启用 Apple built-in VPN/NetworkExtension；
- 任何可能中断 Surge 或当前 SSH 的动作。

批准前必须存在：

```text
docs/evidence/live-test-plan.md
scripts/run_native_charon.sh
scripts/stop_native_charon.sh
docs/evidence/rollback.md
```

计划必须列影响、预计中断时间、一次只改一个变量、最大尝试次数、观察
指标和逐条回滚。需要用户注意时先发 macOS alert，再等待批准。

### Checkpoint 7 — privileged backend without server

经批准后，先不连接服务器：

1. PF_KEY + PF_ROUTE 启动、创建和完整清理 smoke；
2. 记录 Surge 前后 interface/default route/DNS；
3. 若 PF_KEY 失败，再测 upstream kernel-libipsec + native utun；
4. 每次停止后验证零残留；
5. 不同时启用两个 kernel-ipsec provider。

只在此 checkpoint PASS 后进入 server interop。

### Checkpoint 8 — standard IKEv1 server interoperability

经批准并限制尝试次数：

- 只选择一个已授权 resource；
- 先只建立标准 IKEv1 Main Mode + base CHILD_SA；
- 精确使用观察到的 proposal；
- 记录 current generation 的 VICI/IKE event；
- 不发送猜测的 ADDRULE；
- 失败时记录 last-good-state / first-bad-event；
- 完成后 teardown 和回滚。

验收：standard base SA PASS，或形成精确的 server/Vendor-ID/HASH/API blocker。

### Checkpoint 9 — single-resource ADDRULE

在 standard base PASS 后：

- 发送一个已验证的 ADDRULE；
- 只激活一个 resource；
- 验证 resource response、精确 `/32` route/policy、fresh SSH banner；
- 发送 DELRULE/断开并验证完整清理；
- 不测试多 resource 并发。

此 checkpoint PASS 才能宣称“技术 GO”。

### Checkpoint 10 — recovery and Surge coexistence

只在原生单 resource 已成功后并再次获批：

- 睡眠唤醒、断网 30–120 秒、Wi-Fi→热点各 10 次；
- 目标 10/10 正确恢复或明确 blocked；
- p95 恢复时间目标不超过 30 秒；
- 无重叠连接、重复 SA/route、旧 generation callback 或 secret log；
- Surge 始终保持预期 default route/DNS/functionality；
- manual disconnect 不自动重连。

真实 session expiry 不需人为等待；用 deterministic integration test 覆盖，
自然发生时再采证。

### Checkpoint 11 — final report

输出 `docs/reports/final-feasibility-report.md`：

- Success A 或 Blocked B；
- 5.8.0 oracle 与 6.0.7 target 的最小差异；
- ADDRULE/DELRULE contract 和 patch surface；
- control-plane、XPC、IKE、backend、Surge 五层边界；
- 状态机与测试覆盖；
- secret handling audit；
- 可复现命令和 rollback；
- 一个下一轮最小 Goal，不输出松散 backlog。

## 10. Validation commands

当前已经存在或应立即适配：

```bash
cd /Users/larry_1/Opensource/powervpn-cli
swift test
swift build --arch arm64
swift run powervpn status --json
swift run powervpn oracle inventory --json
swift run powervpn spec validate-redacted fixtures/redacted/tunnel-spec.example.json
```

6.0.7 baseline：

```bash
file /Users/larry_1/scratch-data/powervpn-strongswan/install-6.0.7-arm64/libexec/ipsec/charon
file /Users/larry_1/scratch-data/powervpn-strongswan/install-6.0.7-arm64/sbin/swanctl
cd /Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-arm64
make check -j8
```

未来 harness（未实现前不得假装存在）：

```text
pvnative doctor --json
pvnative render --resource <approved-resource> --redacted
pvnative connect --resource <approved-resource>
pvnative status --json
pvnative disconnect --resource <approved-resource>
pvnative probe --resource <approved-resource> --ssh-banner
```

命令返回 0 不是唯一证据。Goal status 必须记录结构化输出、关键状态与证据
位置，但不得复制 secret 或 raw capture。

## 11. Progress protocol

每个 checkpoint 完成后更新 `docs/progress/GOAL_STATUS.md`：

```markdown
## <timestamp> — Checkpoint N

State: PASS / IN PROGRESS / BLOCKED
Verified:
Evidence:
Changed files:
Tests/commands:
Safety/cleanup:
Remaining:
Next command:
Approval required: yes/no
```

要求：

- 简短、具体、可审计；
- 先保留证据再清理；
- 一个 checkpoint 一个局部、可回滚 commit；
- 不提交 raw capture/secrets/generated build；
- 不重复已经 PASS 的工作，除非新证据冲突；
- 失败后一次只改变一个变量；
- 同一路线三次无进展时收束 blocker 并切换更小实验；
- 状态模糊时收紧 checkpoint，不扩大 scope。

## 12. Pause conditions

出现以下情况时暂停：

- 需要用户输入真实密码、PSK、私钥或不可安全读取的 session；
- 需要绕过认证、伪造客户端身份或规避完整性校验；
- 需要修改 vendor app/helper、关闭 SIP 或改变系统安全策略；
- 需要安装持久 root service/NetworkExtension/system extension；
- 尚未获批却需要中断 VPN、SSH、Surge 或改 route/policy；
- capture 中出现无法自动 redaction 的秘密；
- 同一 blocker 已用两种独立方法复现，继续只会重复；
- 只有服务端变更才能继续；
- 任务漂移到 UI、分发、多用户或多 resource 产品化。

暂停前必须记录 exact blocker、已尝试方法、当前安全状态和下一步所需的
唯一用户动作；需要用户注意时先发送 macOS alert。

## 13. Decision rules

- 5.8.0 build 成功不等于项目成功；
- 6.0.7 build/test 成功也不等于 server interop；
- static capability 不等于 negotiated behavior；
- route 存在不等于 SA/data path 正常；
- TCP connect 不等于 SSH banner；
- GUI/resource switch/history log 不得作为 tunnel truth；
- session invalid 与 tunnel invalid 是正交状态；
- WebSocket closed 与 IKE_SA lost 是正交事件；
- ADDRULE 是 confirmed requirement，不得再假设纯 VICI child config 足够；
- 不得把 vendor 5.8 object 直接塞进 6.0.7；
- PF_KEY 先测，证据失败再切 upstream kernel-libipsec，不同时调两个未知数；
- 如果 standard base SA 失败，先解决标准层，不写 resource codec workaround；
- 如果 base PASS、ADDRULE 失败，阻塞点已定位到 private extension；
- 如果 ADDRULE 和 `/32` route PASS、banner 失败，先查 data path/policy，不
  自动重建 session；
- 如果 6.0.7 全部互通，不继续复刻 vendor 内部架构。

## 14. Future work explicitly deferred

只有 Success Path A 达成后才考虑：

- transient root runner 收敛为受控 XPC service/SMAppService；
- Keychain-backed production credential flow；
- SwiftUI `MenuBarExtra`；
- 多 resource；
- NetworkExtension 可行性；
- signing、entitlements、notarization 和分发。

这些不是当前 Goal 的完成条件。

## 15. Reference sources

- 本机 repo：`/Users/larry_1/Opensource/powervpn-cli`
- 当前路线：`docs/2026-08-08-native-replacement-plan.md`
- 事件复盘：`docs/2026-08-08-power-vpn-incident-postmortem.md`
- 6.0.7 build evidence：`docs/strongswan-6.0.7-arm64.md`
- strongSwan 6.0.7 release：
  <https://github.com/strongswan/strongswan/releases/tag/6.0.7>
- strongSwan on macOS：
  <https://docs.strongswan.org/docs/latest/os/macos.html>
- strongSwan IKEv1 examples：
  <https://docs.strongswan.org/docs/latest/config/IKEv1.html>
- strongSwan VICI/swanctl：
  <https://docs.strongswan.org/docs/latest/swanctl/swanctl.html>
- Codex Follow a goal：
  <https://developers.openai.com/codex/use-cases/follow-goals>
