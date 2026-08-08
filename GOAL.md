---
title: PowerVPN Apple Silicon 原生协议核心（strongSwan 6.0.7）
status: active-codex-goal
updated: 2026-08-08
goal_type: long-running, evidence-driven prototype
repository: /Users/larry_1/Opensource/powervpn-cli
scratch_root: /Users/larry_1/scratch-data/powervpn-strongswan
upstream_target: strongSwan 6.0.7
vendor_compatibility_baseline: strongSwan 5.8.0
current_checkpoint: 7-live-backend-approval-prep
immediate_next: diagnose-vici-version-timeout-and-write-live-gate-artifacts
next_approval_gate: checkpoint-7-live-backend
review_policy: checkpoint-gated-risk-weighted
commit_policy: checkpoint-squash
primary_platform: Apple Silicon macOS 27 beta
---

# PowerVPN Apple Silicon 原生协议核心：Codex Goal

## 启动方式

把本文件复制到仓库根目录并命名为 `GOAL.md`，从
`/Users/larry_1/Opensource/powervpn-cli` 启动：

```text
/goal Implement GOAL.md from current_checkpoint. Work continuously inside the active checkpoint. Do not pause for per-commit review, repository-wide rereads, or progress narration. Use WIP/fixup commits freely, batch related changes, run targeted tests, and invoke only the bounded review gate defined in Section 10 when checkpoint acceptance commands pass or a listed risk trigger fires. Before marking a checkpoint PASS, squash checkpoint-local commits into one evidence-bearing commit and update docs/progress/GOAL_STATUS.md. Pause only at explicit approval gates or exact blockers.
```

若 `/goal` 尚未启用：

```bash
codex features enable goals
```

执行原则：**review 绑定语义风险和 checkpoint 边界，不绑定每一次 Git
commit。** 普通实现循环不应被“提交一次、全面 review 两次”打断。

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

### Protocol fidelity invariant：这是兼容性移植，不是协议设计

1. **MUST NOT add/remove/reorder/normalize/reinterpret/symmetrize.** 已观察
   payload、field、byte order、HASH coverage、request/revoke asymmetry 不得为了
   API 整洁、RFC 习惯或本地测试方便而增删、重排、归一化、重解释或
   对称化。
2. **Every outbound byte MUST have evidence.** 每个可能影响服务端解析、
   HASH/认证或状态转移的 byte，都必须可追溯到 value-free vendor
   serializer/HASH-input differential、受保护 reference vector，或经批准的
   server-acceptance 结果。
3. **Unknown stays opaque.** 证据未提升的 length-delimited 字段必须保持
   `opaque`/neutral；不得发明业务名称、编码转换、默认值或跨字段关系。
4. **Parse != accept != emit.** structural parser 只有界、无损地保留
   observed variants；canonical compatibility profile 才按
   direction/dialect/family/exchange/state 决定可否接受或发送。
5. **The private predicate MUST be complete.** 仅当完整、明确的 private
   context predicate 成立时才进入移植分支；谓词之外的 payload order、
   HASH、message rules 和返回值必须与 unmodified upstream 一致。
6. **Same-implementation round-trip proves self-consistency only.** 同一份新代码
   generate/verify 自己的向量不是 vendor oracle，不得据此标记 compatibility PASS。
7. **Observed vendor behavior outranks standards cleanup.** vendor static/runtime 证据
   与通用 RFC/upstream 直觉冲突时，compatibility profile 以前者为准；标准只用于
   解释，不得“修正”已观察 wire。
8. **Wire-neutral safety is allowed; wire-visible improvement/generalization is
   forbidden.** bounds、memory safety、secret hygiene、fail-closed 等不改变 wire 的
   安全加固可以加入；更强 proposal、新 fallback、自动 normalization、更宽泛发送
   等 wire-visible “改进”或泛化禁止进入 compatibility profile。
9. **Owned internals may be refactored.** 自有 GUI、XPC/control schema、helper 名称、
   类结构和内部状态机可以重构；必须一致的是 server-observable wire bytes、
   时序和状态效果。
10. **Intentional divergence MUST live outside the compatibility profile.** 实验性
    扩展必须独立 feature gate、default off，且不能被 canonical encoder/profile 或
    默认 runtime 路径误启用。

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
- vendor `_get_hash_phase2` at `0x10014fa70` 没有 expandrule/custom HASH
  branch；
- vendor Quick Mode `_build_i` state 0 先构建标准 SA/NONCE/TS，state 1
  才追加 ADDRULE；
- 因此已观察 `[HASH ADDRULE]` 使用标准 Quick Mode `HASH(3) =
  PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`；ADDRULE bytes 不在 HASH input 内；
- 当前成功日志没有观察到 XAuth 或 Mode Config transaction；
- 二进制中存在 XAuth/Mode Config code 只代表 static capability，不能写成
  negotiated behavior；
- 不得擅自强化 proposal。服务端不变时，第一轮 interop 必须精确复现
  观察到的兼容参数。

### 3.3 Network/data-plane facts

- 历史成功连接的一次带时间戳快照中，PowerVPN 创建了 `utun9`；
- 当前一次带时间戳快照中，Surge Enhanced Mode 使用 `utun8`，地址空间为
  `198.18.0.1/15`；
- 把 `utun8` 写成 PowerVPN interface 是已纠正的旧错误；
- `utunN` 序号不是稳定身份，运行时不得硬编码 Surge=`utun8`、
  PowerVPNNative=`utun9`；
- interface identity 必须由创建 generation、地址、route ownership、backend
  association 和运行时事件动态归因；
- upstream 6.0.7 自带 macOS utun 创建代码，kernel-libipsec 可直接使用，
  暂不需要自写 PacketTunnelProvider 或 packetFlow adapter；
- Apple built-in VPN/PacketTunnelProvider 可能禁用其他 app 的 VPN config，
  这是风险假设，不是已验证 runtime 方案；
- 目标共存形态是：

  ```text
  Surge system extension -> dynamically identified packet tunnel / default route
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

### 3.5 Repository and execution facts

- 当前仓库：`/Users/larry_1/Opensource/powervpn-cli`；
- 本地 `main` 无 remote/upstream，不得声称已同步远端；
- 现有 SwiftPM product 为 `powervpn`，library 为 `PowerVPNCore`；
- `reconnect` / `PowerVPNController` 已移除；旧 CLI 只保留为只读
  diagnostic/oracle harness；
- CP0–CP3 与 CP2 可复现构建已经拆分为三个本地提交，主树干净；
- CP2 build wrapper forward-test 已覆盖 configure、增量 build、scratch
  install、全部 `make check`、六个 arm64 artifact gate；产物 SHA-256 与原始
  可复现构建一致；
- vendor log reader 已改为 FileHandle 分块逐行 allowlist，不把完整敏感日志
  解码为 String；混合 marker+secret 行只保留 canonical marker，plugin 行只
  保留静态白名单中的 plugin 名；对应回归测试已加入；
- TunnelSpec 已包含 VIP、NAT-T、session binding reference、map ID、
  tunnel/resource identifiers、routes、credential reference 和
  ADDRULE/DELRULE operations；
- XAuth/Mode Config oracle evidence 明确标为 static compiled capability，
  不是 negotiated behavior；
- Goal 启动基线为 19 项 Swift tests PASS、arm64 build PASS、只读 on-host
  oracle/status PASS、`git diff --check` PASS；测试数量不是不变量，后续只要求
  所有命名 contract categories 持续 PASS；
- helper 未运行时不得用历史 CHILD_SA 报 healthy；helper generation 不一致时，
  历史日志只能称为 historical hint；
- `/var/log/vsgvpn.log` 已知含敏感认证材料，流式 allowlist 是必须保持的安全
  回归条件；
- CP4 的静态证据已经收敛到可实现状态：
  - client request 使用有方向的 payload type `18/19` family；
  - 仅存在 server revoke 的 receive-only type `17` compatibility path；
  - client envelope 与 server revoke 不是对称 body，而是带 direction、dialect、
    family 的不同 profile；
  - parser 与 canonical vendor profile 必须分层：parser 可接受已观察到的 inbound
    variant，profile validator 才强制 `next=0`、single-delta 等 canonical bytes；
- CP4 当前只允许在 official 6.0.7 独立 worktree 中实现离线 codec/tests；不得
  提前接 IKE_SA、Quick Mode task、message factory 或网络路径。


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

不得使用单线状态机，也不得把 SSH 可达性写回 IKE tunnel truth。至少保持以下
正交维度：

```text
AuthSessionState
  signedOut / authenticating / valid / expired / failed

ControlChannelState
  disconnected / connecting / online / backoff / failed

IKEState
  idle / negotiating / established / degraded / recovering / backoff / blocked

PathGeneration
  monotonic generation + satisfied/unsatisfied + dynamically resolved interface identity

ResourceState per resource
  desired(inactive|active) + observed(inactive|activating|active|failed|unknown)

ProbeState per resource
  unknown / probing / healthy / unhealthy / timeout

UserIntent
  connect / disconnect
```

`OperationalReadiness` 是按同一 generation 动态推导的只读视图，不是另一个
可独立写入的状态：

```text
auth valid
+ control channel state known
+ IKE established
+ desired resource observed active
+ exact route/policy present
+ end-to-end probe healthy
```

规则：

- WebSocket 断开不等于 auth session 过期；
- auth session 过期不等于 IKE_SA 已失效；
- IKE_SA established 不等于某个 resource 已 active；
- SSH probe unhealthy 不得把 `IKEState.established` 改成 false；
- path change 只触发 generation bump/debounce，不直接宣称 tunnel dead；
- IKEv1 无 MOBIKE 时，对旧 generation 做 single-flight teardown/re-initiate；
- 旧 callback/timer 不得覆盖新 generation；
- manual disconnect 必须取消或压制所有 recovery；
- runtime interface identity 不得依赖固定 `utunN`；
- 缺少某一层时，只在该层报告 unknown/degraded/failed，不得用一个
  `connected` 布尔量掩盖差异。


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

已提交并验证：仓库边界、回滚基线、vendor 未修改、旧 CLI 仅为只读
harness，以及 gateway/管理员/watchdog/GUI restart 均不属于本路线。

### Checkpoint 1 — vendor 5.8.0 + B/C classification — PASS

已提交并验证：5.8.0 baseline、critical plugin、`CUSTOM:kernel-ipsec`、
ADDRULE/DELRULE/expandrule/Quick Mode markers、proposal，以及 PowerVPN/Surge
interface 归因纠错。commit-safe inventory 只保留 marker/hash，不保留 raw
symbol/log line。

归因要求：`vendor implementation = B+C` 已确认；只有 registration/call graph
证据能够确认某项 C 能力属于 `leadsecbridge` 时，才把 module ownership 写成
confirmed，不能只因符号位于同一 Mach-O 就推断所有权。

### Checkpoint 2 — upstream 6.0.7 arm64 baseline — PASS

已提交并 forward-test：official tag/commit、configure、增量 build、scratch
install、全部 `make check`、六个 arm64 artifact gate、PF_KEY/PF_ROUTE/
kernel-libipsec/VICI load smoke，以及产物 SHA-256 可复现一致性。

仍未证明且不得混淆：privileged backend startup、SA install、utun lifecycle、
Surge coexistence、server interoperability。

### Checkpoint 3 — oracle safety and TunnelSpec — PASS

已提交并验证：

- 只读 `powervpn oracle inventory --json`；
- canonical-marker/plugin-name allowlist，含 mixed-line secret regression；
- historical evidence/generation safety；
- strict TunnelSpec tri-state 与 redacted fixture validation；
- secret-leak、partial-tail、strict-schema negative tests；
- arm64 build、Swift tests、只读 on-host oracle/status 和 `git diff --check`。

以后不得重新把完整日志载入 String，也不得把测试数量 `19` 固定成产品
contract。

### Checkpoint 4A — expandrule wire syntax and strict codec — PASS

目的：恢复并实现 **wire syntax**，不提前给 opaque field 绑定未经证实的业务
语义。

已确认的实现边界：

- official 6.0.7 独立 worktree；
- 纯 codec 位于 `src/libcharon/encoding/payloads/`；
- tests 接入 `src/libcharon/tests/suites/`；
- client request 与 server revoke 必须显式区分 direction/dialect/family；
- parser 接受已观察到的 inbound variant；canonical vendor profile validator
  才强制 `next=0`、single-delta、canonical bytes；
- 不依赖 IKE_SA、Quick Mode task 或网络；
- 暂不接 message factory/task manager。

任务：

1. 用受保护 specimen 或完整 serializer/parser static evidence 确认 generic
   payload header、body length、field offset、byte order、operation code、固定值、
   count 和可变区域；
2. 未证明的字段命名为 `opaqueFieldN`，并标记 confirmed/inferred/unknown；
3. 实现 request/revoke profile，禁止假设 encode/decode 完全对称；
4. 创建不含真实 endpoint/resource 的 synthetic golden fixtures；
5. 做 byte-for-byte encode/decode 和 canonicalization tests；
6. 拒绝 malformed length、unknown op、oversize、invalid direction/dialect/family、
   duplicate rule 和不合法 profile combination；
7. 不启动网络、不连接服务端、不读取 secret。

进入条件：至少满足以下一项：

- 有 plaintext serialization boundary 的 ADDRULE/DELRULE specimen；或
- static disassembly 足以完整恢复字段 offset、length、byte order 与 parser
  constraints。

若两项都不满足，先完成最小 oracle acquisition，不得从加密 pcap 或日志文本
猜 body codec。

验收：targeted codec suite、完整 strongSwan relevant tests、artifact diff 和
secret scan PASS；schema/tests 足以解释 wire syntax，不依赖 raw secret capture。

### Checkpoint 5 — control-plane and XPC semantic correlation — PASS

经用户合法登录或复用合法现有 session，只记录：

- HTTPS method/path/status、field name/type/length；
- auth session 与 control channel 的独立 state transition；
- WebSocket message type/order/keepalive/resume；
- resource list/activation/deactivation schema；
- GUI↔helper XPC key/type/order；
- portal session 如何关联 PSK、VIP、map/tunnel/resource metadata。

禁止保存 header value、cookie、PSK、session、identity、raw body、TLS key log。
动态注入只能作为实验显微镜，不进入产品。

验收：三边界文档分开，字段均标 confirmed/inferred/unknown；raw capture 在
mode-700 scratch，Git 仅有脱敏 schema。

### Checkpoint 4B — semantic promotion gate — PASS

在 Checkpoint 5 完成后，将 `opaqueFieldN` 与 control-plane/XPC differential
observations 做关联。只有至少两类独立证据一致时，才把字段提升命名为
`mapID`、`resourceID`、`routeCount` 等正式语义；否则保留 opaque。

验收：每次 rename 都有 evidence ID；fixture forward/backward tests PASS；不因
值“看起来像”某个 ID 就永久命名。

结果：gate 已对 8 个候选 slot 逐项执行，promotion set 为空。完整的
XPC-consumer-to-expandrule-writer 静态链只构成一类
`vendor_static_disassembly` 证据；CP5 runtime/differential observations 没有
命中 `start_connection` 或 plaintext serializer slot，不能充当第二类直接映射
证据。因此 `leadingAddress`、primary/secondary、dialect-0/1 opaque 和 server
revoke value 均保留 neutral/opaque。CP4A codec、patch 与 synthetic bytes 未改。

证据与验收入口：

- `docs/evidence/checkpoint-4b-semantic-promotion.md`；
- `fixtures/redacted/semantic-promotion-gate-v1.json`；
- `scripts/verify_checkpoint.sh 4b`。

### Checkpoint 6 — LeadSec compatibility port — PASS (offline compatibility-port checkpoint)

任务：

- 建立可针对 official 6.0.7 重放的最小 patch series；
- 加入 payload factory/message rules/task skeleton；
- 精确复现 Quick Mode state 0 标准 SA/NONCE/TS、state 1 ADDRULE 调度，复用
  upstream HASH(3)，不增加 custom keymat HASH branch；
- 将 synthetic TunnelSpec 转为结构化 VICI load-conn；
- 不解析人类可读 `swanctl` 输出作为核心 API；
- random ports + scratch VICI socket；
- credential reference 缺失时安全失败；
- round-trip proposal、identity 和 selector；仅在本地报告未提升的 resource
  rule metadata，不把它写入 VICI 或 private wire；
- dry run 不创建 SA、route、utun。

验收：offline implementation/self-consistency、VICI dry run 与 exact reference
test 必须共同证明 state-0/state-1 scheduling、标准 HASH(3) input 与
ADDRULE-byte exclusion，并证明完整 private predicate 之外的 upstream 行为不变。
该 test 必须用固定
SKEYID_a/M-ID/Ni/Nr 独立计算 expected HASH(3)，验证 state 0 含标准
SA/NONCE/TS、state 1 wire order 为 `[HASH ADDRULE]`，ADDRULE-only mutation
不改变 HASH，而 Ni/Nr mutation 会改变 HASH。

结果：**PASS (offline compatibility-port checkpoint)**。upstream implementation
commit 为 `67c9810900e2d8486cb3b11495a8362433494ca0`，0002 patch SHA-256 为
`6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`；
patch replay tree equality PASS。

新的 vendor static evidence 已否定早先的 custom-only HASH 路径：
`_get_hash_phase2` at `0x10014fa70` 没有 custom branch；Quick Mode
`_build_i` 在 state 0 构建标准 SA/NONCE/TS，state 1 才追加 ADDRULE。
移植必须保留标准 `HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`，
且排除 ADDRULE bytes。已有 `[HASH ADDRULE]` generate/verify 只是被新证据
推翻的旧 self-consistency 实验，不能作为 compatibility evidence。

`fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json` 固化 value-free vendor
static HASH(3) contract；独立 synthetic reference 与实现输出一致。targeted
expandrule suite 39/39、full libcharon 5/5、no-IKEv1 build PASS；CP4A base 到
post-fix commit 的 `keymat_v1.c` 与 `task_manager_v1.c` 均为 zero diff，证明没有
custom keymat branch 或 task-manager wiring。官方 stock VICI byte oracle 继续
PASS；其 335-byte request 与 private IKE HASH 相互独立。

这个 PASS 只覆盖 offline compatibility-port checkpoint：static contract、独立
synthetic reference、replayable patch、codec/task 与 deterministic VICI dry run。
live vendor differential 和 server acceptance 仍未验证，不能称为 live/server
compatibility PASS。
一次隔离的非 root daemon smoke 仍为 **BLOCKED**，精确阻塞在首个 VICI `version` response
timeout；未发送 `load-conn`，已完整清理，不能写成 daemon/VICI PASS。该
daemon blocker 不属于 deterministic VICI dry-run acceptance。完整证据和
replayable patch-series record 见 `docs/evidence/checkpoint-6-validation.md` 与
`patches/strongswan-6.0.7/series.json`。VICI timeout 是独立 control-path blocker，
不能替代 private wire compatibility oracle。

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
2. 记录 Surge 前后 interface/default route/DNS，并按动态 identity 归因；
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
- 分别验证 IKE state、resource response、精确 `/32` route/policy 和 fresh SSH
  banner，不把 banner 反写成 tunnel truth；
- 发送 DELRULE/断开并验证完整清理；
- 不测试多 resource 并发。

此 checkpoint PASS 才能宣称“技术 GO”。

### Checkpoint 10A — bounded recovery and Surge coexistence

只在原生单 resource 已成功后并再次获批：

- 用 deterministic tests 覆盖 generation、single-flight、manual disconnect、
  stale callback suppression、bounded backoff；
- 执行一次受控 path change；
- 执行一次 30–120 秒 outage；
- 正确恢复，或明确进入 degraded/blocked；
- 无重叠连接、重复 SA/route、旧 generation callback 或 secret log；
- Surge 始终保持预期 default route/DNS/functionality。

本 checkpoint 满足当前 Goal 的恢复可行性验收。

### Checkpoint 10B — reliability stress — DEFERRED TO NEXT GOAL

睡眠唤醒、断网、Wi-Fi→热点各 10 次、10/10 成功率与 p95 恢复时间属于
下一轮 daily-driver reliability Goal，不阻塞本轮 protocol-core technical GO。

### Checkpoint 11 — final report

输出 `docs/reports/final-feasibility-report.md`：

- Success A 或 Blocked B；
- 5.8.0 oracle 与 6.0.7 target 的最小差异；
- ADDRULE/DELRULE contract 和 patch surface；
- control-plane、XPC、IKE、backend、Surge 五层边界；
- 状态模型与测试覆盖；
- secret handling audit；
- 可复现命令和 rollback；
- 一个下一轮最小 Goal，不输出松散 backlog。


## 10. Execution cadence, review budget and commit policy

### 10.1 核心原则

- review 发生在**语义边界**，不是每个 Git 边界；
- checkpoint 内连续实现、连续测试，不因 WIP commit 暂停；
- 默认只 review changed files、direct contract、adjacent tests 和 evidence，
  不重读整个 repo；
- 自动化 invariant/test 优先于反复人工复述；
- 除非命中风险触发器，禁止“实现 → 全面 review → commit → 再全面 review”
  的递归循环。

### 10.2 三条执行车道

```text
Fast lane
  docs / evidence manifest / build wrapper / test plumbing
  -> 1 次 checkpoint-end self-review

Guarded lane
  secret handling / wire codec / parser-profile split / state concurrency
  -> 1 次 implementation review + 1 次 independent targeted review

Live lane
  root / SA / route / utun / network switching / Surge impact
  -> user approval + preflight review + post-run evidence/cleanup review
```

CP4 属于 Guarded lane，所以一次独立 targeted review 是合理的；CP2 的 build
wrapper、普通文档和每一个局部 commit 不应套用同样强度。

### 10.3 Review 触发器

仅在以下情况下启动 review gate：

1. checkpoint acceptance commands 首次全部 PASS；
2. secret redaction、credential boundary 或 log parsing 发生变化；
3. wire byte layout、direction/dialect/family、HASH/order 或 canonicalization
   发生变化；
4. generation、single-flight、manual-disconnect 等并发状态语义发生变化；
5. 即将跨越 Live Approval Gate；
6. 新证据与 verified baseline 冲突。

普通 rename、注释、manifest、局部 build-script 调整和 WIP commit 不触发完整
review。

### 10.4 Review budget

- Fast lane：每 checkpoint 最多 1 次 broad self-review；
- Guarded lane：每 checkpoint 最多 1 次 implementation review + 1 次
  independent targeted review；
- 第二次 review 只检查第一次发现项及其直接影响面，不重新审计整个
  checkpoint；
- 没有 critical/high finding 时立即进入 checkpoint commit，不再“为了确认
  review 本身”追加 review；
- 同一 finding 修复两次仍不收敛时，记录 exact blocker，缩小实验，不扩大
  review 面。

### 10.5 Commit policy

- checkpoint worktree 内允许任意数量的 local WIP/fixup commits；这些 commit
  不逐个 review；
- checkpoint acceptance 和 review gate 通过后，squash/fixup 为一个
  canonical evidence-bearing commit；
- 一个 checkpoint 对应一个可回滚 canonical commit，但不要求实现过程只有
  一个 commit；
- commit message 记录 contract、tests、evidence path 和 safety/cleanup；
- review 发现仅文档或测试缺口时，优先 amend/fixup，不创建“review of review”
  commit；
- 只有跨 checkpoint 的独立修复才单独提交。

### 10.6 验证节奏

checkpoint 内按成本从低到高运行：

```text
1. targeted unit/fixture tests
2. changed-component build
3. relevant upstream suite
4. full checkpoint acceptance script
5. review gate
6. canonical checkpoint commit
```

重复两次以上的命令应收敛为 `scripts/verify_checkpoint.sh <id>` 或等价入口，
避免 Codex 每轮重新拼命令、重复解释和重复读取输出。

### 10.7 Progress output budget

- 不在每个 commit 后更新 `GOAL_STATUS.md`；
- 只在 checkpoint PASS、BLOCKED、进入 approval gate，或出现会改变下一步的
  material finding 时更新；
- 中间执行只保留短 scratch notes，不向用户逐命令直播；
- 每次状态更新必须给出唯一 `Next command`，避免生成新的松散 backlog。

## 11. Validation commands

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

## 12. Progress protocol

只在 checkpoint PASS / BLOCKED、material finding 或 approval gate 时更新
`docs/progress/GOAL_STATUS.md`；不要在每个 WIP commit 后更新：

```markdown
## <timestamp> — Checkpoint N

State: PASS / IN PROGRESS / BLOCKED
Verified:
Evidence:
Canonical commit:
Changed files:
Tests/commands:
Review lane and result:
Safety/cleanup:
Remaining:
Next command:
Approval required: yes/no
```

要求：

- 简短、具体、可审计；
- 先保留证据再清理；
- checkpoint 内可用 WIP/fixup commits，PASS 前收敛为一个 canonical commit；
- 不提交 raw capture/secrets/generated build；
- 不重复已经 PASS 的工作，除非新证据冲突；
- 失败后一次只改变一个变量；
- 同一路线三次无进展时收束 blocker 并切换更小实验；
- 状态模糊时收紧 checkpoint，不扩大 scope；
- 不做 repository-wide double review，除非 Section 10 的风险触发器明确要求。


## 13. Pause conditions

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

## 14. Decision rules

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
- `utunN` 只作为时间戳快照，不作为 runtime identity；
- SSH banner 是 ProbeState，不是 IKEState；
- review 绑定 checkpoint/risk，不绑定每个 commit；
- Guarded lane 的第二次 review 只做 targeted independent check，不重复全仓审计；
- CP4A 先恢复 syntax，CP5/4B 再提升 field semantics。

## 15. Future work explicitly deferred

只有 Success Path A 达成后才考虑：

- transient root runner 收敛为受控 XPC service/SMAppService；
- Keychain-backed production credential flow；
- SwiftUI `MenuBarExtra`；
- 多 resource；
- NetworkExtension 可行性；
- Checkpoint 10B 的 30-run reliability stress 与 p95 统计；
- signing、entitlements、notarization 和分发。

这些不是当前 Goal 的完成条件。

## 16. Reference sources

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
