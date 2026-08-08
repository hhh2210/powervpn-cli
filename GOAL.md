---
title: PowerVPN Apple Silicon 原生协议核心（strongSwan 6.0.7）
goal_version: 3
status: active-codex-goal
updated: 2026-08-09
goal_type: long-running, evidence-driven native-protocol prototype
repository: /Users/larry_1/Opensource/powervpn-cli
scratch_root: /Users/larry_1/scratch-data/powervpn-strongswan
upstream_target: strongSwan 6.0.7
upstream_base_commit: 5973ff8e41deef4e015e1138a2de688acedf6f75
vendor_compatibility_baseline: strongSwan 5.8.0
canonical_lab_commit: 3231a3bfe992fcc5f84793543ce9c8687afcd7fa
strongswan_cp6_commit: 67c9810900e2d8486cb3b11495a8362433494ca0
strongswan_patch_sha256: 6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213
current_checkpoint: 7b-privileged-backend-preflight
immediate_next: request-cp7b-root-live-execution-approval-for-final-manifest
next_approval_gate: 7b-root-live-execution-after-preflight-review
review_policy: checkpoint-gated-risk-weighted-single-integrated-review
commit_policy: canonical-checkpoint-commits-with-local-fixups
primary_platform: Apple Silicon macOS 27 beta
---

# PowerVPN Apple Silicon 原生协议核心：Codex Goal V3

## 启动方式

把本文件复制到仓库根目录并命名为 `GOAL.md`，从
`/Users/larry_1/Opensource/powervpn-cli` 启动：

```text
/goal Implement GOAL.md from current_checkpoint. Treat CP0 through CP6 and the
three evidence anchors in the front matter as a locked verified baseline.
Do not repeat their broad analysis or full acceptance runs unless the current
work changes shared code or new evidence directly conflicts with them.

Resume from the current checkpoint and its approval gate. CP7A and the CP7B
preflight are complete; do not launch the privileged backend until the user
explicitly approves the finalized manifest hash and exact command. That approval
does not authorize server traffic, credentials, routes, SA/utun creation,
PowerVPN shutdown, Surge mutation, or later recovery tests.

Review the cumulative checkpoint candidate, not every commit. Use local
WIP/fixup commits, targeted tests and one integrated checkpoint review. Do not
run recursive repository-wide audits or review-of-review loops. Update
GOAL_STATUS.md only on PASS, BLOCKED, a material finding, or an approval gate.
```

若 `/goal` 尚未启用：

```bash
codex features enable goals
```

## 0. Codex execution contract

本文件是执行合同，不是松散 backlog。

1. **CP0–CP6 已完成。** 启动时只核验 clean tree、commit 与 patch hash；不要
   重新逆向厂商二进制、重新设计 codec、重新做全仓 review，或重新跑 CP6
   全量验收来制造“进度”。
2. **CP6 是离线 compatibility-port PASS，不是服务器互通 PASS。** 当前仍没有
   原生服务器 IKE_SA、CHILD_SA、resource route、SA/policy/utun 证据。
3. **CP7A 已 PASS；CP7B preflight 已 PASS 并等待 live approval。** 未获得绑定
   finalized manifest 的第二次明确授权前，不得进入 root/backend；server
   interop、credential acquisition、网络切换和恢复测试仍在更后的独立 gate。
4. **CP7B preflight PASS 不是 backend PASS。** arm64 build、root-closure 设计、
   gated lifecycle 和 dry validation 不证明 PF_KEY/PF_ROUTE constructor 已在本机
   成功，也不证明任何 SA、policy、route、utun 或 server compatibility。
5. **一次只改变一个变量。** 对同一个失败假设最多做三次有信息增益的尝试；
   仍不收敛时记录 last-good-state / first-bad-event，并缩小实验。
6. **review 绑定 checkpoint 和风险，不绑定 commit。** 除 Live lane 的
   preflight/cleanup 外，一个 checkpoint 默认只有一次 integrated review。
7. **不主动扩大产品层。** 不做 SwiftUI、LaunchDaemon 产品化、
   NetworkExtension、安装器、签名或多 resource。
8. **不发明 LeadSec 协议。** 服务端可见的行为必须由 vendor evidence、独立
   oracle 或真实 server acceptance 支撑。

## 1. Durable objective

在**不修改服务端、不绕过正常认证、不依赖厂商 x86_64 helper、不引入中转
Gateway、不把 watchdog 或重启 GUI 包装成修复**的前提下，在当前 Apple
Silicon Mac 上构建一个可回滚、可验证的 PowerVPN 原生协议核心：

1. 以厂商 strongSwan 5.8.0 fork 作为合法行为与 wire-contract oracle；
2. 以 upstream strongSwan 6.0.7 作为唯一 native runtime；
3. 保持标准 IKEv1 Main Mode 和 Quick Mode 的 upstream 语义；
4. 只移植已观察到的 ADDRULE/DELRULE compatibility profile；
5. 通过 VICI 驱动 arm64 `charon`，并使用一个可在本机干净启动、清理、与
   Surge 共存的数据面 backend；
6. 使用用户合法持有、经明确授权的运行时材料，不从 vendor 日志或 helper
   抓取可重放秘密；
7. 建立一个已授权 resource 的原生 tunnel 与精确 route/policy；
8. 用正交、事件驱动的 truth model 消除“GUI/route 看似在线但 tunnel 已死”
   的假在线；
9. 完成一次有界恢复可行性验证；
10. 若无法互通，给出 evidence-complete 的第一个不可兼容点，而不是退回
    x86 helper、GUI 自动重启或无界 watchdog。

当前 critical path 已从“协议是什么”转变为：

```text
VICI runtime 可控
→ 至少一个 macOS backend 可干净启动/清理
→ 合法 runtime material 可安全交付
→ IKEv1 Main Mode
→ vendor-compatible Quick Mode message 3: [HASH(3), ADDRULE]
→ 单 resource route/policy/data path
→ 有界恢复与 Surge 共存
```

## 2. Verifiable stopping conditions

Goal 只能在下列两个终态之一完整满足后结束。

### Success Path A — 原生单资源技术可行性 PASS

必须同时满足：

- `charon`、VICI client/control path 和实际 backend 均为 arm64；
- runtime 不运行厂商 `charon-xpc`、`ipsec-xpc`、`sh-xpc`，不依赖 Rosetta；
- 使用用户合法持有的认证材料，不绕过 portal/server authentication；
- IKEv1 Main Mode 成功；
- vendor-compatible Quick Mode 成功，其中第三包使用标准 HASH(3)，并按
  已观察 profile 携带 ADDRULE；
- 不把 ADDRULE bytes 加入 HASH(3)，不重写标准 IKEv1 keymat；
- 至少一个已授权 resource 的 desired/observed state 一致；
- 对应 SA、policy 与精确 route 可结构化检查；
- 新建 TCP 连接能够收到目标 SSH banner；
- SSH probe 只作为 end-to-end `ProbeState`，不得反写 IKE truth；
- Surge 保持运行，默认路由与 DNS 未被原型接管；
- 停止后不残留进程、VICI socket、SA、policy、route、utun、PID file、
  credential file 或 secret log；
- 状态输出分别报告 daemon、VICI、auth session、control channel、IKE、
  backend、path generation、resource 与 probe，不使用单一 `connected`；
- 一次受控 path change 或 30–120 秒 outage 后能够有界恢复，或明确进入
  degraded/blocked，不产生假在线；
- 构建、启动、停止、验证与回滚可重复；
- Git、日志、fixtures 与普通临时文件中没有密码、PSK、session、token、
  cookie、私钥、真实 endpoint、真实 resource 标识或可重放 payload。

本 Goal 的技术原型允许**用户介入的安全 credential handoff**，但不允许从
vendor helper/log 运行时抓取秘密。自动化 portal/WebSocket 产品化、菜单栏 UI
和长期常驻服务属于后续 Goal。

### Evidence-Complete Blocked Path B — 精确阻塞结论

若 Success Path A 无法达到，必须同时满足：

- CP6 commit、patch hash、arm64 build 与离线测试证据保持可重放；
- 明确记录最后成功状态与第一个失败事件；
- blocker 精确落入一个或多个层次：
  - VICI daemon launch/readiness/socket/transport；
  - privileged backend 初始化或 macOS 权限；
  - portal/runtime material 来源与安全 handoff；
  - IKEv1 Main Mode proposal、identity、PSK 或 Vendor ID；
  - Quick Mode message order、HASH(3)、ADDRULE profile 或 server acceptance；
  - SA/policy/route/utun 安装与清理；
  - Surge 共存；
  - end-to-end data path；
- 每个已排除假设都有命令、结构化日志、独立 oracle、VICI event、
  disassembly fact、最小 fixture 或 live server response 支撑；
- raw secret/capture 不进入 Git；
- 下一项最小工程任务有明确输入、输出与验收条件；
- 没有为了“完成”而退回 vendor helper、GUI restart、服务端修改、中转
  gateway、禁用系统安全策略或无界 watchdog。

## 3. Locked verified baseline

以下 baseline 只有在新证据直接冲突时才能重开。任何冲突都必须先作为
material finding 写入 `GOAL_STATUS.md`。

### 3.1 Evidence anchors

```text
Canonical lab commit
  6122825e37d5061c94d2e1b4e7a88cadcd354e04

strongSwan 6.0.7 CP6 commit
  67c9810900e2d8486cb3b11495a8362433494ca0

Exported patch SHA-256
  6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213
```

CP7 不得 amend、rebase 或重写上述 evidence anchors。若 live evidence 要求改动
protocol patch，必须在新 commit 中记录“旧假设、反证、最小修正与新 patch
hash”。

Goal 启动时只做一次轻量核验：

```bash
cd /Users/larry_1/Opensource/powervpn-cli
git status --short
git rev-parse HEAD

cd /Users/larry_1/scratch-data/powervpn-strongswan/<active-6.0.7-worktree>
git status --short
git rev-parse HEAD
```

并核对 `GOAL_STATUS.md` 中记录的 patch 文件 SHA-256。除非 tree/hash 不匹配，
不要重新跑 CP6 全量验收。

### 3.2 Vendor and protocol baseline

- PowerVPN 3.2.1 build 24572 及特权 helper 为纯 x86_64；
- vendor baseline 为 strongSwan 5.8.0 confirmed，vendor patch level unknown；
- vendor implementation 包含：
  - 自定义 macOS kernel/data-plane integration；
  - 私有 ADDRULE/DELRULE IKEv1 resource extension；
- 分类为 **B + C confirmed**，但单个能力的 module ownership 仍需
  registration/call-graph 证据，不能只因符号位于同一 Mach-O 就推断；
- IKE 使用 IKEv1 Main Mode 与 PSK evidence；
- 已观察 IKE proposal：
  `AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024`；
- 已观察 ESP proposal：
  `AES_CBC_128/HMAC_SHA1_96/NO_EXT_SEQ`；
- static XAuth/Mode Config capability 不等于当前部署实际 negotiated behavior；
- payload family：
  - type 18：client ADDRULE full envelope；
  - type 19：client DELRULE full envelope；
  - type 19：server short revoke；
  - type 17：server receive-only legacy revoke alias；
- client envelope 与 server revoke 不是对称格式；
- 未被独立证据提升的字段继续保持 opaque；
- `utunN` 只是带时间戳快照，不是稳定 runtime identity；
- Surge 与 PowerVPNNative interface 必须通过 generation、地址、route ownership、
  backend association 与创建事件动态归因。

### 3.3 CP0–CP5/4B baseline

- CP0 boundary/rollback：PASS；
- CP1 vendor inventory 与 B+C classification：PASS；
- CP2 official 6.0.7 arm64 reproducible build：PASS；
- CP3 safe oracle、streaming allowlist、TunnelSpec/redaction：PASS；
- CP4A expandrule syntax/strict codec：PASS；
- CP5 control-plane/XPC schema acquisition：静态与 value-free 证据已完成；
- CP4B semantic promotion gate：PASS，结果为 **zero promotion**；
- portal → PSK/VIP/routes/map/resource 的完整动态值级绑定仍未证明；
- vendor log 可能含明文敏感材料；项目不得完整解码、复制或提交该日志。

### 3.4 CP6 canonical conclusion — PASS, offline only

CP6 的正式结论是：

> **离线 compatibility-port checkpoint PASS；不等于 server interoperability
> PASS，也不等于 daemon VICI runtime PASS。**

已落实的关键纠正：

1. 删除错误的 `M-ID | encoded ADDRULE` custom HASH 路径；
2. vendor behavior 复现为：ADDRULE 位于标准 Quick Mode 的第三包；
3. 使用标准：

   ```text
   HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni | Nr)
   ```

4. ADDRULE bytes 不参与 HASH(3)；
5. `keymat_v1.c` 与 `task_manager_v1.c` 相对 CP4A 为零差异；
6. structural parser、strict compatibility profile、outbound canonicalization
   保持分离；
7. standard upstream IKEv1 路径在完整 LeadSec predicate 之外保持不变。

CP6 验证快照：

```text
expandrule suite                  39/39 PASS
libcharon relevant suites          5/5 PASS
no-IKEv1 link/object/symbol gate       PASS
Swift targeted                   14/14 PASS
Swift full                       55/55 PASS
official VICI fixtures      324/335-byte byte-for-byte match
patch replay / arm64 / Gitleaks        PASS
diff hygiene / clean-tree rerun        PASS
scripts/verify_checkpoint.sh 6       exit 0
```

测试数量是时间点证据，不是永久不变量。以后验收依赖命名 contract 与全部测试
PASS，而不是必须保持相同计数。

仍未通过：

- vendor live differential；
- server acceptance；
- daemon VICI first `version` response；
- privileged backend；
- IKE_SA、CHILD_SA、SA/policy/route/utun；
- 单 resource data path；
- recovery。

### 3.5 Retired hypotheses — must not reappear

以下假设已被 CP6 反证，后续代码、文档和 review 不得重新引入：

- “ADDRULE 是独立 custom-only Quick Mode”；
- “`[HASH, ADDRULE]` 使用 generic Phase-2 HASH”；
- “HASH 输入包含 encoded ADDRULE bytes”；
- “必须修改 `keymat_v1.c` 才能支持 ADDRULE”；
- “必须修改通用 task manager 才能支持 ADDRULE”；
- “client request 与 server revoke 应设计成对称格式”；
- “type 17/18/19 可只凭 payload type 自动推断 direction/profile”；
- “固定 `utun8`/`utun9` 可以作为 runtime identity”；
- “离线 encode/decode 自洽等于 vendor/server compatibility”；
- “socket 文件存在或 request 已发送等于 VICI runtime PASS”。

## 4. Protocol fidelity invariant

本项目是 **LeadSec compatibility port**，不是新协议设计。

服务端可观察到的 HTTP/WebSocket 与 IKEv1/ADDRULE 行为必须尽可能匹配合法
vendor PowerVPN 客户端。内部 Swift/C 架构可以重写，但不能擅自优化 wire
protocol。

1. 不得在没有独立证据时增加、删除、重排、归一化、重新解释或对称化任何
   server-visible 字段或消息。
2. 每个 outbound byte 必须可追溯到以下至少一种证据：
   - vendor static serializer/parser evidence；
   - 脱敏 plaintext-boundary specimen；
   - value-free differential oracle；
   - live server acceptance。
3. 未知字段保持 opaque；值相似、命名相似或结构位置相似不构成语义证据。
4. structural parseability 不等于 protocol acceptance；未观察到的 exchange、
   direction、type、dialect、family、payload order 默认 fail closed。
5. 只有完整 LeadSec compatibility predicate 成立时才进入 custom path；标准
   upstream IKEv1 行为必须保持不变。
6. 同一实现生成并验证的 round trip 只证明 self-consistency，不证明 vendor
   compatibility。
7. 当标准“看起来更合理”但 vendor evidence 不同，以有边界的 vendor-compatible
   行为为准；不得进行 standards-based cleanup。
8. bounds checking、secret redaction、zeroization、memory safety 等 wire-neutral
   加固允许；改变服务器看到的 bytes、时序、重传或状态语义不允许。
9. vendor GUI↔helper XPC 与内部类布局只作为 oracle；若两端均由本项目替换，
   不要求复制其内部 API。
10. 任何有意 divergence 必须记录 evidence、置于 compatibility profile 之外、
    feature-gated 且默认关闭。

## 5. Evidence taxonomy

所有重要结论必须标明证据等级，避免把离线自洽写成 live compatibility：

```text
L0  hypothesis
L1  vendor static evidence
L2  vendor value-free runtime observation
L3  candidate self-consistency test
L4  independent implementation/oracle agreement
L5  privileged local runtime evidence
L6  live server acceptance
L7  repeated recovery/coexistence evidence
```

规则：

- CP6 主要达到 L3/L4；
- daemon VICI `version` 只有真实 daemon response 才能达到 L5；
- IKE/ADDRULE 只有 server 接受才能达到 L6；
- 不得用低等级证据替换高等级验收；
- `GOAL_STATUS.md` 中的 `Verified` 项应注明 evidence level。

## 6. Scope

### 本 Goal 包含

- CP7A VICI runtime diagnosis 与 live artifacts；
- 经批准的 privileged backend smoke；
- secure runtime material handoff prototype；
- IKEv1 Main Mode live interop；
- vendor-compatible Quick Mode third-packet ADDRULE；
- 单 resource route/policy/data-path 验证；
- 正交状态模型和 deterministic recovery tests；
- 一次受控 recovery 与 Surge coexistence 验证；
- 完整 teardown、rollback 与 feasibility report。

### 本 Goal 不包含

- SwiftUI/MenuBarExtra；
- App Store、notarization、正式安装包；
- persistent LaunchDaemon/SMAppService 产品化；
- NetworkExtension/PacketTunnelProvider 产品化；
- 多 resource 并发、通用客户端或多用户；
- 学校/服务端管理员协作；
- 新增中转 gateway、代理或 jump host；
- vendor app/helper patch、重签名、永久 injection；
- 从 vendor log/helper 抽取、转存或重放秘密；
- watchdog 或 GUI restart automation；
- 公开二进制分发与许可证包装。

本 Goal 的分发假设是**个人本机/私有源码技术原型**。公开发布属于后续决策。

## 7. Safety and approval gates

### 7.1 Global invariants

1. 不修改 `/Applications/PowerVPN.app`、其签名或 vendor helper；
2. 不关闭 SIP、Gatekeeper、hardened runtime 或系统安全策略；
3. 不执行 system-prefix `make install`；
4. 不安装持久 kext、LaunchDaemon、system extension 或 NetworkExtension；
5. source/build/prefix 保持在 scratch root，大体积生成物不进入 Git；
6. raw capture 位于 mode-700 scratch；Git 只保留脱敏 schema、hash、长度、
   事件顺序和事实表；
7. secret 不进入 argv、environment、shell history、普通文件、CLI output、Git、
   progress log 或 crash log；
8. 本机权限只通过 macOS 原生授权交互取得；Codex 不读取或代输密码；
9. 脚本不得使用会打印 secret 的 `set -x`；
10. 所有 live script 必须 idempotent、bounded、可单独 stop，并验证 zero residue。

### 7.2 CP7A — no approval required

CP7A 只允许：

- unprivileged/random socket daemon；
- official Python VICI client 与 Swift client 的本地 A/B；
- synthetic/redacted `load-conn`；
- 只读进程、socket、文件权限与日志诊断；
- `--dry-run` 启动/停止/rollback 演练；
- shell syntax、path、PID ownership 与 cleanup 单测。

CP7A 禁止：

- `sudo`/Touch ID；
- root `charon`；
- UDP 500/4500；
- VPN server traffic；
- 创建 SA、policy、route、utun；
- 停止或重启当前 PowerVPN；
- 修改 Surge；
- 读取真实 credential。

### 7.3 Live Approval Gate 1 — CP7B privileged backend

CP7A PASS 后，CP7B 分为两个独立授权阶段：

1. **preflight authorization**：只允许独立 scratch build、runner/rollback
   实现、dry validation 和 integrated preflight review；不允许 Touch ID、root
   daemon、PF_KEY/PF_ROUTE live access 或网络变化；
2. **live execution authorization**：preflight PASS 且 manifest 全部 hash 固定后，
   必须再次暂停，并向用户提供一段简短 approval request，包含：

   - 将执行的精确命令；
   - backend、端口、预计持续时间与最大尝试次数；
   - 是否需要 Touch ID；
   - 是否保持 PowerVPN/Surge 运行；
   - 可能影响；
   - pre-state snapshot；
   - stop/rollback 命令；
   - zero-residue 验证命令。

截至 2026-08-09，用户只批准了第一阶段。该批准不得解释为 root/live execution。
用户对任一 CP7B 阶段的批准也**不自动授权** CP8/CP9 server traffic。

### 7.4 Live Approval Gate 2 — server interop

CP7B PASS 且 CP8A secure material handoff PASS 后，必须再次暂停，说明：

- server endpoint 只在私有 runtime 输入中提供；
- 仅一个已授权 resource；
- 最大连接尝试次数；
- 观察指标；
- 完成后 teardown；
- 不记录 secret/raw packet payload。

### 7.5 Live Approval Gate 3 — recovery/network changes

CP9 PASS 后，任何睡眠、Wi-Fi/热点切换、30–120 秒 outage 或主动 path change
都需新的明确批准。

## 8. State and truth model

不得使用单线状态机。至少保持以下正交维度：

```text
DaemonState
  stopped / starting / ready / stopping / failed

VICIState
  disconnected / connecting / ready / timeout / protocolError / failed

BackendState
  uninitialized / initializing / ready / degraded / tearingDown / failed

AuthSessionState
  signedOut / authenticating / valid / expired / failed

ControlChannelState
  disconnected / connecting / online / backoff / failed

IKEState
  idle / mainMode / quickMode / established / degraded / recovering / backoff / blocked

PathGeneration
  monotonic generation + satisfied/unsatisfied + dynamically resolved interface identity

ResourceState per resource
  desired(inactive|active) + observed(inactive|activating|active|failed|unknown)

ProbeState per resource
  unknown / probing / healthy / unhealthy / timeout

UserIntent
  connect / disconnect
```

`OperationalReadiness` 是按同一 generation 动态推导的只读视图：

```text
Daemon ready
+ VICI ready
+ Backend ready
+ Auth material valid
+ IKE established
+ desired resource observed active
+ exact policy/route present
+ probe healthy
```

规则：

- VICI timeout 不等于 daemon process 已死；
- daemon ready 不等于 backend ready；
- WebSocket 断开不等于 auth session expired；
- auth session expired 不等于 IKE_SA 已失效；
- IKE Main Mode 成功不等于 Quick Mode/resource 成功；
- IKE established 不等于 route/data path 正常；
- SSH probe unhealthy 不得把 IKEState 改成 false；
- path change 只 bump generation/debounce，不直接宣称 tunnel dead；
- IKEv1 无 MOBIKE 时，对旧 generation 做 single-flight teardown/re-initiate；
- stale callback/timer 不得覆盖新 generation；
- manual disconnect 必须抑制 recovery；
- interface identity 不得依赖固定 `utunN`；
- 任何层缺失时只在该层报告 unknown/degraded/failed。

## 9. Required repository artifacts

复用现有 SwiftPM 与 docs 结构，不创建平行工程：

```text
README.md
Package.swift
Sources/
  PowerVPNCore/
  PowerVPNCLI/
Tests/
  PowerVPNCoreTests/
docs/
  progress/GOAL_STATUS.md
  evidence/
    vici-runtime-diagnosis.md
    live-test-plan.md
    rollback.md
    checkpoint-7-backend.md
    checkpoint-8-server-interop.md
    checkpoint-9-single-resource.md
  architecture/
  reports/final-feasibility-report.md
fixtures/
  redacted/
patches/
  strongswan-6.0.7/
scripts/
  verify_checkpoint.sh
  verify/
    checkpoint_7a.sh
    checkpoint_7b.sh
    checkpoint_8.sh
    checkpoint_9.sh
  lib/
  run_native_charon.sh
  stop_native_charon.sh
  snapshot_network_state.sh
  assert_clean_teardown.sh
```

规则：

- `verify_checkpoint.sh` 只做参数检查与转发，不堆积 checkpoint 逻辑；
- 共享逻辑进入 `scripts/lib/`，但不要仅因行数做无关重构；
- 第二次重复的手工流程才固化为 helper；
- `run_native_charon.sh` 默认 `--dry-run` 或明确拒绝未授权 live mode；
- PID file 必须记录 executable identity、start time 与 generation；stop 只终止
  与记录身份匹配的进程；
- runtime config、socket、PID、log 使用 mode 600/700 scratch 路径；
- cleanup script 必须可重复执行；
- raw capture、generated build、prefix、private fixture、secret 不进入 Git；
- existing CP6 evidence/patch filenames 不因 V3 重命名；`GOAL_STATUS.md` 继续
  作为 evidence index。

至少忽略：

```text
.build/
.swiftpm/
build/
prefix/
captures/raw/
fixtures/private/
secrets/
runtime/
*.pcap
*.pcapng
*.keylog
*.key
*.p12
*.mobileconfig
```

## 10. Checkpoint plan

### CP0–CP6 — LOCKED PASS

CP0、CP1、CP2、CP3、CP4A、CP5/4B、CP6 均按 Section 3 锁定。除 direct
conflicting evidence 外不得重开。

### Checkpoint 7A — VICI runtime diagnosis and live preparation — PASS

#### Objective

在**不需要 root、不联系 VPN server、不改变网络状态**的条件下，解释并修复
首个 VICI `version` response timeout，证明 Swift client 能与真实 6.0.7
`charon` 交换 VICI request/response；然后补齐可审计的 live 启动、停止、
快照、清理与回滚 artifacts。

#### Diagnostic decision tree

必须使用**同一个 daemon process、同一个 VICI socket、同一 readiness window**
做 A/B：

```text
Official Python VICI version succeeds
Swift version succeeds
  -> transport/runtime PASS; continue load/list/unload

Official Python succeeds
Swift times out/fails
  -> only fix Swift connect/write/frame/read/EOF/timeout handling
  -> do not redesign AST or already-matching request serializer

Official Python also times out/fails
  -> only diagnose daemon launch, VICI plugin, socket URI, readiness,
     permissions, process lifecycle or event loop
  -> do not change Swift wire codec without contrary evidence
```

若需要第三个隔离实验，可使用本地 synthetic Unix-domain test server 验证 Swift
partial-read、length framing、EOF 与 timeout；不得用它替代真实 daemon PASS。

#### Tasks

1. 确认 active 6.0.7 binary、plugin path、config path、VICI socket URI 与 PID；
2. bounded readiness poll：进程存活、VICI plugin loaded、socket 可连接；
3. 对同一 socket 运行 official Python `version`；
4. 运行 Swift `version`，记录 value-free：connect errno、write bytes、read bytes、
   frame type/length、timeout phase；
5. 修复最小 runtime issue；不得改 CP6 protocol patch，除非有 direct evidence；
6. 证明：`version -> synthetic load-conn -> list-conns -> unload-conn`；
7. synthetic connection 不 initiate，不含真实 credential/endpoint/resource；
8. 运行前后证明没有 SA、policy、route、utun 或 production IKE socket；
9. 创建并 dry-validate：
   - `run_native_charon.sh`；
   - `stop_native_charon.sh`；
   - `snapshot_network_state.sh`；
   - `assert_clean_teardown.sh`；
   - `docs/evidence/live-test-plan.md`；
   - `docs/evidence/rollback.md`；
10. 更新 `vici-runtime-diagnosis.md`，记录 last-good / first-bad / exact fix。

#### Acceptance

以下全部满足才可 PASS：

- official Python 与 Swift 均从真实 daemon 收到并解析 `version` response；
- synthetic `load-conn/list-conns/unload-conn` 语义等价；
- 没有 SA、route、policy、utun、server packet 或 secret；
- launch/stop/snapshot/cleanup/rollback 的 dry-run 与 negative tests PASS；
- timeout、stale PID、wrong executable、missing socket、partial response、double stop
  等失败路径可预测且 fail closed；
- `scripts/verify_checkpoint.sh 7a` exit 0；
- targeted tests、arm64 build、secret scan、`git diff --check` PASS；
- 一次 cumulative integrated review 只覆盖 VICI transport、process lifecycle、
  script safety、secret boundary 与 cleanup；
- 形成一个 canonical CP7A commit；
- 更新 `GOAL_STATUS.md` 后暂停在 Live Approval Gate 1。

若 official client 与 Swift 均无法得到 response，但已经精确证明是 6.0.7
runtime/plugin blocker，则 CP7A 可标记 BLOCKED，不得包装成 PASS。

### Checkpoint 7B — privileged backend without server — APPROVAL REQUIRED

#### Objective

在不联系服务器的情况下，证明至少一个 backend 能以临时 root process 在当前
macOS 启动、接受 VICI 控制并完整清理，同时不破坏 Surge。

#### Preflight defaults

- 第一轮保持 Surge 运行；
- 第一轮尽量保持 vendor PowerVPN 运行；若存在明确 provider/port conflict，
  停止 PowerVPN 需要单独写入 approval request；
- 使用独立 CP7B scratch source/build/prefix/piddir 和 scratch config；
- 不加载 `socket-default`：macOS PF_KEY NAT-T 初始化会写全局
  `net.inet.ipsec.esp_port`，且 upstream destroy path 不恢复；
- 使用 `socket-dynamic`；配置保留 `port=0`/`port_nat_t=0`，但 no-send smoke
  的预期 UDP descriptor 数必须为零；
- 不联系任何 VPN gateway；
- 每个 backend 最多两次 launch；
- PF_KEY/PF_ROUTE 严格 timebox，失败证据充分后切 kernel-libipsec/utun；
- 两个 kernel-ipsec provider 不得同时加载。

#### Tasks

1. 完成 dedicated CP7B arm64 build、manifest、runner/rollback 和 negative tests；
2. integrated preflight review PASS 后再次请求 live execution approval；
3. 获批后采集两个稳定 before snapshot：process、interfaces、routes、default
   route、DNS、Surge/PowerVPN、SAD、SPD 和 global ESP port；
4. PF_KEY/PF_ROUTE + `socket-dynamic` 最小启动与 stop smoke；
5. 要求 UDP descriptor 数为零；任何 send 或 ESP-port 变化 fail closed；
6. 若失败，记录 exact errno/plugin boundary，不长期纠缠；
7. 必要时改用 upstream kernel-libipsec + native utun，但必须新 review 和新授权；
8. VICI `version` 与只读 status PASS，connection/SA/policy listing 为空；
9. 不 load connection/credential，不 initiate，不发送 server packet；
10. stop 后执行 zero-residue assertion；
11. 比较 before/during/after，SAD/SPD/ESP port、Surge default route/DNS/
    functionality、PowerVPN 和 utun inventory 不变。

#### Acceptance

- 至少一个 backend 达到 ready 并能干净 teardown；或形成 evidence-complete
  backend blocker；
- 不残留 root process、socket、SA、policy、route、utun、PID/config/log；
- native UDP descriptor 始终为零，`net.inet.ipsec.esp_port` 始终不变；
- Surge before/after 无非预期变化；
- `scripts/verify_checkpoint.sh 7b` 在获批窗口中 PASS；
- 一次 preflight review + 一次 post-run cleanup review；不做额外 broad review；
- canonical CP7B commit 和 evidence report 完成。

### Checkpoint 8A — secure runtime material handoff — NO SERVER TRAFFIC

#### Objective

构建一个不依赖 vendor helper/log 的、用户明确授权的最小运行时材料交付路径，
使 native harness 能获得 server interop 所需参数，同时不把 secret 落盘或输出。

#### Required material classes

```text
gateway/port reference
local/remote identity
PSK credential reference
IKE/ESP proposal
NAT-T setting
VIP/base selector information if required
one approved resource's canonical opaque metadata
```

#### Rules

- secret 不进入 argv/environment/JSON/fixtures/log；
- 允许使用 Keychain reference、secure prompt 或同等 native in-memory provider；
- 不从 `/var/log/vsgvpn.log`、vendor XPC dictionary 或 process memory 导出可重放
  secret；
- redacted render 只能显示 presence/type/length/category，不显示值；
- opaque resource metadata 未经证据不得改名；
- 若无法在不依赖 vendor helper 的情况下取得必要材料，记录为 control-plane
  blocker，不在 CP8B 猜默认值。

#### Acceptance

- `pvnative render --redacted` 或等价 API 生成完整但无 secret 的 live spec；
- credential provider 的 success/cancel/expired/denied/zeroization tests PASS；
- secret scan 与 process-argument audit PASS；
- 不联系 server；
- canonical CP8A commit 完成。

### Checkpoint 8B — IKEv1 Main Mode server interoperability — APPROVAL REQUIRED

#### Objective

用一个已授权 endpoint 和合法运行时材料证明 IKEv1 Main Mode，保持 Quick Mode/
ADDRULE phase 的证据边界清晰。

#### Rules

- 仅一个 endpoint、一个 resource、有限尝试；
- 精确复现已观察 proposal，不擅自强化或现代化算法；
- 记录 VICI/IKE event、last-good-state、first-bad-event；
- 不记录 PSK、identity 原值或 raw decrypted payload；
- 不假设存在“先完成一个独立 base CHILD_SA，再单独 ADDRULE”的 vendor 流程；
- 如果 strongSwan initiation API 将 Main Mode 与 Quick Mode 绑定在一次运行中，
  可以在同一 live run 内继续，但证据与 checkpoint 判定必须按 phase 分离；
- 不发送未经 CP6 canonical profile 验证的 ADDRULE。

#### Acceptance

- Main Mode IKE_SA server acceptance PASS；或形成 proposal/identity/PSK/Vendor-ID/
  runtime-material 的精确 blocker；
- 完整 teardown 与 Surge snapshot PASS；
- canonical CP8B commit 完成。

### Checkpoint 9 — one vendor-compatible Quick Mode + ADDRULE — APPROVAL REQUIRED

#### Objective

完成一个已授权 resource 的 vendor-compatible Quick Mode：第三包携带标准
HASH(3) 与 canonical ADDRULE，并验证 CHILD_SA、resource state、route/policy 与
fresh application traffic。

#### Required protocol behavior

```text
Quick Mode message 1/2
  standard upstream behavior

Quick Mode message 3
  HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni | Nr)
  ADDRULE follows according to the observed canonical profile
  ADDRULE bytes are not part of HASH(3)
```

#### Tasks

- 只激活一个 resource；
- 发送 CP6 canonical outbound ADDRULE；
- 记录 server response/revoke/error category；
- 分别验证 IKE、CHILD_SA、resource observed state、exact route/policy；
- 新建 TCP 连接并读取 SSH banner；
- 发送 canonical DELRULE 或 disconnect；
- 验证完整清理；
- 不测试多 resource、自动恢复或 UI。

#### Acceptance

- server 接受 vendor-compatible Quick Mode/ADDRULE；
- 一个 resource 的 exact route/policy 与 fresh SSH banner PASS；
- Surge 保持预期 default route/DNS/functionality；
- stop 后 zero residue；
- 此 checkpoint PASS 才可宣称 protocol/data-plane **Technical GO**；
- canonical CP9 commit 完成。

### Checkpoint 10A — bounded recovery and Surge coexistence — APPROVAL REQUIRED

只在 CP9 PASS 后：

- deterministic tests 覆盖 generation、single-flight、manual disconnect、stale
  callback suppression、bounded backoff 与 cooldown；
- 执行一次受控 path change；
- 执行一次 30–120 秒 outage；
- 正确恢复，或明确进入 degraded/blocked；
- 不出现重叠连接、重复 SA/route、旧 generation callback、假在线或 secret log；
- Surge 始终保持预期 default route/DNS/functionality；
- manual disconnect 不自动重连；
- canonical CP10A commit 完成。

### Checkpoint 10B — reliability stress — DEFERRED

睡眠、断网、Wi-Fi→热点各 10 次、10/10 成功率、p95 恢复时间与长时间 session
expiry 属于下一轮 daily-driver reliability Goal，不阻塞本轮 technical GO。

### Checkpoint 11 — final feasibility report

输出 `docs/reports/final-feasibility-report.md`：

- Success A 或 Blocked B；
- evidence levels；
- 5.8.0 oracle 与 6.0.7 target 的最小差异；
- CP6 protocol correction 与最终 server result；
- VICI、backend、runtime material、IKE、resource、Surge、recovery 七层边界；
- state model 与测试覆盖；
- secret handling audit；
- 可复现命令、patch hash 与 rollback；
- 一个下一轮最小 Goal，不输出松散 backlog。

## 11. CP7A validation protocol

### 11.1 Fast loop

实现期间只运行：

```text
1. VICI transport targeted tests
2. process/socket lifecycle targeted tests
3. changed Swift target build
4. affected shell dry-run/negative tests
```

不得在每个编辑循环运行 full Swift suite、full strongSwan `make check`、Gitleaks
和全仓 review。

### 11.2 Candidate acceptance

形成 checkpoint candidate 后一次性运行：

```bash
scripts/verify_checkpoint.sh 7a
swift build --arch arm64
swift test
# existing secret scanner / Gitleaks entrypoint
git diff --check
```

如果 CP7A 没有修改 strongSwan source，不重跑 full strongSwan `make check`；只核验
CP6 commit/hash 与运行 binary identity。若修改了 strongSwan shared code，才运行
relevant suite，并在 candidate 末尾最多一次 full acceptance。

### 11.3 Required structured evidence

至少记录：

```text
daemon binary hash and arch
config/plugin path
PID and generation
VICI socket URI/mode/owner
readiness timestamps
official client request/result
Swift client request/result
write/read byte counts
first timeout/failure phase
load/list/unload semantic result
before/after process/socket/network inventory
cleanup result
```

不记录 request secret、endpoint、identity、credential、raw private payload。

## 12. Execution cadence, review budget and commit policy

### 12.1 Default cadence

```text
implement a coherent slice
→ targeted tests
→ continue within checkpoint
→ candidate acceptance once
→ one integrated review
→ fix blocking findings
→ re-run affected tests
→ canonical checkpoint commit
```

### 12.2 Review budget

- CP7A：一次 integrated review，范围仅限 VICI transport、daemon lifecycle、
  script safety、secret boundary、cleanup；
- CP7B/8B/9/10A：一次 preflight review + 一次 post-run cleanup/evidence review；
- 第二个 reviewer 只有在 first review 发现 critical/high finding，或 wire/secret/
  root boundary 改变时才启用，并且只看直接影响面；
- 禁止默认串联 `repo audit → mechanism review → protocol review → commit review`；
- 不使用 generic `commit-smart` 反复拆提交/复审；验收通过后直接形成 canonical
  checkpoint commit；
- 最多两个并行 read-only agent，不允许并行 writer 修改同一 worktree；
- 没有 critical/high finding 时，不做 review-of-review。

### 12.3 Commit policy

- checkpoint 内允许 WIP/fixup commits，不逐个 review；
- checkpoint PASS 前 squash/fixup 为一个 canonical commit；
- commit message 记录 contract、tests、evidence、safety/cleanup；
- strongSwan 与 host repo 分别形成清晰 commit；
- 每个 strongSwan checkpoint 导出最小 patch 并记录 SHA-256；
- 不改写已锁定的 CP6 anchors；
- review 修复优先 amend/fixup，不创建无意义“review cleanup”提交链。

### 12.4 Progress output budget

- 不逐命令向用户直播；
- 不在每个 commit 后更新 `GOAL_STATUS.md`；
- 只在 PASS、BLOCKED、material finding 或 approval gate 更新；
- 每次更新只给一个 `Next command`；
- approval request 必须短、具体、可直接回答。

## 13. Progress protocol

`docs/progress/GOAL_STATUS.md` 使用：

```markdown
## <timestamp> — Checkpoint <id>

State: PASS / IN PROGRESS / BLOCKED / WAITING FOR APPROVAL
Evidence level: L0–L7
Verified:
Not proven:
Evidence:
Canonical commit:
StrongSwan commit/patch SHA-256:
Changed files:
Tests/commands:
Review result:
Safety/cleanup:
Last good state:
First bad event:
Remaining:
Next command:
Approval required: yes/no
```

要求：

- 简短、具体、可审计；
- 不复制 raw log/capture/secret；
- 不用百分比表示研究进度；
- PASS 表示该 checkpoint 的全部 acceptance 已满足；
- “离线 PASS”“local runtime PASS”“server PASS”必须显式区分；
- 不把 future work 写成当前已实现能力。

## 14. Pause conditions

出现以下情况必须暂停：

- CP7A acceptance 已满足，需要进入 root/live backend；
- 需要用户输入或批准真实 credential；
- 需要联系 VPN server；
- 需要停止/退出 PowerVPN；
- 需要改变 Surge、route、policy、SA、utun、Wi-Fi、热点或睡眠状态；
- 需要安装持久服务、NetworkExtension 或 system extension；
- 需要绕过认证、伪造身份或规避完整性校验；
- 需要修改 vendor app/helper、关闭 SIP 或改变系统安全策略；
- capture/output 出现无法自动 redaction 的 secret；
- 同一 blocker 已用两类独立方法复现且继续只会重复；
- 新证据与 CP6 fidelity invariant 冲突；
- 任务漂移到 UI、分发、多用户、多 resource 或长期 daemon 产品化。

暂停前必须记录：exact blocker、已尝试方法、当前安全状态、唯一下一用户动作、
stop/rollback 状态。

## 15. Decision rules

- 5.8.0 build 或 static symbol 不等于 negotiated behavior；
- 6.0.7 build/test 不等于 daemon runtime；
- daemon process/socket 存在不等于 VICI ready；
- offline VICI bytes 与官方一致不等于真实 daemon response；
- self-consistency 不等于 vendor compatibility；
- vendor static evidence 不等于 server acceptance；
- Main Mode PASS 不等于 Quick Mode/ADDRULE PASS；
- route 存在不等于 SA/data path 正常；
- TCP connect 不等于 SSH banner；
- SSH banner 是 ProbeState，不是 IKEState；
- session invalid、control channel lost、IKE_SA lost、resource inactive 是正交状态；
- ADDRULE 位于 vendor-compatible Quick Mode 第三包，不得恢复 custom generic-HASH
  方案；
- ADDRULE bytes 不进入 HASH(3)；
- 不修改标准 keymat/task manager，除非新的 L2/L6 证据直接要求；
- PF_KEY 只做严格 timebox；失败证据充分后转 kernel-libipsec，不同时调两个
  backend；
- 如果 Main Mode 失败，先解决标准层，不写 resource workaround；
- 如果 Main Mode PASS、Quick Mode/ADDRULE 失败，blocker 定位到 resource
  compatibility path；
- 如果 SA/route PASS、banner 失败，先查 policy/data path，不自动重建 auth；
- 如果 CP9 全部互通，不继续复刻 vendor 内部架构；
- review 绑定 checkpoint/risk，不绑定 commit；
- CP7A 未 PASS 前禁止跨 Live Approval Gate。

## 16. Future work explicitly deferred

Success Path A 达成后才考虑：

- native HTTPS/WebSocket 全自动控制面；
- Keychain-backed production credential lifecycle；
- transient root runner 收敛为 XPC service/SMAppService；
- SwiftUI `MenuBarExtra`；
- 多 resource；
- 30-run reliability/p95 stress；
- NetworkExtension 可行性；
- signing、entitlements、notarization、installer 与公开分发。

这些不是本 Goal 的完成条件。

## 17. Reference sources

- 本机 repo：`/Users/larry_1/Opensource/powervpn-cli`
- 当前状态索引：`docs/progress/GOAL_STATUS.md`
- 原生替代路线：`docs/2026-08-08-native-replacement-plan.md`
- 事件复盘：`docs/2026-08-08-power-vpn-incident-postmortem.md`
- strongSwan 6.0.7 build evidence：现有 `docs/` 证据索引
- CP6 canonical lab commit：
  `6122825e37d5061c94d2e1b4e7a88cadcd354e04`
- CP6 strongSwan commit：
  `67c9810900e2d8486cb3b11495a8362433494ca0`
- CP6 patch SHA-256：
  `6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`
- strongSwan 6.0.7 release：
  <https://github.com/strongswan/strongswan/releases/tag/6.0.7>
- strongSwan macOS backend：
  <https://docs.strongswan.org/docs/latest/os/macos.html>
- strongSwan IKEv1：
  <https://docs.strongswan.org/docs/latest/config/IKEv1.html>
- strongSwan VICI/swanctl：
  <https://docs.strongswan.org/docs/latest/swanctl/swanctl.html>
- Codex Follow a goal：
  <https://developers.openai.com/codex/use-cases/follow-goals>
