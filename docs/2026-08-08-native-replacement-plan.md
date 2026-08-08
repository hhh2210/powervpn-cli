# PowerVPN Apple Silicon 原生替代路线

日期：2026-08-08

作者：Zhuoyuan Hao、Codex

状态：协议可行性阶段；取代旧的 GUI 重启、watchdog、等待厂商/管理员路线

## 1. 目标与边界

目标是在服务端完全不变、不绕过认证的前提下，用 Apple Silicon 原生
客户端逐层替换 PowerVPN，并补齐可验证的恢复状态机。

本项目不再把以下方案当作目标：

- 新增一台中转 gateway 或把 Mac 变成长期网关；
- 依赖学校或服务端管理员调整协议；
- 等待厂商提供 ARM 更新；
- 用 watchdog 或 `reconnect` 隐藏厂商故障；
- 在协议未验证前开发 SwiftUI 或 NetworkExtension。

这里的“排除管理员”指不依赖学校/服务端管理员。若最终采用 PF_KEY、
kernel-libipsec 或自建 utun，本机仍需要用户亲自批准一次受控的
LaunchDaemon；本轮没有请求或使用该权限。

## 2. 已证实的协议分层

```text
HTTPS / WebSocket portal
    -> runtime PSK, virtual IP, resource/rule metadata
       (session binding and value provenance are not yet fully known)
    -> IKEv1 Main Mode + standard base Quick Mode
    -> private encrypted QUICK_MODE [HASH ADDRULE/DELRULE]
    -> custom kernel-ipsec/utun policy installation
```

本机二进制和允许列表日志已证明：

1. `charon-xpc` 基于 strongSwan 5.8.0；
2. `leadsecbridge` 是 critical plugin，并提供自定义
   `CUSTOM:kernel-ipsec`；
3. 成功会话发送 `HASH ADDRULE`，二进制同时包含 `DELRULE_V1`、
   `expandrule_payload_create` 和 IKEv1 task 扩展；
4. 因而分类不是 A（纯配置翻译），而是 B + C：自定义 strongSwan
   plugin，加私有 IKEv1 resource-rule wire extension；
5. 标准 IKE/ESP 基础仍可由 upstream strongSwan 承担。

这把最大未知量从“是否有私有协议”缩小为“私有扩展的最小编码、状态
转移和内核安装语义是什么”。

## 3. 版本策略

最终目标以 strongSwan 6.0.7 为基线，5.8.0 只作为行为 oracle。

选择 6.0.7 的原因：

- 官方 6.0 文档仍提供 IKEv1、XAuth、VICI 和 macOS backend；
- 6.0.7 修复了影响 `libstrongswan` 的 CVE-2026-47895；
- 本机已经完成 arm64 编译和非 root 插件加载烟测；
- 新实现不应从一个 2019 年的 vendor fork 开始积累技术债。

不能直接加载厂商 5.8.0 plugin。6.0.3 起 loader 强制插件版本匹配；更
重要的是，最终产品不能依赖 x86_64 vendor code。迁移方式应是从协议
证据重写最小扩展，并把 patch 与 upstream 6.0.7 独立维护。

## 4. 最小 patch surface

预期需要的 strongSwan 改动边界是：

- 一个 `expandrule` payload codec，负责长度、编码、校验和安全解析；
- IKEv1 Quick Mode task 的 ADDRULE/DELRULE 生成与接收分支；
- 资源 desired/observed state 到该 task 的调用边界；
- 如 upstream backend 不满足服务端语义，一个窄的 macOS kernel adapter。

这不是“纯 VICI 配置即可”，也不应演变成复制整个 `leadsecbridge`。
VICI 负责标准 connection/credential/SA 生命周期；私有资源 task 通过
一个小型、可测试的扩展接口进入。

## 5. 分阶段 hard gates

### Gate 0：oracle 证据

- 版本、插件、backend 和私有 payload marker 能由只读 CLI 重现；
- 任何输出均不包含 raw log、session、PSK、cookie 或身份值；
- TunnelSpec 的可提交 fixture 通过严格 redacted gate。

### Gate 1：6.0.7 arm64 基线

- `charon`、`swanctl`、VICI、PF_KEY、PF_ROUTE、kernel-libipsec 均为 arm64；
- 非 root 启动能加载 PF_ROUTE/VICI，并且 kernel backend 仅因预期权限
  门槛停止；
- 不启动真实连接，不更改路由。

### Gate 2：三条协议边界

- 控制面：登录、session check、资源列表/激活的脱敏结构；
- XPC：GUI 到 helper 的 key/type/order，不记录 value secret；
- IKE：成功连接与网络切换失败的消息类型/顺序，原始 capture 留在
  mode-700 scratch。

### Gate 3：标准 base SA

- 用 6.0.7 复现 IKEv1 Main Mode + PSK；
- 复现 base CHILD_SA；
- PF_KEY 和 kernel-libipsec 只在隔离窗口分别测试，选择证据更好的后端。

### Gate 4：资源扩展

- 先用离线 fixture 完成 ADDRULE/DELRULE encode/decode round trip；
- 再复现单个资源的服务器认可响应；
- 最后验证单个 `/32` 路由、SSH banner 和资源关闭清理。

### Gate 5：控制面与恢复

- 自有 HTTPS/WebSocket 客户端生成 runtime TunnelSpec；
- credential 只进入 Keychain 或受限内存；
- 睡眠、Wi-Fi 切换、热点切换均按 current generation 重建。

每一 Gate 都必须单独 PASS。协议失败时不提前构建 UI、LaunchDaemon 或
NetworkExtension。

## 6. 恢复模型

恢复状态不能压成一条线，也不能把 SSH banner 当唯一真相。至少维护四
组正交状态：

- `ControlSessionState`：signedOut / ready / reconnecting / expired；
- `TunnelState`：idle / connecting / established / degraded / backoff；
- `PathGeneration`：每次稳定网络路径变化递增；
- per-resource desired/observed state。

WebSocket 断开不等于 SA 失效；SA 失效也不等于 session 过期。协调器按
证据选择最小恢复动作。手动断开必须抑制自动恢复；网络变化经 debounce
后 single-flight 重建，旧 generation 的回调不得把状态改回 established。

`Established` 最终需同时满足 current-generation IKE/CHILD 状态、资源
ADDRULE 结果、期望 `/32` 路由和应用层 probe；缺任一项只能是 degraded。

## 7. Surge 共存约束

当前 Surge 使用自己的 Packet Tunnel 和 `utun8`。启用另一个系统 VPN
配置可能禁用其他 app 的 VPN configuration，因此 Apple 内置 IKEv1 和
PacketTunnelProvider 不是无副作用的“便宜实验”。

首选产品形态仍是受控 arm64 daemon 加独立 utun/精确路由。任何内置 VPN
或 NetworkExtension 实验必须安排隔离窗口，记录 Surge 前后状态，并有
明确恢复步骤。本轮没有切换任何 VPN configuration。

## 8. 当前下一步

最高价值工作不是继续反汇编所有函数，而是产出一次成功认证的三边界
脱敏 capture，并以此建立 ADDRULE/DELRULE 离线 codec fixture。完成前，
不得宣称 6.0.7 已能连接生产服务端。
