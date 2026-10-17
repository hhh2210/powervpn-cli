# Native strongSwan 后端：数据面打通记录（2026-10-17）

结论：用本仓库补丁版 strongSwan 6.0.7 自己的 charon（kernel-libipsec + VICI）
替代厂商 x86_64 helper 连接 NC 资源，在打开 `charon.leadsec_new_client_vid`
后稳定可用：A/B 对照补 VID 6/6、不补 0/6，随后连续 10/10，每次都 `ssh` 成功并收到回程 ESP。

正式 `powervpn` CLI 仍走厂商 helper。本记录只证明 native 数据面可行；
接进产品命令（`backend = native`）是下一步。

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
