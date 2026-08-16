# PowerVPN Native Rescue

状态：M1 被动查询 / M2 一次性连接 / proxy 持久访问，三阶段 live-proven。

非官方 arm64 原生 macOS 客户端，替代已停更的 LeadSec PowerVPN 3.2.1 GUI。
它不自带隧道栈，而是驱动官方安装的特权 helper
（/Library/PrivilegedHelperTools/com.leadsec.charon-xpc）按原协议建隧道。
不绕过认证；前提是这台机器仍装有官方 PowerVPN。

## 当前状态

- M1 被动查询：只读命令，不登录 Portal，不改 helper 状态。
- M2 一次性连接：connect-once 全链 PASS，含新鲜 SSH banner 证明。
- 持久代理访问：proxy ssh 经 OpenSSH ProxyCommand 直达远端主机，exit 0；
  IDE 场景（Remote-SSH 走 Host 别名）同样 exit 0。

## 命令

被动查询（M1）：

```sh
powervpn doctor --json
powervpn helper status --json
powervpn resources --json
powervpn snapshot --dry-run --json
```

一次性连接（M2）：

```sh
powervpn m2 connect-once \
  --resource-display-name <resource> \
  --ssh-target <ssh-target> \
  --json
```

代理访问（proxy）：

```sh
# OpenSSH ProxyCommand 模式（Remote-SSH 推荐路径）
powervpn proxy ssh --resource-display-name <resource> --ssh-target <ssh-target> \
  <numeric-ipv4> <port> --non-interactive

# 前台 loopback SOCKS4/5，默认 127.0.0.1:1080，给浏览器等 TCP 客户端用
powervpn proxy serve --resource-display-name <resource> --ssh-target <ssh-target> \
  --listen-port 1080 --non-interactive --json
```

proxy serve 底层是系统 /usr/bin/ssh -D，不是自研 SOCKS 实现，也没有
LaunchAgent/daemon。两个命令都在前台运行，SIGHUP/SIGINT/SIGTERM 停止，
退出前会停掉 helper 租约并验证清理。

## 目标配置

所有 current-machine 命令都先读取 `~/.config/powervpn/targets.json`。
文件必须是当前用户拥有的普通文件且权限严格为 `0600`；`--ssh-target <key>`
精确查找 `targets[key]`。配置缺失、目标不存在或字段非法时会分别返回
`config_missing`、`target_unknown`、`target_invalid`，不会联系 Portal 或
请求 helper 变更。闭合 schema 示例见 `docs/targets.example.json`；先复制后
替换 `portalOrigin`、目标数字 IPv4 和 SSH 用户名：

```sh
mkdir -p ~/.config/powervpn
cp docs/targets.example.json ~/.config/powervpn/targets.json
chmod 600 ~/.config/powervpn/targets.json
```

## 凭据

--non-interactive 模式从 ~/.config/powervpn/credentials.env（0600）读：

```sh
PORTAL_USERNAME=...
PORTAL_PASSWORD=...
```

不加 --non-interactive 时走 TTY 模式，操作者当场输入。凭据绝不进
argv、日志或报告。

## Remote-SSH 配置

proxy ssh 就是一个 OpenSSH ProxyCommand：拿到一次批准的资源租约后，
exec 系统 /usr/bin/nc 连到数字 IPv4 + 端口，透传 stdin/stdout。
VS Code / Cursor 的 Remote-SSH 起的就是同一个 ssh，不需要额外 SOCKS 跳板，
http.proxy / remote.SSH.httpProxy 与这一跳无关。

```text
Host campus-host
  HostName <numeric-ipv4>
  User <remote-user>
  Port 22
  ControlMaster no
  ProxyCommand <binary-path> proxy ssh --resource-display-name <resource> --ssh-target <ssh-target> %h %p --non-interactive
```

规则：

- `%h` 展开后必须是数字 IPv4，主机名会被拒绝，所以 HostName 直接写数字地址。
- `--non-interactive` 必须是最后一个参数；Remote-SSH 没有控制 TTY。
- `ControlMaster no`：共享 socket 会让后续连接绕过隧道，必须关掉。
- ProxyCommand 是一整行，不要整体加引号；只有含空格的单个参数（如资源
  显示名）才单独引起来。`<binary-path>` 用
  swift build --product powervpn --arch arm64 产物的绝对路径。

## 工程约束

- 协议保真不变量：每个出站字节都必须能溯源到 vendor 证据（从冻结的官方
  客户端逆向出的字段与序列），不发明、不猜。
- value-free 报告：JSON 报告为 schema 15，全部 closed enum token，
  不携带地址、用户名等值。
- M2 是一次性交易：单调 120 秒预算、生成围栏（generation fencing）、
  有界清理、授权材料用后擦除。
- proxy 退出码：0 成功且清理已验证；64 用法错误；69 helper 变更前不可用；
  70 已验证清理后的运行失败；74 清理未证明（不要重试）；77 批准被拒或
  不可用；130 取消。

## 已知 vendor 缺陷与客户端对策

helper 是官方闭件，不可修改；以下缺陷都在客户端侧缓解：

- 所有命令响应只经 ordinary connection channel 返回，reply callback 永远
  不回业务 ACK。客户端把 ReplyFailed 归为 replyUnavailable（非终结），
  继续在 ordinary channel 上等结果。
- 异步 status 通知会读一个未 retain 的全局请求指针（use-after-free），
  迟到的 CHILD_SA install/delete 通知可触发 helper SIGILL。客户端在 stop
  后驻留 10 秒 drain，并在 route 前对 status 通知设 400/800ms 静默门。
  teardown 臂无法根治（崩溃可能晚于任何有限 drain），install 臂已缓解。
- Portal catalog 偶发服务端退化（拒绝列举）。客户端做一次 fresh-login
  重试，再失败即如实上报失败判别 token。

## 构建与目录

```sh
swift build --product powervpn --arch arm64
swift test
```

测试 854 通过。

```text
Sources/
  PowerVPNCore/    vendor helper XPC 控制连接与协议模型
  PowerVPNPortal/  Portal 登录、凭据、cookie、catalog
  PowerVPNProduct/ M1/M2/proxy 产品编排与状态机
  PowerVPNCLI/     argv 解析与命令入口
```

## 历史证据

Rescue R1/R2、checkpoint 序列、strongSwan 5.8.0 溯源、expandrule 线协议
契约、R2 TLS 信任链等协议取证材料完整保留在 docs/（含 docs/evidence/、
docs/progress/）。它们不再是产品关键路径，但仍是理解协议约束的第一手
依据。
