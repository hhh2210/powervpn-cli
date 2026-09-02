# PowerVPN Native Rescue

状态：面向用户的临时 SSH 与持久会话建立在同一套已验证的 Portal/helper/隧道
runtime 上；底层研究命令保留为兼容调试面。

非官方 arm64 原生 macOS 客户端，替代已停更的 LeadSec PowerVPN 3.2.1 GUI。
它不自带隧道栈，而是驱动官方安装的特权 helper
（/Library/PrivilegedHelperTools/com.leadsec.charon-xpc）按原协议建隧道。
不绕过认证；前提是这台机器仍装有官方 PowerVPN。

## 平台与依赖

仅支持 macOS 14.4+ 的 arm64 机器（xpc_session 的 peer requirement 校验
所需）。客户端驱动本机已安装的官方 x86_64 特权 helper，经 Rosetta 翻译
运行；数据面在内核（utun + IPsec SA）。不存在 Windows/Linux 移植路径。
构建需要 Xcode 工具链。

## 快速开始

前置：官方 PowerVPN 已安装，且至少完整运行过一次（特权 helper 已落位）。

```sh
# 1. 安装
brew tap hhh2210/powervpn
brew install powervpn
# 或源码构建：swift build --product powervpn --arch arm64

# 2. 准备配置
mkdir -p ~/.config/powervpn
#    credentials.env：PORTAL_USERNAME / PORTAL_PASSWORD，权限 0600
#    targets.json：cp docs/targets.example.json 改填真实值（portalOrigin
#    与 targets 映射），权限 0600

# 3. 配置 ~/.ssh/config 的 Host 块（见下文），然后选择一种工作流
powervpn ssh lab-a -- hostname       # 临时：命令结束后清理隧道
powervpn up lab-a                    # 持久：建立可复用后台会话
ssh lab-a                            # 普通 SSH / IDE Remote-SSH 复用该会话
powervpn down                        # 停止并验证清理
```

targets.json 缺失、目标不存在、字段非法时分别 fail-closed 为
config_missing / target_unknown / target_invalid，不联系 Portal。

首次验证：

```sh
powervpn doctor --json
```

## 当前状态

- 临时 SSH：`powervpn ssh <target>` 自动建立隧道、运行系统 SSH、忠实返回远端
  exit code，并在 SSH 结束后等待现有 runtime 验证清理。
- 持久会话：`powervpn up <target>` 启动后台 OpenSSH ControlMaster；master 的
  ProxyCommand 持有 PowerVPN lease，普通 SSH 和 Remote-SSH 复用同一 socket，
  直到 `powervpn down`。
- `powervpn status` 显示产品态；helper、launchd 和历史 crash 细节放在
  `powervpn debug status`。

## 命令

临时 SSH（agent / 单条命令）：

```sh
powervpn ssh lab-a
powervpn ssh lab-a -- hostname
powervpn ssh lab-a -- 'some remote command'
```

持久会话（human / IDE）：

```sh
powervpn up lab-a
powervpn status
ssh lab-a
# VS Code / Cursor Remote-SSH 选择同一 Host 别名 lab-a
powervpn down
```

调试命令不属于日常产品面；用下列命令查看：

```sh
powervpn debug help
```

## 目标配置

所有 current-machine 命令都先读取 `~/.config/powervpn/targets.json`。
文件必须是当前用户拥有的普通文件且权限严格为 `0600`；产品命令用 target key
精确查找 `targets[key]`，并从同一项解析目标 IP、SSH 用户和 Portal `resource`，
不会要求用户输入 M2/resource-display-name 等内部参数。配置缺失、目标不存在或字段非法时返回
`config_missing`、`target_unknown`、`target_invalid`，不会联系 Portal 或
请求 helper 变更。闭合 schema 示例见 `docs/targets.example.json`；先复制后
替换 `portalOrigin`、目标数字 IPv4、SSH 用户名和对应的 Portal 资源显示名：

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

Host 块只描述普通 SSH 目标和 ControlMaster socket。`powervpn up` 在启动 master
时临时注入内部 ProxyCommand；后续 `ssh lab-a` 和 Remote-SSH 只复用这个 master，
不会重复 Portal/helper startup。无需给 Host 块永久写入 PowerVPN ProxyCommand。

```text
Host lab-a
  HostName <numeric-ipv4>
  User <remote-user>
  Port 22
  ControlMaster auto
  ControlPath ~/.ssh/cm-%C
  ControlPersist 8h
```

规则：

- HostName 必须与 `targets.json` 的数字 IPv4 一致。
- User 必须与 `targets.json` 一致。
- `ControlMaster auto` 与绝对展开后的 `ControlPath` 是持久模式的复用边界；
  `powervpn up` 会拒绝接管不是它创建的现有 master。
- 临时 `powervpn ssh` 强制 `ControlMaster=no`，所以不会错误复用持久 lease。

`powervpn up lab-a` 返回 READY 后，`ssh lab-a` 就是日常用法；VS Code / Cursor
Remote-SSH 选择同一别名。

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

当前 test inventory 为 882 项，`swift test` 全量通过。

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
