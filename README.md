# powervpn

在 Apple Silicon Mac 上用命令行连清华 LeadSec PowerVPN 后面的服务器，代替已经停更的官方 GUI。
第一次由你本人在终端里配置、登录、确认能 SSH 上去；之后的日常命令可以全部交给 coding agent 跑。

<img width="700" height="112" alt="image" src="https://github.com/user-attachments/assets/2baf3ae8-d342-44de-a3ea-0c0da8c93265" />

它不自带加密隧道：默认驱动官方 PowerVPN 装好的特权 helper
（`/Library/PrivilegedHelperTools/com.leadsec.charon-xpc`）按原协议建隧道，
补上了官方客户端在长连接稳定性、和 Surge 这类代理共存方面的问题。
认证照常走学校 Portal，不绕过任何登录。

## 需要什么

- arm64 Mac，macOS 14.4 或更新。
- 已安装官方 PowerVPN，并且用它成功连过一次（这样特权 helper 才会装好）。
- 你自己的 Portal 账号，以及要连的服务器 IP、SSH 用户名，和它在 Portal 里对应的资源名。
- 从源码构建需要完整的 Xcode（只装 Command Line Tools 不够）。

## 第一次使用（你本人在终端里做）

**1. 安装**

```sh
git clone https://github.com/hhh2210/powervpn-cli.git
cd powervpn-cli
swift build -c release --product powervpn --arch arm64
mkdir -p ~/.local/bin && cp .build/release/powervpn ~/.local/bin/   # 或任何在 PATH 里的目录
```

`brew install hhh2210/powervpn/powervpn` 也能装，但它装的是最近一个 release tag，可能比源码旧。

**2. 写账号密码**

```sh
mkdir -p ~/.config/powervpn
cat > ~/.config/powervpn/credentials.env <<'EOF'
PORTAL_USERNAME=你的账号
PORTAL_PASSWORD=你的密码
EOF
chmod 600 ~/.config/powervpn/credentials.env
```

权限不是 `0600` 时命令会直接拒绝运行。密码只从这个文件读，不会出现在命令行参数、日志或报告里。

**3. 写要连的服务器**

```sh
cp docs/targets.example.json ~/.config/powervpn/targets.json
chmod 600 ~/.config/powervpn/targets.json
```

然后按你自己的情况改：

```json
{
  "portalOrigin": "https://<Portal 地址>:<端口>",
  "targets": {
    "lab-a": { "host": "<服务器 IPv4>", "user": "<SSH 用户名>", "resource": "<Portal 里的资源名>" }
  }
}
```

- `lab-a` 是你给这台机器起的名字，后面所有命令都用它。
- `portalOrigin` 就是你在浏览器里登录 VPN 门户的地址。
- `resource` 必须和官方客户端资源列表里的名字一字不差。
- 可以写多台；不过同一时间只能连其中一台。

**4. 配 SSH**

在 `~/.ssh/config` 里给每个目标加一段，名字和 `targets.json` 里的一致：

```text
Host lab-a
  HostName <服务器 IPv4>
  User <SSH 用户名>
  ControlMaster auto
  ControlPath ~/.ssh/cm-%C
  ControlPersist 8h
```

`HostName` 和 `User` 必须和 `targets.json` 对上。不要在这里写 PowerVPN 的 `ProxyCommand`，
需要时 `powervpn up` 会自己注入。

**5. 自检并连一次**

```sh
powervpn doctor              # 应显示 ready；否则会指出第一个要修的问题
powervpn ssh lab-a -- hostname
```

第二条能打印出服务器的主机名，就说明 Portal 登录、隧道和 SSH 全都通了。

想长时间挂着（比如给 VS Code / Cursor Remote-SSH 用）：

```sh
powervpn up lab-a    # 建立后台会话
ssh lab-a            # 普通 ssh 和 Remote-SSH 都复用这条会话
powervpn down        # 用完断开，并确认路由已恢复
```

## 交给 Agent

自检通过之后，Agent 只需要一条命令：

```sh
powervpn run lab-a -- 'nvidia-smi -L'
```

`run` 会复用已有的会话，没有就自动建一个。遇到常见的瞬时失败，它会自己重试或恢复。
多个 `run` 可以同时跑，共用同一条会话。

把 `skills/powervpn/SKILL.md` 装进 agent 的 skill 目录（Claude Code 是 `~/.claude/skills/powervpn/`），
它就知道该怎么用 `run`，什么时候自己恢复，什么时候该来找你。
需要人出面的只有这几种情况：输入密码、短信验证码、Touch ID，以及 macOS 弹出的授权框。

退出码：

| 退出码 | 意思 | 怎么办 |
|---|---|---|
| 远端命令自己的码 | 命令已在服务器上跑完 | 按命令本身处理 |
| 75 | 暂时不行（会话忙、启动失败、中途断开） | 等一会儿原样重跑 |
| 77 | 卡住了 | 看 stderr 最后的 `next:` 行，照着做 |

PowerVPN 自己出错时，stderr 最后两行固定是 `powervpn run: <原因>` 和 `next: <下一步>`。
没有这两行，说明 75/77 是远端命令自己返回的。

## 出问题时

- 先跑 `powervpn doctor`，它会指出第一个要修的问题。
- `next:` 提示 `powervpn recovery …`：说明上次断开时没能确认路由已恢复，会话被隔离了。
  先跑 `powervpn recovery inspect --json`，再跑 `powervpn recovery clear --json`，
  后者只在实测网络状态干净时才会解除隔离。
- `next:` 提示 `powervpn repair vendor-log --json`：官方日志文件丢了，或者权限不对。
  跑这条命令会弹一次 macOS 管理员授权，确认后修复。
- 开发和底层调试命令都在 `powervpn debug help` 里，日常用不到。

## Native strongSwan 后端（实验）

另一条路线是不用官方 helper，改用打过补丁的 strongSwan 6.0.7 自己的 charon 直连，
原生 arm64，不经过 Rosetta。2026-10-17 在真实网关上跑通：补上 `NEW CLIENT` Vendor ID 之后，
对照实验 6/6 对 0/6，随后连续 10/10 都能 SSH 上去。
它还没接进 `run` / `up` / `ssh`，日常仍走官方 helper。
补丁和清单在 `patches/strongswan-6.0.7/`，过程和数据见
`docs/evidence/native-strongswan-backend.md`。

## 开发

```sh
swift build --product powervpn --arch arm64
scripts/hermetic_swift_test.sh    # swift test，但读不到本机真实的 PowerVPN 状态
```

```text
Sources/
  PowerVPNCore/         helper XPC 控制、VICI、路由与清理判定
  PowerVPNPortal/       Portal 登录、凭据、cookie、资源目录
  PowerVPNProduct/      run/up/ssh/down 的编排与状态机
  PowerVPNCLI/          命令行入口
  PowerVPNNativeTrial/  native strongSwan 后端的实验驱动
patches/strongswan-6.0.7/  charon 补丁序列
skills/powervpn/           给 agent 的 skill
docs/                      协议取证、设计和历史记录
```

`main` 是唯一的长期分支，功能分支通过 PR 合进来，发布用 tag（见 `docs/branching.md`）。
