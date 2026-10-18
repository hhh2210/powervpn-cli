# powervpn

在 Apple Silicon Mac 上用命令行连清华 LeadSec PowerVPN 后面的服务器。
隧道由我们自己打过补丁的 strongSwan 建立，原生 arm64，**不需要安装官方 PowerVPN 客户端**。
第一次由你本人在终端里构建、安装、写配置，确认能 SSH 上去；之后的日常命令可以全部交给 coding agent。

<img width="700" height="112" alt="image" src="https://github.com/user-attachments/assets/2baf3ae8-d342-44de-a3ea-0c0da8c93265" />

## 它是怎么工作的

```text
powervpn run thu21 -- cmd                       你的用户身份
  ├─ Portal 登录、选资源（和官方客户端走同一套认证，不绕过登录）
  ├─ 通过 VICI 让 charon 建 IKEv1 和隧道
  └─ 作为 ssh 的 ProxyCommand 转发 ──► 只有目标 IP 走隧道

powervpn-native-helper                          root LaunchDaemon，安装一次
  ├─ 常驻运行打过补丁的 charon（strongSwan 6.0.7）
  ├─ VICI 代理逐帧检查命令与配置字段；charon 的原始 socket 只供 root 访问
  └─ 控制接口：查状态、为安装时授权的目标加 /32 路由、删掉它
```

- 默认路由、DNS 和 Surge 都不动，只有你配置的目标 IP 走隧道。
- helper 不执行任何调用方给的命令或路径，控制 socket 只对安装它的用户开放。
- 正常断开会核对路由、SA、连接配置、共享密钥和 Portal 登出。异常退出后的恢复只证明本地对象已清理；Portal 登出无法确认时保留原记录，后续连接前归档到 `~/.local/state/powervpn/native-recovery-*.json`。
- 清理由会话记录中的 backend 决定；修改 `targets.json` 不会清除另一后端的未完成清理。没有 backend 字段的旧记录按 vendor 处理。

## 需要什么

- arm64 Mac，macOS 14 或更新。
- 完整的 Xcode（只装 Command Line Tools 不够）和 Homebrew。

- 你自己的 Portal 账号，以及要连的服务器 IP、SSH 用户名，和它在 Portal 里对应的资源名。

## 第一次使用（你本人在终端里做）

**1. 安装**

```sh
brew install hhh2210/powervpn/powervpn
```

Homebrew 在本机从源码编译 CLI、root helper 和打过补丁的 strongSwan 6.0.7，约几分钟。
想直接从源码构建，见文末「从源码构建」。

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
  "backend": "native",
  "targets": {
    "lab-a": { "host": "<服务器 IPv4>", "user": "<SSH 用户名>", "resource": "<Portal 里的资源名>" }
  }
}
```

- `lab-a` 是你给这台机器起的名字，后面所有命令都用它。
- `portalOrigin` 就是你在浏览器里登录 VPN 门户的地址。
- `resource` 必须和 Portal 资源列表里的名字一字不差。
- `backend` 不写时默认是旧的官方 helper 方案，所以这里要写 `"native"`。
- 可以写多台；同一时间只连其中一台。

**4. 安装 native 后端（只需要一次 sudo）**

```sh
sudo "$(brew --prefix)/bin/powervpn" native install
```

它只装我们自己的东西：`/Library/PrivilegedHelperTools/com.hhh2210.powervpn-native/` 和一个 LaunchDaemon。
看到 `install: native backend running` 就好了。

安装时会把 `targets.json` 的目标 IP 固定到 root 拥有的路由白名单。以后新增或修改目标 IP，需重新执行安装命令。
root 进程运行的是复制进系统目录、校验过的副本，从不直接执行 Homebrew 目录（当前用户可写）里的文件。

**5. 配 SSH**

在 `~/.ssh/config` 里给每个目标加一段，名字和 `targets.json` 里的一致：

```text
Host lab-a
  HostName <服务器 IPv4>
  User <SSH 用户名>
  ControlMaster auto
  ControlPath ~/.ssh/cm-%C
  ControlPersist 8h
```

`HostName` 和 `User` 必须和 `targets.json` 对上。不要在这里写 `ProxyCommand`，`powervpn` 会自己注入。

**6. 自检并连一次**

```sh
powervpn doctor              # 应显示 ready；否则会指出第一个要修的问题
powervpn ssh lab-a -- hostname
```

第二条能打印出服务器的主机名，就说明 Portal 登录、隧道和 SSH 全都通了。

想长时间挂着（比如给 VS Code / Cursor Remote-SSH 用）：

```sh
powervpn up lab-a    # 建立后台会话
ssh lab-a            # 普通 ssh 和 Remote-SSH 都复用这条会话
powervpn down        # 用完断开，并核对路由、SA 都已清理
```

## 交给 Agent

自检通过之后，Agent 只需要一条命令：

```sh
powervpn run lab-a -- 'nvidia-smi -L'
```

`run` 会复用已有的会话（一条命令约 0.1 秒），没有就自动建一个（约 1.5 秒）。
遇到 Portal 资源列表偶发不完整这类瞬时失败，它会自己重试。多个 `run` 可以同时跑，共用同一条会话。

把 `skills/powervpn/SKILL.md` 装进 agent 的 skill 目录（Claude Code 是 `~/.claude/skills/powervpn/`），
它就知道该怎么用 `run`，什么时候自己恢复，什么时候该来找你。

退出码：

| 退出码 | 意思 | 怎么办 |
|---|---|---|
| 远端命令自己的码 | 命令已在服务器上跑完 | 按命令本身处理 |
| 75 | 暂时不行（会话忙、启动失败、中途断开） | 等一会儿原样重跑 |
| 77 | 需要人（helper 没装、账号被拒、配置或 TLS 信任被拒） | 看 stderr 最后的 `next:` 行，照着做 |

PowerVPN 自己出错时，stderr 最后两行固定是 `powervpn run: <原因>` 和 `next: <下一步>`。
没有这两行，说明 75/77 是远端命令自己返回的。

## 出问题时

- 先跑 `powervpn doctor`，它会指出第一个要修的问题和下一步。
- native 登出会用同一会话做前后只读探测：只有确认已失效才报告完整清理。网关的 logout HTTP 302 不会被跟随，也不直接视为成功。若探测明确仍有效，自动重连被阻止；只有本人在 Portal 结束该会话后，才使用 `powervpn recovery clear --json --acknowledge-portal-logout`。这个显式确认保留原始未验证回执，不用于自动重试。
- `native_portal_unavailable` / `native_resource_unavailable`：Portal 传输或目录暂不可用，`run` 有限重试后返回 75，不误报密码错误。
- `native_helper_unavailable` / `native_charon_unavailable`：helper 没装或没在跑，按 `next:` 行重新安装 native 后端。
- 日志（需要 sudo 读）：`/var/log/powervpn-native-helper.log`、`/var/log/powervpn-native-charon.log`。
- 升级：`brew upgrade powervpn`。只有 helper 或 strongSwan 运行时变了才需要再 sudo 一次；
  `powervpn native status` 或 `powervpn doctor` 会告诉你，并给出要执行的命令。
- 卸载：`sudo "$(brew --prefix)/bin/powervpn" native uninstall`，再 `brew uninstall powervpn`。

## 为什么需要打补丁

LeadSec 网关说的是带私有扩展的 IKEv1：Quick Mode 里要带一段 `ADDRULE` 载荷描述资源，
Main Mode 第一个包还要带 `NEW CLIENT` 这个 Vendor ID。缺了后者，网关照样完成 IKE、建隧道、
转发入向流量，就是不给虚拟 IP 回 ESP，表现为能连上却收不到任何回包。
补上之后对照实验 6/6 对 0/6，随后连续 10/10 都能 SSH 上去。
补丁和清单在 `patches/strongswan-6.0.7/`，过程和数据见 `docs/evidence/native-strongswan-backend.md`。

## 旧方案：驱动官方 helper

不写 `backend` 或写 `"backend": "vendor"` 时，powervpn 改为驱动官方 PowerVPN 装的 x86 特权 helper。
它需要先装官方客户端，断开时证明不了清理干净，会进入隔离和 recovery 流程。
只作为回退保留，见 [docs/vendor-backend.md](docs/vendor-backend.md)。

## 从源码构建

不用 Homebrew 时，先装构建依赖，再用仓库里的脚本：

```sh
brew install autoconf automake libtool gettext bison gperf pkgconf openssl@3
git clone https://github.com/hhh2210/powervpn-cli.git
cd powervpn-cli
scripts/native/build_runtime.sh            # 拉 strongSwan 6.0.7，打补丁，编译，约 1–2 分钟
swift build -c release --arch arm64
mkdir -p ~/.local/bin && cp .build/release/powervpn ~/.local/bin/   # 或任何在 PATH 里的目录
sudo scripts/native/install.sh             # 代替 powervpn native install；升级后同样重跑
```

卸载用 `sudo scripts/native/uninstall.sh`。

## 开发

```sh
swift build --arch arm64
scripts/hermetic_swift_test.sh --no-parallel   # swift test，但读不到本机真实的 PowerVPN 状态
```

```text
Sources/
  PowerVPNCore/          VICI、helper 协议、路由与清理判定
  PowerVPNPortal/        Portal 登录、凭据、cookie、资源目录
  PowerVPNProduct/       run/up/ssh/down 的编排；NativeTunnel 是 native 后端
  PowerVPNCLI/           命令行入口
  PowerVPNNativeHelper/  root helper（charon 守护、/32 路由）
  PowerVPNNativeTrial/   native 后端的实验驱动
patches/strongswan-6.0.7/  charon 补丁序列
scripts/native/            runtime 构建、安装、卸载
skills/powervpn/           给 agent 的 skill
docs/                      协议取证、设计和历史记录
```

`main` 是唯一的长期分支，功能分支通过 PR 合进来，发布用 tag（见 `docs/branching.md`）。
