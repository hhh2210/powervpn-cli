# 旧方案：驱动官方 helper（vendor 后端）

在 native 后端出现之前，powervpn 不自带隧道，而是驱动官方 PowerVPN 装好的特权 helper
（`/Library/PrivilegedHelperTools/com.leadsec.charon-xpc`，x86_64，经 Rosetta 运行）按原协议建隧道。
它仍然可用，作为回退：`targets.json` 里不写 `backend`，或写 `"backend": "vendor"`。

## 需要什么

- 已安装官方 PowerVPN，并且用它成功连过一次，这样特权 helper 才会装好。
- 其余配置（`credentials.env`、`targets.json`、`~/.ssh/config`）和 native 后端相同，见 README。

## 和 native 后端的区别

- 官方 helper 是黑盒，powervpn 证明不了它把网络状态收干净了，所以每次断开都要拿整机网络快照做对比。
  对不上就把会话**隔离**，需要 `powervpn recovery` 实测恢复后才允许重连。
- 官方 helper 在长会话里会崩溃（大约 20–80 分钟一次，`child_updown` 时 SIGILL），`run` 会自动重连。
- 它依赖官方的日志文件 `/var/log/vsgvpn.log`，权限必须是 root `0600`。

## 出问题时

- 先跑 `powervpn doctor`，它会指出第一个要修的问题。
- `next:` 提示 `powervpn recovery …`：上次断开时没能确认路由已恢复，会话被隔离了。
  先跑 `powervpn recovery inspect --json`，再跑 `powervpn recovery clear --json`，
  后者只在实测网络状态干净时才会解除隔离。
- `next:` 提示 `powervpn repair vendor-log --json`：官方日志文件丢了，或者权限不对。
  这条命令会弹一次 macOS 管理员授权，确认后修复。

隔离、冷基线和 recovery 的设计记录在 `docs/design/` 和 `docs/progress/` 里。
