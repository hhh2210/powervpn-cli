# native：长时间运行后 Quick Mode 前的虚拟 IP 准备失败

状态：机制为 **最可能、未直接观测**；已加可观测的自愈与日志，等待下一次复现的 KNL 日志确认。

## 现象（2026-11-12/13）

- 每次 `powervpn run thu21 -- hostname` 都报 `native_child_failed`，CLI 文案是
  “the gateway did not install the tunnel for this resource”。
- IKEv1 Main Mode 每次约 140 ms 成功；第二个 `initiate`（child `selected-resource`）失败。
  没有任何 Quick Mode 包离开本机。
- charon 用 Portal 下发的虚拟 IP 建了 utun，约 1.3 s 后又删掉。
- helper 与 charon 自 2026-11-10 18:57 起连续运行约 2.5 天，期间多次睡眠/唤醒与网络切换。
  `sudo launchctl kickstart -k system/com.hhh2210.powervpn-native` 之后下一次连接立即成功。

结论：故障在长时间运行的 charon 的本地状态里，不在网关。

## 失败路径（源码可证）

`patches/strongswan-6.0.7/0004-*.patch` 的 `prepare_leadsec_vip()`：先查 charon 自己的
接口地址缓存，确认 VIP 不属于别的接口；再 `add_virtual_ip()`；最后再查一次缓存，
查不到就返回 FALSE，Quick Mode 以 `scoped Portal VIP preparation failed`（DBG1 IKE）中止。

`add_virtual_ip()` 走 kernel-pfroute 的 `add_ip()`（`kernel_pfroute_net.c:1260` 起）：建 TUN、
设地址，然后等缓存里出现这个地址，等待窗口是 `vip_wait`（默认 1000 ms，每来一个 PF_ROUTE
事件重新计时）；超时记 `virtual IP %H did not appear on %s`（DBG1 KNL），销毁 TUN，返回 FAILED。
“utun 存活约 1.3 s”与这个超时一致，不是“地址已被占用”那条分支（那条分支不会建 utun）。

## 最可能的机制：接口缓存只增不减，ifindex 与 utun 名字漂移

1. macOS SDK 的 `net/route.h` 没有 `RTM_IFANNOUNCE`，所以 `HAVE_RTM_IFANNOUNCE` 未定义，
   `process_announce()` 被编译掉。已安装的 `libstrongswan-kernel-pfroute.so` 里有
   `interface %s appeared`，没有 `interface %s disappeared`。kernel-pfroute 的接口列表
   只有这一处删除路径（`kernel_pfroute_net.c:972`），因此 charon 运行期间，每个消失的接口
   （每个会话自己的 utun、其他 VPN 在睡眠唤醒时重建的 utun）都永久留在缓存里。
2. 本机 ifindex 与 utun 名字并不固定对应。2026-11-13 的 `netstat -in`：`utun7`=#30、
   `utun5`=#36、`utun0`=#37、`utun11`=#38、`utun6`=#39，中间有 #22/#27/#29/#34/#35 空洞。
   名字取最小空闲单元号，ifindex 另行分配，运行越久两者越错位。
3. `process_link()` 按 ifindex 找到旧条目时保留旧名字（`kernel_pfroute_net.c:872-900`），
   随后 `repopulate_iface()`（`:813`）按 **名字** 用 `getifaddrs()` 重建该条目的地址表。
   一旦某个 ifindex 被重新分配给另一个名字的 utun，新 utun 的 RTM_NEWADDR 会被记到旧名字的
   条目上，而之后任何一条该 ifindex 的 RTM_IFINFO（up、MTU）都会按旧名字重建地址表，
   把刚学到的 VIP 冲掉；`add_ip()` 就等不到地址。charon 重启时 `init_address_list()` 从
   `getifaddrs()` 按真实名字重建缓存，所以 kickstart 立即见效。

第 1、2 点已核实；第 3 点中“ifindex 被另一个名字复用”和“冲掉 VIP 的那条 RTM_IFINFO”是推断，
需要 root 才能复现。备选解释：PF_ROUTE socket 在唤醒时溢出（会记
`unable to receive from PF_ROUTE event socket`），丢失的事件不会补，缓存与内核失步。

## 当时为什么没有日志

旧 `install.sh` 写的 charon filelog 是 `/var/log/powervpn-native-charon.log`：`append = no`
（每次 charon 启动截断，kickstart 恰好抹掉了故障现场），没有 `flush_line`（stdio 全缓冲，
进程被杀时缓冲区内容丢失；2026-11-13 一次成功连接之后该文件仍是 0 字节），并且 `knl` 只到 0 级，
`did not appear on` 本来就不会写。它也不经过脱敏，IKE 身份就是 Portal session id。

## 这次的改动

- charon 只写 stderr（`default = 0, ike = 1, cfg = 1, knl = 1, ike_name = yes, flush_line = yes`），
  helper 逐行脱敏后写入 root-only、按大小轮转的 `/var/log/powervpn-native/native.log`，
  owner 通过控制 socket 的 `log-tail` 读取（`powervpn native log`）。旧 charon 日志在重装时删除。
- VICI `errmsg` 不再丢弃；失败分为 IKE 阶段、本机虚拟 IP 准备（`native_local_vip_failed`）、
  网关拒绝（error notify）与超时，只在有正面证据时命名原因，否则写“原因未识别”，不再归咎网关。
- 自愈：只在 `native_local_vip_failed` 时，CLI 请求 helper `restart-charon`；helper 自己确认
  没有任何路由、IKE SA、连接或共享密钥（无法确认即拒绝），并受 60 s 间隔、30 分钟 3 次的预算限制；
  重启后重试一次。这是自愈，不是根因修复。

## 下一次复现时如何确认

在 `powervpn native log 200` 里找同一次尝试的 KNL 行：若 `<VIP> appeared on utunM` 的名字与
`virtual IP <VIP> did not appear on utunN` 不同，或之前出现 `interface utunN activated` 却没有对应的
`appeared`，即证实第 3 点；若看到 `unable to receive from PF_ROUTE event socket`，则是备选解释。

## 待决定的根因修复

在 kernel-pfroute 上加一个补丁：`process_link()` 找到条目时用 `if_indextoname()` 刷新名字
（名字变了就记一行 KNL 并按新名字重建），解析不到名字就删掉该条目；`add_ip()` 超时前再按 TUN 名字
`getifaddrs()` 核对一次。需要新增 patch、重建 runtime、改安装清单哈希，并且只能在 root 安装后验证，
因此没有放进这个分支。
