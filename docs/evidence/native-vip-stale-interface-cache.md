# native：长时间运行后 Quick Mode 前的虚拟 IP 准备失败

状态（2026-11-13 晚）：**根因已确认并修复**。是候选一：内核把已销毁 utun 的 ifindex 重新分给另一个名字的
utun，而 charon 的 kernel-pfroute 在 macOS 上从不删除离开的接口，继续用旧名字。修复是 strongSwan 补丁
`patches/strongswan-6.0.7/0005-kernel-pfroute-follow-reused-interface-indexes.patch`，证据见文末
“根因确认与修复”。下面保留当时的分析过程。

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

## 候选机制一：接口缓存只增不减，ifindex 与 utun 名字漂移

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

第 1、2 点已核实：离开的接口从不清除，名字与 ifindex 不是一起分配的。第 3 点是推断，需要 root 才能复现，
而且有反证：上面的空洞没有被后来的 `utun0`（#37）填上，说明内核至少不会把空闲 ifindex 随便分给新接口；
第 3 点只有在内核回收旧 ifnet（连同它原来的 ifindex）给另一个单元号的 utun 时才成立，这一点没有核实。

## 候选机制二：PF_ROUTE 事件丢失

睡眠唤醒和网络切换时路由消息成批出现，PF_ROUTE socket 接收缓冲溢出时 `receive_events()` 记
`unable to receive from PF_ROUTE event socket` 并睡 1 s，丢掉的事件不会补发，也没有任何重新同步；
缓存从此与内核不一致，直到 charon 重启重新 `getifaddrs()`。它能解释“重启即好”，但单靠它不容易解释
每次新建的 utun 都失败，除非失步落在会被反复用到的条目上。

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

在 `powervpn native log 200` 里找同一次尝试的 KNL 行，比的是接口名。正常连接在
`installing new virtual IP <VIP>` 之后只有一行 `interface utunM appeared`（helper 随后记
`route add <host> -> utunM`），并没有 `<VIP> appeared on utunM` 这一行：2026-11-13 的两次成功连接
都是如此，所以不要拿那一行当判据。若失败那次 `virtual IP <VIP> did not appear on utunN` 里的 utunN
与同一次尝试的 `interface utunM appeared` 里的 utunM 不同，或者根本没有对应的 `interface … appeared`
（缓存里已有这个 ifindex 时，charon 记的是 `interface utunM activated`，名字是旧的），
即支持候选一；若看到 `unable to receive from PF_ROUTE event socket`，则支持候选二。

## 复现记录（2026-11-13 18:52–18:55 CST）

charon 连续运行约 2 小时 52 分（07:59:46Z 启动）后，同一故障复现，证据支持候选一：

- 至少 5 次连续尝试（10:53:04Z–10:55:37Z）都是同一组日志：`installing new virtual IP <VIP>` 之后是
  `<VIP> appeared on utun11` 和 `interface utun11 activated`（地址确实到了，但记在旧名字下），约 1 秒后 `virtual IP <VIP> did not appear on utun6`，随后
  `interface utun11 deactivated`。charon 新建的 TUN 叫 utun6，而它缓存里同一 ifindex 的名字还是 utun11
  （上一个会话在 08:00:41Z 用的正是 utun11），所以地址事件记到了旧名字下，等 utun6 的那一方超时。
  期间没有 `unable to receive from PF_ROUTE event socket`。
- 自愈按设计生效：10:55:38Z helper 记 `restart-charon granted (owner request; charon idle)`，
  重启后的下一次尝试是 `interface utun6 appeared`、`route add <host> -> utun6`，连接建立。
  重启前后 TUN 名字同为 utun6，区别只在 charon 的缓存是否为空。
- 前 4 次由 Homebrew 0.2.2 的旧 CLI 发起：它不认识这个故障，报的是“the gateway did not install the
  tunnel for this resource”，也不会请求 `restart-charon`，所以一直失败（`session_start_failed`，75）。
  同一时刻换成本分支的 CLI 就自动恢复了，整次 `run` 用时 8.9 秒。

## 根因确认与修复（2026-11-13 19:42–19:44 CST）

### 复现工具

`scripts/native/utun_index_reuse_probe.c`（需 root，不建任何 VPN 连接）按 charon 配置自己 TUN 的方式
（`IFF_UP|IFF_RUNNING`、MTU 1400、一个 TEST-NET-1 的 /32 地址）先后建两个 utun，各存活约 1 秒，并打印内核
为这个 ifindex 发出的路由消息。第一个要高单元号（utun100），第二个取最小空闲单元号，和 charon 一样。
`prime` 只建第一个。

### 证据

1. **内核确实换名重用 ifindex**：三次运行都是 `reused: index 50 was utun100 and became utun6`。
   每个设备收到的消息相同：`RTM_NEWADDR`、`RTM_ADD`、`RTM_IFINFO flags 0x8051`（up），关闭时
   `RTM_DELETE`、`RTM_DELADDR`、`RTM_IFINFO flags 0x8050`（down），全部只带序号 50，不带名字。
2. **旧 charon 用错名字**：安装前对运行中的未打补丁 charon 跑探针，第一个设备明明叫 utun100，charon
   记的却是 `<addr> appeared on utun6`、`interface utun6 activated`：它缓存里序号 50 还挂着之前会话的
   utun6，于是把 utun100 的事件全记到 utun6 名下。这就是线上故障的同一机制，只是名字对调。
3. **打补丁的 charon 名字正确，并删除离开的接口**：安装后同样的探针，charon 记
   `interface utun100 appeared`，关闭时 `interface utun100 disappeared`；第二个设备是全新的
   `interface utun6 appeared`、`interface utun6 disappeared`。缓存里不再留下陈旧条目。
4. **端到端**：`prime` 让 utun100 用掉序号 50 后，立即发起真实连接。会话的 TUN 是 `utun6`，序号正是 50
   （`netstat -in`：`utun6 <Link#50>`），也就是旧 charon 必然失败的情形。打补丁的 charon 首次尝试即建立
   （attempt a1154e34：ike 137 ms、child 177 ms，`interface utun6 appeared`、`route add … -> utun6`），
   整次 `run` 1.65 秒，没有 `native_local_vip_failed`，没有 `restart-charon`。

### 补丁做了什么（只改 `kernel_pfroute_net.c`）

- 收到某序号的 `RTM_IFINFO` 且接口已关闭、`if_indextoname()` 已解析不到时，删除该条目
  （macOS 没有 `RTM_IFANNOUNCE`，原来没有任何删除路径）。证据 3、4 走的就是这一条。
- 序号仍在但已属于另一个名字时，按新名字重建条目，记 `interface X disappeared, index N is now Y`；
  `RTM_NEWADDR` 先于 `RTM_IFINFO` 到达时同样处理。顺带清除声称同一名字的其他陈旧条目。
- `add_ip()` 等地址超时前，再按 TUN 名字直接核对一次（`virtual IP … found on … after resynchronizing`），
  防止丢事件时误判失败。

后两条是后备：只有离开消息被错过（例如 PF_ROUTE 缓冲溢出，候选二）时才会走到，这次验证没有触发，
**未经实测**。CLI 的 `restart-charon` 自愈保留，作为最后一道兜底。

### 部署

新运行时由 `scripts/native/build_runtime.sh` 构建（补丁序列现为 0001–0005），以 runtime archive 方式安装
（`installed-from` 的 `runtime-archive 215e1572…`）。Homebrew 0.2.2 的 keg 不含这个补丁，因此
`powervpn doctor` 会继续提示“installed copy differs”；在发布含 0005 的版本之前，**不要**执行它建议的
`sudo powervpn native install`，那会装回旧运行时。回滚：用 keg 的 `runtime.tar` 重新安装
（`POWERVPN_NATIVE_RUNTIME_ARCHIVE=…/libexec/powervpn-native/runtime.tar sudo scripts/native/install.sh`）。
