# CI

状态：push / PR / 每周全量 + 每晚 catalog-replay 顺序矩阵，全部离线。

CI 覆盖四件事：构建与全量测试、格式、密钥扫描、release 构建；外加一个
专门针对 Portal catalog 间歇拒绝的确定性回放（catalog-replay）。
所有 job 都只跑离线路径——CI 永不联系真实 Portal、永不触碰本机
特权 helper、永不执行任何 live 动作，workflow 里没有任何凭据或
内网目标值。

## 结构

| workflow | 触发 | 内容 |
|---|---|---|
| `ci.yml` | push（main / rescue-mvp）、PR 到 main、每周一 09:00 UTC | 四个 job：build-and-test、format、secrets、release-build |
| `catalog-replay.yml` | 每次 push（快）+ 每晚 03:17 UTC 顺序矩阵 | catalog 回放套件（`swift test --filter CatalogReplay`） |
| `tap-sync.yml` | 推 `v*` tag | 打印 tap 手动发版清单（不自动改 tap） |

Runner 用 `xcode-27`（macOS 26 + Xcode 27，Swift 6.4）：源码即在此
工具链下开发；macos-14 最高只有 Xcode 16.2（Swift 6.0.x），会在
`PortalRequestCancellation.swift:20` 处编译失败（成员名被同名局部
绑定遮蔽）。降级 runner 需要先改产品源码，不建议。

- **build-and-test**（xcode-27 arm64）：`swift build --product powervpn
  -c debug` 后 `swift test` 跑全部套件；`.build` 用 actions/cache 缓存。
- **format**：`xcrun swift-format lint --strict --recursive Sources Tests`，
  与仓库 checkpoint 脚本同一条命令，无豁免文件。
- **secrets**（ubuntu）：先跑 `scripts/verify_no_secrets.sh` 的禁路径
  检查，再由它调用固定版本（8.30.1，tarball 经 checksums 校验）的
  gitleaks 做 `dir` 扫描。CI 上不装 Homebrew、不飘版本。
- **release-build**：`swift build --product powervpn --arch arm64 -c
  release`，确认 Mach-O arm64 后把 sha256 写进 job summary（不作为
  artifact 上传）。brew tap 发版仍以 tag tarball 的 sha256 为准
  （见 tap 仓库 `scripts/release.sh`），这里的二进制 SHA 只用于
  追溯对应 commit 的产物。

## catalog-replay：把间歇拒绝变成确定性回归

背景（假设，未定论）：live 时间线记录了三次 catalog 拒绝
（2026-08-12 / 08-15 / 08-16），样本频率约 1/8（3 次拒绝 / 22 次登录，
样本极小）——**这是待验证假设的一部分，不是结论**；唯一证据源是
scratch 时间线档案（`~/scratch-data/powervpn-catalog-investigation-2026-08-16/`
的 timeline / failure-hunter / session-oracle 三份）。rank-1 假设是
我们的 fresh-login-per-run 会话形态与官方客户端的一次登录 + 60s
check/session 保活不一致；**没有任何 live 拒绝记录过更细的失败
分类**（schema-8 时代没有该字段，proxy 模式当时丢弃了它）。客户端
已有两层缓解：单次 fresh-login 重试与 value-free 失败判别 token
（`selectionFailureClass` / `resourceCatalogFailure`）。

CI 不能复现这个 bug 本身——它需要真实 Portal 的服务端状态。回放套件
做的是次优但可证的事：把每一种拒绝形态离线喂进真实采集管线，
断言缓解逻辑本身不退化：

- 每个形态都走真实路径：synthetic XML → 快照铸造 → `selectUnique`
  → 类型化分类 → 恰好一次 fresh-login 重试 → 首会话先 logout 再
  重登（事件序 `login_1, logout_1, login_2, logout_2`）；
- `automaticRetryCount` 如实（成功=1、耗尽=1、未重试=0）；
- 非 catalog 类（resourceNotFound / selectionReplay / prepareRemap）
  绝不重试；
- 预算不足时跳过重试并保留首次分类；
- 重试后仍拒绝的报告携带完整判别 token 且 value-free；
- 形态覆盖钉住整个服务端可达分类学（`catalog_empty`、scope 级
  `integration_info_missing` / `resource_list_missing` / 四个
  `major_version_*`、resource 级 `integer_invalid` /
  `display_name_missing` / `display_name_invalid` / `duplicate_field`；
  `resource_list_duplicate` 在铸造阶段即被拒——测试也钉住了这一点，
  scope `unclassified` 只能由未知 throw 到达，没有任何 XML 字节能
  产生它）。

每个形态带机器可读的来源标签（`CatalogReplayProvenance`）：

- `observed_live`：对应一次实际记录的 live 拒绝事件的档案指定
  best-fit 替身——`catalog_empty`（timeline row 31，proxy-ssh-4-ide）
  与 `resource_list_missing`（timeline row 21，attempt-7）；两次的
  细分类都未被记录，标签因此明确写为"best-fit stand-in"；
- `derived_from_observed`：与观测事件同族的退化形态
  （`integration_info_missing`）；
- `synthetic_taxonomy`：从分类代码枚举、live 从未见过的形态。

实现上是 `Tests/PowerVPNProductTests/CatalogReplay*.swift` 七个文件
（fixtures + 共享 harness + retry / non-catalog / budget / order /
coverage 五组套件），复用该 target 既有的注入层
（`productM2TestDependencies` / `authenticatedSnapshot` /
`testAuthorizationLease`），不另造平行基建。push 时跑全量回放
（秒级）；每晚矩阵用确定性轮转（`CATALOG_REPLAY_PERMUTATIONS`
种子 0–10，每个种子对应形态矩阵的一个确定顺序，无随机源）跑
顺序不变性，防止状态机里出现跨采集的隐藏状态。

## live 证据协议

CI 永远不触真实 Portal——凭据不进 workflow、runner 上也没有任何
内网目标值（targets.json 属于本机 `~/.config/powervpn/`，仓库里只有
闭合 schema 示例 `docs/targets.example.json`）。live 验证（M2
connect-once、proxy ssh / IDE）在本机按既有纪律人工执行，一次批准
一次 attempt。

live 事件的记录协议保持不变：value-free JSON / 判别 token 落到
scratch 档案目录（格式同 2026-08-16 的 catalog 调查与 attempt
历史档案：时间线表 + 每行一个 canonical 产物 + 明确 ABSENT 标注），
不做任何 CI 自动上报。若 catalog 拒绝复发，stderr 判别 token
（`:selection=…:catalog=…`）会直接给出分类；同一分类若能离线重放，
先修离线回放使其复现，再动产品谓词。
