# CI

状态：push / PR / 每周全量 + 每晚 catalog-replay 顺序矩阵，全部离线。

CI 覆盖四件事：构建与全量测试、格式、密钥扫描、release 构建；外加一个
验证 catalog 拒绝后客户端缓解契约的确定性回放（catalog-replay）。
所有产品构建与测试都只跑离线产品路径：CI 永不联系真实 Portal、
永不触碰本机特权 helper、永不执行任何 live 动作，workflow 里没有
任何凭据或内网目标值。workflow bootstrap 仍会访问 GitHub 以 checkout/cache
源码与下载已固定版本并校验 checksum 的 gitleaks；这些不是产品网络路径。

## 结构

| workflow | 触发 | 内容 |
|---|---|---|
| `ci.yml` | push（main / rescue-mvp）、PR 到 main、每周一 09:00 UTC | 四个 job：双工具链 build-and-test、format、secrets、release-build |
| `catalog-replay.yml` | 每次 push（快）+ 每晚 03:17 UTC 顺序矩阵 | catalog 回放套件（`swift test --filter CatalogReplay`） |
| `tap-sync.yml` | 推稳定 `vX.Y.Z` tag，或手动指定已存在版本 | 解析并证明 exact tag commit，复用完整 CI；仅全绿后打印 tap 手动发版清单 |

构建矩阵同时钉住两个环境：`macos-14` + Xcode 16.2 是 README 宣称的
最低支持源码安装环境；`xcode-27`（macOS 26 + Xcode 27，Swift 6.4）
是当前开发工具链。`PortalRequestCancellation` 的成员/局部变量遮蔽已在
源码修复，不能再用只跑新工具链的绿色结果替代最低支持证明。

- **build-and-test**（minimum Xcode 16.2 + current Xcode 27）：两条 leg 都先
  `swift build --product powervpn -c debug`，再用 `swift test` 跑全部套件；
  `.build` cache 按 source SHA、toolchain、runner OS/arch 与 package
  manifest 精确隔离，只允许同一提交重跑复用。
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

## catalog-replay：把客户端缓解契约变成确定性回归

live 证据必须分期读取，不能合并成一个“服务端间歇率”：2026-08-12
事件发生在早期 client predicate/mapper 兼容问题尚未修复时，属于已知
客户端根因；2026-08-15 与 08-16 的两个 coarse
`resource_catalog_rejected` outcome 发生在相关修复之后，触发原因仍未
解释。现有档案不足以给服务端 degradation 估计频率，也没有任何 live
事件保存具体 XML shape 或更细的失败分类（schema-8 当时没有该字段，
proxy 模式当时未保留它）。证据源是 scratch 时间线档案
（`~/scratch-data/powervpn-catalog-investigation-2026-08-16/` 的 timeline /
failure-hunter / session-oracle）；fresh-login-per-run 与官方客户端一次登录
+ 60s check/session 保活不一致仍只是假设。客户端已有两层缓解：单次
fresh-login 重试与 value-free 判别 token（`selectionFailureClass` /
`resourceCatalogFailure`）。

CI 不能复现这个 bug 本身——它需要真实 Portal 的服务端状态。回放套件
做的是次优但可证的事：把每个 synthetic 分类形态离线喂进真实采集管线，
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

每个形态把事件与 shape 来源拆成两个机器可读维度，避免把 coarse live
outcome 错写成具体 XML 已被观察：

- `eventProvenance=observed_outcome` 仅表示存在一条实际记录的 coarse
  outcome：timeline row 31（proxy-ssh-4-ide）或 row 21（attempt-7）；
  `no_observed_event` 表示没有对应 live 事件；
- `shapeProvenance=synthetic_best_fit` 表示与上述 outcome 关联的 best-fit
  替身（`catalog_empty` / `resource_list_missing`），并不表示这个 shape
  在 live 被捕获；`synthetic_related` 是 failure-hunter 同组的 synthetic
  hypothesis（`integration_info_missing`），没有对应 live 事件；
  `synthetic_taxonomy` 从分类代码枚举。

实现上是 `Tests/PowerVPNProductTests/CatalogReplay*.swift` 七个文件
（fixtures + 共享 harness + retry / non-catalog / budget / order /
coverage 五组套件），复用该 target 既有的注入层
（`productM2TestDependencies` / `authenticatedSnapshot` /
`testAuthorizationLease`），不另造平行基建。push 时跑全量回放
（秒级）；每晚矩阵用本地固定算法的 deterministic seeded shuffle
（`CATALOG_REPLAY_PERMUTATIONS` 种子 0–10）跑顺序不变性。测试同时
钉住 11 个顺序互异，且每个 shape 至少覆盖 5 个不同前驱与后继，避免
rotation 保留相邻关系而形成的覆盖假象。

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
