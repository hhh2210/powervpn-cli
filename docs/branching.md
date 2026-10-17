# 分支与发布

只保留 `main` 一条长期分支。新功能和修复都在短期分支上开发，通过 PR 合进 `main`，
合并前 CI 要过。

发布看 tag，不看 `main` 的最新提交：在 `main` 上打 `vX.Y.Z`，`tap-sync.yml` 会对这个 tag
跑完整 CI，全绿后打印 Homebrew tap 的发版清单。brew 装的是 tag 对应的源码包，
所以 `main` 往前走不影响已经发布的版本。

2026-10 之前的开发线 `rescue-mvp` 已经合进 `main` 并删除。`v0.1.0` 指向 `3a56b28`，保持不变。
