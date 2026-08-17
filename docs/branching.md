# 分支策略

`rescue-mvp` 是活跃开发线，日常提交与 `push` 都走这里。
`main` 是稳定发布线，只在发布时推进，不跟随开发 tip。

推进 `main` 的唯一依据是已打好的 release tag。发布后把本地指针挪到
tag 目标再推送，不要把 `main` fast-forward 到 `rescue-mvp` 的开发 tip：

```sh
git branch -f main <tag-target>
git push origin main
```

例：`v0.1.0` 指向 `3a56b28`（README daily-ssh 修正）。brew tap 的 tarball
SHA 与该 commit 一致，因此 `3a56b28` 是合法发布内容。

hotfix：在当前 release commit 上 cherry-pick，打新 tag，再按上面的步骤
把 `main` 同步到新 tag 目标。不要在 `rescue-mvp` 上直接推进 `main`。

当前 `main == v0.1.0 == rescue-mvp` tip 属打包期巧合，后续分叉。
