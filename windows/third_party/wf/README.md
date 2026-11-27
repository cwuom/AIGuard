# wf（AIGuard fork）

源自 [tailscale/wf](https://github.com/tailscale/wf) `v0.0.0-20240214030419-6fbb0a674ee6`（BSD-3-Clause，见 LICENSE、AUTHORS）。

改动：

- 新增 `transaction.go`：公开 `BeginTransaction` / `CommitTransaction` / `AbortTransaction`（原库已声明底层 syscall 但没有对外暴露），以及只枚举指定 provider 规则的 `RulesForProvider`。
- `malloc.go`：超过 4096 字节的申请改为单独分配，原版会直接 panic（几百个 IP 段的条件数组就会超过）。
- 去掉测试、代码生成器和工具依赖文件；`go.mod` 只保留运行时依赖。
