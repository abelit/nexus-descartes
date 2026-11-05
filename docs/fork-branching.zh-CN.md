# Fork 分支维护说明

> 本文记录 `abelit/nexus-descartes` 相对上游 `t8y2/dbx` 的分支模型与上游同步流程。  
> 最后更新：2026-11-05

## 1. 仓库关系

| 远端 | 地址 | 角色 |
|---|---|---|
| `origin` | `git@github.com:abelit/nexus-descartes.git` | 本 fork |
| `upstream` | `git@github.com:t8y2/dbx.git` | 上游原项目 |

## 2. 分叉点

| 项 | 值 |
|---|---|
| commit | `e6b1a478b` |
| 时间 | 2026-11-01 16:44:46 +0800 |
| 上游 tag | `v0.6.63-beta.20261101.3` |
| 说明 | 完整保留了上游历史，`fork-base` 就是双方唯一的 merge-base |

## 3. 分支一览

| 分支 | 用途 | 跟踪 |
|---|---|---|
| `main` | **纯净的上游镜像**。2026-11-05 已重置到 `upstream/main` 并 force-push；不要在上面提交 | `origin/main` |
| `fork-base` | **分叉点锚点**，只读，用于 diff/溯源 | 无 |
| `upstream-main` | **上游镜像的本地分支**，便于在 IDE 中查看/对比上游代码 | `upstream/main` |
| `enterprise-dev` | **二开主线**：开发、合并上游、推送都在这里进行 | `origin/enterprise-dev` |
| `backup/main-before-mirror` | `main` 重置前的备份（含 4 个 Playwright 产物提交），确认无用后可删除 | 无 |

## 4. `enterprise-dev` 分支说明

- **用途**：企业治理方向的二开（服务端审计、RBAC、资产级授权、高风险规则、审批中心、DMS 式执行等）。
- **基点**：`fork-base`（`e6b1a478b`）。
- **上游合并**：2026-11-05 已合并 `upstream/main`（`dc41ee213`，v0.6.66），merge commit `6bb196c1f`。
- **worktree 路径**：`.claude/worktrees/feat+enterprise-audit-p0`（目录名沿用旧名，分支名是 `enterprise-dev`）。
- **推送状态**：与 `origin/enterprise-dev` 同步。

## 5. 日常开发与同步上游

```bash
cd /home/abelit/Documents/code/github/nexus-descartes/.claude/worktrees/feat+enterprise-audit-p0

# 1. 取回上游最新提交与标签
git fetch upstream

# 2. 合并上游（在 enterprise-dev 上执行）
git merge upstream/main

# 3. 验证
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
cargo check -p dbx
pnpm install --frozen-lockfile && pnpm typecheck
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance

# 4. 推送
git push origin enterprise-dev
```

### 为什么不 rebase

上游更新频繁。rebase 会反复重写二开提交，导致同样的冲突被重复解决；`merge` 只在合并点解决一次，并保留完整历史。

### 方向不能反

始终在 `enterprise-dev` 上执行 `git merge upstream/main`（把上游拉进来）。不要合并到 `upstream/main`，也不要向 `t8y2/dbx` 推送。

## 6. 首次合并记录（2026-11-05）

合并 `upstream/main`（`dc41ee213`）时产生 **11 个冲突**，已全部解决：

| 文件 | 处理 |
|---|---|
| `crates/dbx-core/src/query/mod.rs` | 保留本地 `audit` + 上游 `report_compilation_errors` |
| `crates/dbx-web/src/routes/query.rs` | 保留 `audit` / `approval_token` / `policy_approved` + 上游新字段 |
| `src-tauri/src/commands/query.rs` | 保留桌面审计上下文 + 上游新字段 |
| `crates/dbx-web/src/auth.rs` | 本地多用户登录/审计/逐账号限流 + 上游图片验证码 |
| `crates/dbx-web/src/state.rs`、`main.rs`、`routes/mq.rs` | 保留本地 `LoginRateLimit` + 上游 captcha 状态 |
| `LoginPage.vue`、`settingsSearch.ts` | 邮箱登录 + 验证码 UI/设置项 |
| `EditorSettingsDialog.vue` | 上游搜索激活逻辑 + 本地治理 tab 过滤 |
| `AppToolbar.vue` | 同时保留 `FolderOpen` 与 `ShieldCheck` |

另外补上了 `/access-requests` 和 `/my-tasks` 的路由权限分类，修复了 WIP 遗留的覆盖测试失败。

## 7. 注意事项

- `main` 只做上游镜像，不要在上面提交；同步上游用 fast-forward：
  ```bash
  git fetch upstream
  git push origin upstream/main:main
  ```
- `.playwright-mcp/` 已加入 `.gitignore`。
- 上游可能修改函数签名或依赖版本，合并后必须编译并通过测试。
- `fork-base`、`upstream-main` 只作参考，不应作为提交目标。
- 预提交钩子可能在 `PolicyEditor.vue` 的示例 JSON（`<approval-template-id>`）上误报 oxfmt 解析错误，需要时先修复该转义。

## 8. 操作记录

- **2026-11-05**：配置 `upstream` 远端；建立 `fork-base`、`upstream-main`、`backup/main-before-mirror`；将 `worktree-feat+enterprise-audit-p0` 重命名为 `enterprise-dev`。
- **2026-11-05**：WIP 提交 `961fa6305`；合并 `upstream/main`（`dc41ee213`）为 `6bb196c1f`；解决 11 个冲突并通过编译与类型检查。
- **2026-11-05**：`main` 重置为 `upstream/main` 并 force-push；本说明与 `.playwright-mcp/` 忽略规则提交到 `enterprise-dev`。
