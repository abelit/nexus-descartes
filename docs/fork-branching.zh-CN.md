# Fork 分支维护说明

> 本文记录 `abelit/nexus-descartes` 相对上游 `t8y2/dbx` 的分支模型与上游同步流程。  
> 最后更新：2026-11-12

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
| `upstream-main` | **纯上游镜像**，只读，只由 `git fetch upstream` 更新 | `upstream/main` |
| `enterprise-dev` | **二开开发/集成分支**：开发、合并上游、推送都在这里进行 | `origin/enterprise-dev` |
| `main` | **二开集成/发布分支**（主目录）：只从 `enterprise-dev` 快进或合并，不直接合并上游 | `origin/main` |
| `fork-base` | **分叉点锚点**，只读，用于 diff/溯源 | 无 |
| `backup/main-before-mirror` | 旧镜像方案的备份（含 4 个 Playwright 产物提交），确认无用后可删除 | 无 |

上游流向：

```
upstream (t8y2/dbx)
    │ fetch
    ▼
upstream-main（只读镜像）
    │ merge
    ▼
enterprise-dev（worktree，开发/集成）
    │ merge --ff-only
    ▼
main（主目录，发布/集成快照）
```

## 4. `enterprise-dev` 分支说明

- **用途**：企业治理方向的二开（服务端审计、RBAC、资产级授权、高风险规则、审批中心、DMS 式执行等）。
- **基点**：`fork-base`（`e6b1a478b`）。
- **上游合并**：2026-11-12 已合并 `upstream/main`（最新 `29c48300e`，113 个上游提交），merge commit `9a62c5ff9`；此前一次为 `ecdeb8b60` → `b04842140`，更早为 `dc41ee213` → `6bb196c1f`。
- **worktree 路径**：`.claude/worktrees/feat+enterprise-audit-p0`（目录名沿用旧名，分支名是 `enterprise-dev`）。
- **推送状态**：与 `origin/enterprise-dev` 同步。

## 5. 日常开发与同步上游

```bash
# 1. worktree：更新上游镜像并合并到开发分支
cd /home/abelit/Documents/code/github/nexus-descartes/.claude/worktrees/feat+enterprise-audit-p0
git fetch upstream
git branch -f upstream-main upstream/main
git merge upstream-main

# 2. 验证
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
cargo check -p dbx
pnpm install --frozen-lockfile && pnpm typecheck
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance
cargo test -p dbx-web --features enterprise-audit --bin dbx-web route_permissions

# 3. 推送开发分支
git push origin enterprise-dev

# 4. 主目录：main 快进到开发分支并推送
cd /home/abelit/Documents/code/github/nexus-descartes
git merge --ff-only enterprise-dev
git push origin main
```

### 为什么不 rebase

上游更新频繁。rebase 会反复重写二开提交，导致同样的冲突被重复解决；`merge` 只在合并点解决一次，并保留完整历史。

### 方向不能反

上游只在 `enterprise-dev` 上合并；`main` 不直接合并上游，只从 `enterprise-dev` 快进或合并。不要向 `t8y2/dbx` 推送，也不要把二开合进 `upstream/main`。

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

### 第二次合并记录（2026-11-12）

合并 `upstream/main`（`29c48300e`，113 个上游提交）时产生 **2 个冲突**，均为“两边都保留”：

| 文件 | 处理 |
|---|---|
| `apps/desktop/src/composables/useSqlExecution.ts` | 保留本地 `approvalRequiredDetail` + 上游新增 `resultExecutionTimeMs` |
| `crates/dbx-core/src/persistence/storage.rs` | `Storage` 同时保留本地 `audit_db` 与上游 `desktop_credential_recovery` / `credential_reset_confirmation` |

另修复一处合并前已存在的桌面端编译错误：`src-tauri/src/commands/ai.rs` 的 `AgentLoopContext` 初始化补上 `governance_tools: None`（桌面端没有 Web 治理工具）。

验证：`cargo check -p dbx-core --features enterprise-audit`、`cargo check -p dbx-web --features enterprise-audit --bin dbx-web`、`cargo check -p dbx`、`pnpm typecheck`、`cargo test -p dbx-core --features enterprise-audit --lib governance`（44 通过）、`cargo test -p dbx-web --features enterprise-audit --bin dbx-web route_permissions`（11 通过）、`node scripts/check-governed-sql.mjs` 全部通过。

## 7. 注意事项

- `upstream-main` 只做上游镜像，不要在上面提交；`main` 只从 `enterprise-dev` 更新，不直接合并上游。
- `main` 默认用 `git merge --ff-only enterprise-dev`；如果 `main` 上出现独立提交，快进会失败，应先决定是合并还是丢弃这些提交。
- `.playwright-mcp/` 已加入 `.gitignore`。
- 上游可能修改函数签名或依赖版本，合并后必须编译并通过测试。
- `fork-base`、`upstream-main` 只作参考，不应作为提交目标。
- 预提交钩子可能在 `PolicyEditor.vue` 的示例 JSON（`<approval-template-id>`）上误报 oxfmt 解析错误，需要时先修复该转义。

## 8. 操作记录

- **2026-11-05**：配置 `upstream` 远端；建立 `fork-base`、`upstream-main`、`backup/main-before-mirror`；将 `worktree-feat+enterprise-audit-p0` 重命名为 `enterprise-dev`。
- **2026-11-05**：WIP 提交 `961fa6305`；合并 `upstream/main`（`dc41ee213`）为 `6bb196c1f`；解决 11 个冲突并通过编译与类型检查。
- **2026-11-05**：`main` 重置为 `upstream/main` 并 force-push；本说明与 `.playwright-mcp/` 忽略规则提交到 `enterprise-dev`。
- **2026-11-05**：切换为 `upstream-main → enterprise-dev → main` 模型；合并最新 `upstream/main`（`ecdeb8b60`）无冲突，merge commit `b04842140`；`main` 快进到 `enterprise-dev`。
- **2026-11-12**：合并 `upstream/main`（`29c48300e`，113 个上游提交）为 `9a62c5ff9`；解决 2 个冲突并补齐桌面端 `governance_tools` 字段；编译、类型检查、治理与路由权限测试、governed-SQL 守卫全部通过。
