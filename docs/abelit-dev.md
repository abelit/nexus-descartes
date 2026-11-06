下面是这次启动服务的实际过程与可复现步骤。

## 环境路径

- 代码 worktree：`/home/abelit/Documents/code/github/nexus-descartes/.claude/worktrees/feat+enterprise-audit-p0`
- 服务端二进制：`target/debug/dbx-web`
- 前端静态文件：`dist/`

## 1. 确认现状

```bash
docker ps -a
docker images 'dbx-acceptance'
docker volume ls | grep -i dbx
```

当时的情况：

- DBX 镜像和容器已被清理掉；
- 数据卷 `dbx-acceptance_dbx-acceptance-data` 仍存在；
- 原 `dbx-acceptance-postgres` / `dbx-acceptance-mysql` 容器不存在；
- 4224 端口无服务响应。

## 2. 重建 Docker 网络和卷

```bash
docker network create dbx-acceptance-net
docker volume create dbx-acceptance-pgdata
docker volume create dbx-acceptance-mysqldata
docker volume create dbx-acceptance-backups
```

## 3. 启动 Demo PostgreSQL

```bash
docker run -d \
  --name dbx-acceptance-postgres \
  --network dbx-acceptance-net \
  --network-alias demo-postgres \
  -e POSTGRES_DB=app \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=dbx \
  -v dbx-acceptance-pgdata:/var/lib/postgresql/data \
  postgres:16
```

## 4. 启动 Demo MySQL

```bash
docker run -d \
  --name dbx-acceptance-mysql \
  --network dbx-acceptance-net \
  --network-alias demo-mysql \
  -e MYSQL_ROOT_PASSWORD=dbx \
  -e MYSQL_DATABASE=app \
  -e MYSQL_USER=dbx \
  -e MYSQL_PASSWORD=dbx \
  -v dbx-acceptance-mysqldata:/var/lib/mysql \
  mysql:8.4.11
```

这两个容器使用 `--network-alias`，因此原有连接配置中的主机名 `demo-postgres` / `demo-mysql` 仍然可解析。

## 5. 构建可运行的 Web 镜像

原 `deploy-dbx:latest` 镜像的 glibc 版本较旧，无法运行当前 worktree 的调试二进制（需要 glibc 2.44），因此使用 Arch 基础镜像重新构建运行时镜像。

```bash
# 安装运行依赖
docker run -d --name dbx-build-tmp archlinux:base \
  bash -lc 'pacman -Sy --noconfirm fontconfig freetype2 libpng brotli &&
            mkdir -p /app/data /app/backups /app/static'

# 等待安装完成后复制二进制和静态文件
docker cp target/debug/dbx-web dbx-build-tmp:/usr/local/bin/dbx-web
docker exec dbx-build-tmp chmod +x /usr/local/bin/dbx-web
docker cp dist/. dbx-build-tmp:/app/static/

# 提交镜像
docker commit \
  --change 'ENTRYPOINT ["dbx-web"]' \
  --change 'CMD []' \
  --change 'WORKDIR /app' \
  dbx-build-tmp dbx-acceptance:session-refresh-arch-20261106

docker tag dbx-acceptance:session-refresh-arch-20261106 dbx-acceptance:local
docker tag dbx-acceptance:session-refresh-arch-20261106 dbx-acceptance:local-next25
docker rm -f dbx-build-tmp
```

> 实际过程中曾先使用 `--entrypoint sleep` 的临时容器复制文件，提交后继承成了错误的 sleep entrypoint；随后通过重新提交修正为 `ENTRYPOINT ["dbx-web"]`。

## 6. 启动 DBX Web 容器

```bash
docker run -d \
  --name dbx-acceptance-web \
  --network dbx-acceptance-net \
  -p 4224:4224 \
  --restart unless-stopped \
  --entrypoint /usr/local/bin/dbx-web \
  -v dbx-acceptance_dbx-acceptance-data:/app/data \
  -v dbx-acceptance-backups:/app/backups \
  -e DBX_DATA_DIR=/app/data \
  -e DBX_STATIC_DIR=/app/static \
  -e DBX_BACKUP_ROOT=/app/backups \
  -e DBX_PASSWORD=dbx-admin-pass \
  -e DBX_GOVERNANCE_MODE=enforce \
  -e DBX_AUDIT_MODE=on \
  -e DBX_AUDIT_SQL_MODE=full \
  dbx-acceptance:session-refresh-arch-20261106
```

当前运行容器因历史镜像 entrypoint 问题带上了 `--entrypoint /usr/local/bin/dbx-web`；最终镜像已经修正 entrypoint，后续重新创建容器时理论上可以省略该参数。

## 7. 健康检查

```bash
curl -I http://127.0.0.1:4224/
docker ps | grep dbx-acceptance
docker logs --tail 20 dbx-acceptance-web
```

验证结果：

- `http://127.0.0.1:4224/` 返回 200；
- `dbx-acceptance-web`、`dbx-acceptance-postgres`、`dbx-acceptance-mysql` 均 Up；
- Web 端口 `0.0.0.0:4224->4224/tcp`；
- 重启策略 `unless-stopped`。

## 8. 登录与连接验证

```bash
curl -c /tmp/a.jar \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin","password":"dbx-admin-pass"}' \
  http://127.0.0.1:4224/api/auth/login

curl -b /tmp/a.jar http://127.0.0.1:4224/api/connection/list
```

随后分别执行：

- PostgreSQL：`SELECT 1`
- MySQL：`SELECT 1`

均正常返回。

## 9. 数据说明

- DBX 自身数据卷 `dbx-acceptance_dbx-acceptance-data` 被保留，因此管理员、用户、角色、策略、审批、审计等数据仍在。
- Demo PostgreSQL/MySQL 使用新建卷，连接正常，但之前手工保留的 `qa2_*` 演示表/函数数据没有恢复。
- 当前镜像标签：
  - `dbx-acceptance:session-refresh-arch-20261106`
  - `dbx-acceptance:local`
  - `dbx-acceptance:local-next25`