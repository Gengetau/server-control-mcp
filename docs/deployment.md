# 部署与运维

## 目录和权限

使用专门的普通系统用户。三个位置分开：程序目录、执行工作目录、私有状态目录。
`.env` 不放在执行工作目录内；状态目录与其子文件默认 0700/0600。
所有相对路径相对于启动进程的工作目录；systemd 建议使用绝对路径。

| 配置 | 默认/用途 |
|---|---|
| CODING_TOOLS_MCP_SERVER_URL | 必填 HTTPS origin，不带路径 |
| CODING_TOOLS_MCP_OAUTH_PASSWORD | init 生成，至少 32 字符 |
| CODING_TOOLS_MCP_OAUTH_TOKEN_SECRET | init 生成，至少 32 字符 |
| CODING_TOOLS_MCP_OAUTH_TOKEN_TTL | 生成配置为 3600 秒 |
| SCM_STATE_DIR | ./state，持久数据库与网关临时目录 |
| SCM_WORKSPACE | ./workspace，唯一执行工作目录 |
| SCM_BACKEND_PORT / SCM_GATEWAY_PORT | 28766 / 28767，仅 127.0.0.1 |
| SCM_PERMISSION_MODE | safe / trusted / dangerous，默认 safe |
| SCM_EVENTS_ENABLED | 0 / 1，默认 0 |

原始上游 `CODING_TOOLS_MCP_*` 执行策略覆盖项不会继承到执行进程；通过本表设置模式。
为避免密钥继承，网关的 OAuth 配置也不会进入执行进程。

## HTTPS 入口

服务自身不负责签发 TLS 证书。配置可信的反向代理，将 HTTPS 请求原样转发到
`http://127.0.0.1:28767`；保留 Authorization、Content-Type 和 MCP 相关头，
超时至少覆盖最长命令调用，不要记录 OAuth 查询参数、表单或 Bearer token。
不要公开 28766，不要把后端直接作为公开 MCP URL。
为 OAuth 登录及动态注册配置速率限制。

可选 Tailscale Funnel 示例（需要你自己的 Tailscale 环境）：

```bash
sudo tailscale funnel --bg 28767
```

将配置的 origin 设置为实际 HTTPS 域名，重启服务后再登录。不要将个人设备的
Tailscale 身份密钥、域名或授权结果写进仓库。Funnel 命令及客户端接入属于操作示例，
本提取版未执行公网开通验收。

OpenAI Tunnel 等入口也只转发到网关。其镜像、控制面凭据和连接配置取自供应商，
不包含在本仓库。不要假设某种隧道一定会透传 OAuth：需按客户端流程验证。

## systemd

1. 将项目放入 `/opt/server-control-mcp`，在那里建立 `.venv` 并安装。
2. 创建普通系统用户 `mcp`，准备其可写的 `/srv/mcp-workspace`。
3. 用 `init --output` 生成 `/etc/server-control-mcp.env`，设置 origin；文件仅管理员可读。
   systemd 管理器负责读取 EnvironmentFile 并注入进程，无需服务用户读取该文件。
4. 调整 deploy 中模板目录，安装到 `/etc/systemd/system/` 后 daemon-reload、enable --now。
5. 检查本地监听、未登录 401，再配置 HTTPS 入口和客户端。

模板启用 NoNewPrivileges/PrivateTmp；不承诺在所有内核上提供 Landlock。
扩展执行权限前检查 `server_info` 和 `check_exec_environment`。

## Docker（Linux）

在项目目录生成 `.env`，修改 origin，运行 `docker compose up -d --build`。
容器使用 UID 10001，两个命名卷分别保存私有状态与工作目录；不挂宿主机根或 Docker socket。
该示例依赖 Linux host 网络。若改为普通容器网络，需要同时调整内部监听与入口设计，
不能只把当前 127.0.0.1 listener 加上 ports 就认为可以访问。
镜像仅含 Python/Git；按需构建包含业务工具链的派生镜像。

## 更新、备份、撤销与卸载

- 更新：先停服务，备份配置和整个状态目录，再安装新包、重启并执行验收。
- SQLite 备份：停服务后复制状态目录，或使用 SQLite backup API；不能仅复制活跃主库
  忽略 WAL。备份与原数据库一样敏感。
- 普通重启保留客户端注册、授权码及刷新授权；执行端子进程的正在运行命令不保证跨
  服务重启恢复。进程退出会由 supervisor 清理另一个服务进程。
- 修改登录密码或签名密钥后重启，会撤销已有授权；客户端重新登录。
- origin 改变时现有 DB 明确拒绝启动。迁移前备份并使用全新状态目录重新授权。
- 卸载先关闭入口、停服务并禁用 systemd/Compose；保留或自行安全删除私有状态。
- 不同版本升级数据库迁移尚未提供，本版为初次提取版本。
