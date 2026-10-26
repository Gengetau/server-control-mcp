# Server Control MCP

[![tests](https://github.com/Gengetau/server-control-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Gengetau/server-control-mcp/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

自托管的 Linux 服务器控制集成：让远程 MCP 客户端通过持久化 OAuth
调用文件、补丁、命令、终端会话、Git 和图片工具，并可订阅定向事件。

**状态：0.1.0，首个提取版本。** 目标平台 Linux / Python 3.11+。
执行核心来自 [coding-tools-mcp](https://github.com/xyTom/coding-tools-mcp)
`0.3.0`，保持原样安装；本项目提供持久化认证网关、事件适配和部署集成。
不是上游官方发行版，也不是独立实现的执行引擎。

[English](README.en.md) · [部署](docs/deployment.md) · [事件](docs/events.md)
· [安全边界](SECURITY.md) · [来源与差异](docs/provenance.md)

> [!WARNING]
> 本服务让通过认证的客户端在宿主机上**远程执行命令、读写文件**。仅供单一运维者使用；
> 只通过带速率限制的 HTTPS 入口公开 OAuth 网关，切勿公开执行端端口，切勿以 root 运行。
> 部署前请阅读 [SECURITY.md](SECURITY.md)。

## 环境要求

- Linux，Python 3.11+（CI 覆盖 3.11 / 3.12 / 3.13）
- 自己的 HTTPS 反向代理或隧道（本服务不签发 TLS 证书）
- 可选：Docker Compose（Linux host 网络）或 systemd

## 提供什么

| 功能 | 实现来源 |
|---|---|
| 默认 18 项文件、命令、Git、图片及环境工具 | 上游 coding-tools-mcp |
| 基础 MCP、OAuth/PKCE、动态客户端注册 | 上游 |
| SQLite 保存注册、授权码、刷新授权 | 本项目扩展 |
| 刷新轮换、重放撤销、撤销接口 | 本项目扩展 |
| 定向事件、订阅持久化、签名回调与重试 | 本项目扩展，实验性、默认关闭 |
| 双进程监督、认证后端、systemd / Docker 示例 | 本项目集成 |

### 工具列表（上游 18 项）

| 类别 | 工具 |
|---|---|
| 环境 | `server_info`、`check_exec_environment`、`request_permissions` |
| 文件 | `read_file`、`list_dir`、`list_files`、`search_text`、`apply_patch` |
| 命令 / 终端 | `exec_command`、`write_stdin`、`read_output`、`kill_command` |
| Git | `git_status`、`git_diff`、`git_log`、`git_show`、`git_blame` |
| 图片 | `view_image` |

启用事件后，网关额外提供 `server/discover` 与 `events/*`（见下文）。

OAuth 只解决调用者认证；所有授权客户端仍共用一个操作系统账号和工作目录。
适用于自己管理的客户端，不用于互不信任的租户。

## 快速开始

以下命令在本项目根目录执行，使用普通用户：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/server-control-mcp init
mkdir -p workspace
```

编辑生成的 `.env`：将 `CODING_TOOLS_MCP_SERVER_URL` 改为自己的 **HTTPS 源站地址**，
例如 `https://mcp.example.com`，不加 `/mcp`；按需修改 `SCM_WORKSPACE`。
保留自动生成的密码和签名密钥，将 `.env` 放在工作目录之外。
该文件使用字面量 `KEY=value` 格式，不要加引号或 shell 表达式。

```bash
.venv/bin/server-control-mcp --env-file .env serve
```

默认执行端是 `127.0.0.1:28766`，OAuth 网关是 `127.0.0.1:28767`。
通过你自己的 HTTPS 反向代理或隧道将**网关**对外提供服务。
两者都不直接绑定公网。更完整的部署方法见 [部署说明](docs/deployment.md)。

在支持远程 MCP OAuth 的客户端中添加：

```text
https://mcp.example.com/mcp
```

使用生成配置里的专用密码登录。支持动态注册的客户端通常不需要预填 Client ID / Secret。
客户端是否支持令牌刷新、实验性 Events，取决于客户端自身；本版本没有逐个平台重新验收。

## 配置

`init` 生成的 `.env` 包含以下键（完整说明见 [部署说明](docs/deployment.md)）：

| 键 | 说明 |
|---|---|
| `CODING_TOOLS_MCP_SERVER_URL` | 必填，HTTPS origin，不带路径 |
| `CODING_TOOLS_MCP_OAUTH_PASSWORD` / `..._TOKEN_SECRET` | init 生成，至少 32 字符 |
| `CODING_TOOLS_MCP_OAUTH_TOKEN_TTL` | 访问令牌有效期，默认 3600 秒 |
| `SCM_STATE_DIR` / `SCM_WORKSPACE` | 私有状态目录 / 执行工作目录（二者不可嵌套） |
| `SCM_BACKEND_PORT` / `SCM_GATEWAY_PORT` | 28766 / 28767，仅绑定 127.0.0.1 |
| `SCM_PERMISSION_MODE` | `safe`（默认）/ `trusted` / `dangerous` |
| `SCM_EVENTS_ENABLED` | `0`（默认）/ `1` |

## 权限模式

由上游 coding-tools-mcp 0.3.0 执行：

| 模式 | 网络命令 | shell 展开 / 内联脚本 | Landlock（内核支持时） | 过滤敏感环境变量 | 写全局 /tmp | 跳过全部权限检查 |
|---|---|---|---|---|---|---|
| `safe`（默认） | 否 | 否 | 是 | 是 | 禁止 | 否 |
| `trusted` | 是 | 是 | 是 | 是 | 仅限前缀 | 否 |
| `dangerous` | 是 | 是 | 否 | 否 | 允许 | **是** |

`dangerous` 等同于以服务账号身份不受限执行，仅在隔离环境中使用。
实际生效情况请用 `server_info` / `check_exec_environment` 确认。

## 可选事件

设置 `SCM_EVENTS_ENABLED=1` 并重启后，支持实验性 MCP Events 的客户端可订阅
`server.changed`。本地业务系统按该客户端的 OAuth `client_id` 定向投递：

```bash
.venv/bin/server-control-mcp --env-file .env emit \
  --recipient YOUR_OAUTH_CLIENT_ID --kind task.assigned
```

回调只含事件编号、类型和时间，不含任务正文，也不代表任务已处理。
[事件说明](docs/events.md)包含订阅格式、签名验证、去重和业务适配边界。

## Docker 与 systemd

- Linux Docker：`.env` 需在宿主机上生成（compose 会覆盖其中的状态与工作目录为命名卷）：

  ```bash
  python3 -m venv .venv && .venv/bin/python -m pip install .
  .venv/bin/server-control-mcp init          # 生成 .env
  # 编辑 .env 中的 CODING_TOOLS_MCP_SERVER_URL
  docker compose up -d --build
  ```

  示例用普通容器用户（UID 10001）和命名卷，采用 Linux host 网络；HTTPS 入口仍由你配置。
- 长期运行：参考 [systemd 模板](deploy/server-control-mcp.service)，调整目录后安装。
- 不依赖任何特定云厂商、个人令牌或个人域名。

## 验证与打包

```bash
python -m unittest discover -s tests -v
python scripts/smoke.py
python scripts/release.py --check-only
python scripts/release.py
```

Smoke 在临时目录和随机端口启动真实执行端及网关，跑 OAuth 登录、文件与命令调用、
重启持久化、刷新与撤销；不会连接生产服务器或公开端口。
发布脚本按白名单创建源码 ZIP，拒绝常见凭据格式，并可从未纳入版本控制的本地 `.release-denylist` 文件读取额外正则（每行一个）。
验证结果和未覆盖部分见 [VALIDATION.md](docs/VALIDATION.md)。

## 许可证与来源

[Apache-2.0](LICENSE)，保留 LICENSE 和 NOTICE。上游执行包固定为 `0.3.0`，未复制其核心源码。
我们曾将它与官方 PyPI 发布 wheel 做逐文件比较，核心 15 个 Python 文件一致。
扩展提取来源和公开版改动见 [provenance.md](docs/provenance.md)。
