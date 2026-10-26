# 定向 MCP Events（实验性）

默认关闭，设置 `SCM_EVENTS_ENABLED=1` 后重启。使用支持 `2026-07-28`
实验性 Events 的客户端；传统 MCP 工具调用继续工作。服务只提供 webhook delivery。

## 订阅

完成 OAuth 登录，用有效的 Bearer access token 调用 `events/list`，然后：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "events/subscribe",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {}
    },
    "name": "server.changed",
    "arguments": {},
    "ttlMs": 86400000,
    "delivery": {
      "mode": "webhook",
      "url": "https://receiver.example.com/events",
      "secret": "whsec_BASE64_OF_32_RANDOM_BYTES"
    }
  }
}
```

HTTP 请求还需带镜像头 `MCP-Protocol-Version: 2026-07-28`、
`Mcp-Method: events/subscribe` 以及 `Mcp-Name: server.changed`。
Smoke 使用已固定上游的协议常量，升级依赖时需同步核对。
签名 secret 必须解码成 24–64 字节。
订阅前服务发送 `{"type":"verification","challenge":"..."}`，回调需返回 2xx 和
JSON `{"challenge":"相同值"}`。回调地址必须是公开 HTTPS/443；拒绝私网、混合 DNS、
凭据 URL、重定向。相同认证客户端、origin、回调和事件构成同一个订阅，重复订阅续期。

## 生产事件

订阅 owner 来自 OAuth 认证后的 client_id，不接受请求传入另一个身份。
业务系统必须显式把工单负责人映射到正确的 client_id，再在服务所在主机调用：

```bash
server-control-mcp --env-file .env emit --recipient CLIENT_ID --kind task.assigned
```

生产者也可调用 `EventFeed(state_dir / 'outbox.sqlite3').emit(kind, client_id)`。
操作系统权限是生产者认证边界；没有公开的远程 emit 接口。
仅匹配 recipient 的订阅收到事件；其他事件推进投递游标，不会唤醒该客户端。
新订阅从当前末尾开始，不补投历史。服务不会修改工单状态或业务已读游标。

通知 data 只含 id/kind/at，事件时间为 UTC ISO 8601。接收方需要正文时再调自己的业务工具。
本项目不依赖任何特定任务看板、聊天平台或个人身份。

## 签名与重试

Standard Webhooks HMAC-SHA256：

```text
message = webhook-id + "." + webhook-timestamp + "." + raw_HTTP_body
signature = base64(HMAC-SHA256(base64decode(secret_without_whsec_), message))
webhook-signature = "v1," + signature
```

接收端检查时间窗、常量时间比较签名并按 eventId 去重。服务验证 TLS，连接使用已校验 IP，
保留原域名 SNI。对 410/413 删除订阅；其他失败指数退避，连续 12 次失败删除。
每个成功事件立即保存游标，重试保留 eventId；崩溃后可能重复投递。
默认轮询 30 秒、每批 50 项、最多 16 个有效订阅、TTL 上限 7 天。
授权撤销后下一次 worker 检查移除订阅。续期需要客户端在 refreshBefore 前重新订阅。

数据库不会自动清理历史 outbox。暂不支持多 worker、高可用或长历史回放；超大 backlog
需要在部署前设计保留策略。原始签名密钥仅在本机订阅库中保存，不能公开数据库。
