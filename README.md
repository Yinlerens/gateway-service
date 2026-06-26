# 网关服务

Go 网关服务负责承接前端请求，在调用内部微服务之前统一校验登录状态。

## 前端登录实现

当前前端在 `jizhang` 中使用 Supabase SSR：

- 浏览器端 `app/login/page.tsx` 调用 `supabase.auth.signInWithPassword`
- `lib/supabase/client.ts` 使用 `createBrowserClient`
- `lib/supabase/server.ts` 使用 `createServerClient` 从 Next.js cookies 读写会话
- `app/auth/callback/route.ts` 通过 `exchangeCodeForSession` 写入 Supabase 会话 cookie

也就是说，前端登录态以 Supabase SSR cookie 传给同域后端；网关会从 `Authorization: Bearer ...` 或 Supabase SSR cookie 中取出 access token，然后调用 Supabase Auth `/auth/v1/user` 验证。网关不会信任 cookie 里的用户对象，也不会把浏览器 token 或 cookie 转发给下游微服务。

## 身份边界

所有微服务调用必须经过网关：

1. 前端请求网关路由，例如 `GET /api/v1/assets/me/account`
2. 网关校验 Supabase 登录态
3. 校验成功后，网关注入内部头：
   - `X-Internal-Token`
   - `X-User-Id`
4. 网关转发到内部微服务，例如资产服务的 `/v1/me/account`

客户端伪造的 `X-Internal-Token`、`X-User-Id`、`Authorization` 和 `Cookie` 都会在转发前被移除。

## 接口审计

网关会为所有前端业务接口生成或透传 `X-Request-Id`，并把请求/响应审计写入业务 Postgres 的 `audit.http_api_calls` 表。`/health` 和 `/ready` 只用于探针，不进入业务审计。

审计内容包括：

- 请求方法、路径、query、路由、用户 ID、远端 IP、鉴权结果、上游 URL、状态码、耗时
- 脱敏后的请求头和响应头
- 请求体、响应体原文；JSON 请求/响应会额外保存为 `jsonb`
- 非 UTF-8 body 保存为 base64；超出 `AUDIT_MAX_BODY_BYTES` 的内容会标记 `*_truncated`

不会写入审计的头包括 `Authorization`、`Cookie`、`Proxy-Authorization`、`X-Internal-Token`、`X-User-Id`、API key 相关头和响应 `Set-Cookie`。

审计是 fail closed：配置了 `AUDIT_DATABASE_URL` 时，如果审计开始记录失败，网关不会继续鉴权或转发该请求，直接返回 `503 audit_unavailable`。

建表 SQL 在 `db/audit_schema.sql`。表位于 `audit` schema，应该使用网关后端的数据库账号访问，不给前端直连读取完整 body。

### 审计日志查询接口

网关提供管理员专用的审计日志查询接口。接口仍然使用 Supabase 登录态鉴权，但只有 `AUDIT_LOG_ADMIN_USER_IDS` 中配置的 Supabase user UUID 可以访问；未配置时默认拒绝。

列表接口只返回请求/响应 body 预览，适合前端表格筛选：

```http
GET /api/v1/admin/audit/http-api-calls?limit=50&path=/gacha&route=gacha&status=502
Authorization: Bearer <supabase access token>
```

支持的查询参数：

- `limit`：返回条数，默认 50，最大 200
- `request_id`：精确匹配请求 ID
- `user_id`：精确匹配 Supabase 用户 ID
- `method`：HTTP 方法
- `path`：路径包含匹配
- `route`：网关路由名，例如 `assets`、`gacha`、`backpack`
- `auth_result`：鉴权结果，例如 `authenticated`、`missing_session`、`forbidden`
- `status`：HTTP 响应状态码
- `since` / `until`：RFC3339 时间范围，按 `started_at` 过滤

详情接口按请求 ID 返回完整请求/响应头和 body：

```http
GET /api/v1/admin/audit/http-api-calls/{request_id}
Authorization: Bearer <supabase access token>
```

这些管理接口本身也会进入审计表。

## 配置

必填环境变量：

```text
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<supabase anon key>
INTERNAL_TOKEN=<gateway-to-service shared secret>
UPSTREAM_ROUTES=assets=/api/v1/assets|http://asset-service.asset-service.svc.cluster.local/v1,gacha=/api/v1/gacha|http://gacha-engine-service.gacha-engine-service.svc.cluster.local/v1,backpack=/api/v1/backpack|http://backpack-service.backpack-service.svc.cluster.local/v1
```

可选环境变量：

```text
PORT=8080
SUPABASE_AUTH_COOKIE_NAME=sb-<project-ref>-auth-token
REQUEST_TIMEOUT_SECONDS=15
MAX_BODY_BYTES=4194304
AUDIT_DATABASE_URL=postgresql://...
AUDIT_MAX_BODY_BYTES=4194304
AUDIT_WRITE_TIMEOUT_SECONDS=3
AUDIT_LOG_ADMIN_USER_IDS=<supabase-user-uuid>[,<supabase-user-uuid>...]
```

如果只接资产服务，也可以用：

```text
ASSET_SERVICE_URL=http://asset-service.asset-service.svc.cluster.local
```

此时默认公开路由为 `/api/v1/assets`，并转发到资产服务 `/v1`。

## 路由格式

`UPSTREAM_ROUTES` 支持多个上游，用英文逗号分隔：

```text
assets=/api/v1/assets|http://asset-service.asset-service.svc.cluster.local/v1,gacha=/api/v1/gacha|http://gacha-engine-service.gacha-engine-service.svc.cluster.local/v1,backpack=/api/v1/backpack|http://backpack-service.backpack-service.svc.cluster.local/v1
```

路由会按最长前缀匹配，所有上游路由都需要登录。

## API

公开健康检查：

```http
GET /health
GET /ready
```

受保护的资产服务示例：

```http
GET /api/v1/assets/me/account
Cookie: sb-<project-ref>-auth-token=...
```

或：

```http
GET /api/v1/assets/me/account
Authorization: Bearer <supabase access token>
```

受保护的抽卡与背包服务示例：

```http
POST /api/v1/gacha/me/pulls
Cookie: sb-<project-ref>-auth-token=...
Content-Type: application/json

{
  "banner_id": "limited-character-001",
  "count": 10
}
```

```http
GET /api/v1/backpack/me/inventory
Cookie: sb-<project-ref>-auth-token=...
```

## 本地开发

安装 Go 1.22 或更新版本，然后运行：

```bash
go test ./...
go run ./cmd/gateway-service
```
