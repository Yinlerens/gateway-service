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

网关会为所有前端业务接口生成或透传 `X-Request-Id`，并把请求/响应审计写入 Supabase Postgres 的 `audit.http_api_calls` 表。`/health` 和 `/ready` 只用于探针，不进入业务审计。

审计内容包括：

- 请求方法、路径、query、路由、用户 ID、远端 IP、鉴权结果、上游 URL、状态码、耗时
- 脱敏后的请求头和响应头
- 请求体、响应体原文；JSON 请求/响应会额外保存为 `jsonb`
- 非 UTF-8 body 保存为 base64；超出 `AUDIT_MAX_BODY_BYTES` 的内容会标记 `*_truncated`

不会写入审计的头包括 `Authorization`、`Cookie`、`Proxy-Authorization`、`X-Internal-Token`、`X-User-Id`、API key 相关头和响应 `Set-Cookie`。

审计是 fail closed：配置了 `AUDIT_DATABASE_URL` 时，如果审计开始记录失败，网关不会继续鉴权或转发该请求，直接返回 `503 audit_unavailable`。

建表 SQL 在 `db/audit_schema.sql`。表位于私有 `audit` schema，默认不给 `anon` / `authenticated` 直接读取权限。

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
