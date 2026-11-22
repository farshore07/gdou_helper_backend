# gdou_helper_backend

广东海洋大学助手（`gdou_helper`）纯 HTTP Go 后端服务（v1：无数据库依赖，单二进制部署）。

## 核心能力

- 纯 HTTP 对接金智统一身份认证（`authserver.gdou.edu.cn`），支持：
  - 校内直连（`jw.gdou.edu.cn`）、校外网关（`wfw.gdou.edu.cn`）及自动探测（`netcheck.gdou.edu.cn`）
  - 浏览器可信设备指纹（`MULTIFACTOR_BROWSER_FINGERPRINT`）复用，免重复二次验证
  - 按需图形验证码两步交互（公网环境透传图片由用户输入）
  - 企业微信 / 手机短信两步式二次验证（MFA）
- 教务查询接口（无状态透传 Cookie，与 `gdou_helper` Flutter 客户端对齐）：
  - `POST /api/v1/jwxt/login`
  - `POST /api/v1/jwxt/mfa/send`
  - `POST /api/v1/jwxt/mfa/verify`
  - `POST /api/v1/jwxt/session/validate`
  - `POST /api/v1/jwxt/timetable`
  - `POST /api/v1/jwxt/grades`
  - `POST /api/v1/jwxt/grade-detail`
  - `POST /api/v1/jwxt/exams`
- 健康检查：`GET /health`、`GET /api/v1/health`

## 运行与测试

```bash
# 运行测试（含竞态检测）
go test -race ./...

# 本地启动（默认监听 :8080，自动探测内外网模式）
go run ./cmd/api

# 编译生产二进制
go build -o bin/gdou-helper-backend ./cmd/api
```

## 环境变量与 `.env` 文件

启动时优先读取系统环境变量，其次自动读取当前工作目录的 `.env` 文件（也可通过 `ENV_FILE` 指定路径），参考 [.env.example](.env.example)。

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `ENV_FILE` | `.env` | 自定义 `.env` 配置文件路径（显式指定时文件必须存在） |
| `APP_ENV` | `dev` | 运行环境：`dev` / `prod` / `test` |
| `HTTP_ADDR` | `:8080` | 监听地址（支持 `:8080`、`127.0.0.1:8080` 或纯端口号 `8080`） |
| `HTTP_MAX_BODY_BYTES` | `1048576` | 单请求最大体大小（字节） |
| `TRUSTED_PROXIES` | 空 | 可信反向代理 CIDR（逗号分隔，空则不信任任意代理） |
| `CORS_ALLOW_ORIGINS` | 空 | 允许跨域的 Origin 白名单（逗号分隔，可填 `*`） |
| `JWXT_ACCESS_MODE` | `auto` | 教务接入模式：`auto` / `direct`（`campus`） / `wfw`（`external`） |
| `JWXT_TIMEOUT_SECONDS` | `20` | 教务与认证上游请求超时（秒） |
| `AUTH_TX_TTL_SECONDS` | `300` | 图形验证码与 MFA 事务内存态有效期（秒） |
| `AUTH_TX_MAX_ENTRIES` | `500` | 内存事务态最大并发条数上限 |

详细架构与接口契约见 [docs/architecture-and-api-plan.md](docs/architecture-and-api-plan.md)。
