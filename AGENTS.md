# AGENTS.md

## 项目用途

`gdou_helper_backend` 是 `gdou_helper` Flutter 客户端的独立 Go 后端服务。v1 版本聚焦教务系统统一身份认证与查询代理，采用零数据库架构（进程内短期事务态 + 客户端无状态持有 Cookie 与可信设备指纹）。

## 技术栈与运行环境

- 语言：Go 1.25+（`go.mod` 最低版本 `1.25.0`，当前已验证工具链 `go1.27.4`）
- HTTP 框架：`github.com/gin-gonic/gin`
- HTML 解析：`golang.org/x/net/html`
- 存储：无外部数据库；仅使用进程内存 TTL Map（`AuthTxStore`）暂存图形验证码与二次验证会话，不落盘且不保存明文密码

## 目录结构

- `cmd/api/main.go`：服务入口、配置校验与优雅停机
- `internal/config/config.go`：环境变量解析与启动参数校验
- `internal/integration/jwxt/`：金智统一身份认证加密、重定向与页面检测、纯 HTTP CAS/MFA/wfw 网关接入、课表/成绩/成绩分项/考试解析
- `internal/server/`：Gin 路由、统一 JSON 响应与错误码映射、内存 TTL 事务存储、教务 HTTP 处理器
- `docs/architecture-and-api-plan.md`：协议细节与接口契约文档

## 构建与测试命令

```bash
go vet ./...
go test -race ./...
go build -o bin/gdou-helper-backend ./cmd/api
go run ./cmd/api
```

## 架构与接口约束

- 统一响应格式：`{"code":"OK","message":"ok","data":...}`；错误响应必须返回 JSON（包含 `NoRoute` 404 与 `NoMethod` 405），避免前端解析纯文本失败。
- 会话失效统一返回 HTTP `401` 与 `code: "SESSION_EXPIRED"`，以触发前端 `_withAutoReLogin`。
- 成绩列表每项必须保留 `raw` 字段，供前端提取 `jxb_id`/`kch_id`/`kch`/`xnm`/`xqm` 请求 `/api/v1/jwxt/grade-detail`。
- 每次登录与业务查询均使用独立 `http.CookieJar` 隔离，禁止共享 CookieJar 导致并发串号。
- 禁止在日志或响应中输出用户密码、Cookie、票据或验证码内容；禁止自动绕过图形验证码或自动读取/填充 MFA 动态码。
- 校外 `wfw.gdou.edu.cn` 模式必须在请求 CAS 前清理残留 `wfw` Cookie，先以 `service=https://wfw.gdou.edu.cn/` 激活全新 `WFWSESSID`，再访问 `wfw/https://jw.gdou.edu.cn` 与 `/xtgl/dl_loginForward.html`。
