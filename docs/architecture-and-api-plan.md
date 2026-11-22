# GDOU Helper 后端重构方案与接口契约（v1：教务系统纯 HTTP 版）

## 1. 目标与范围

- 仓库定位：独立 Go 后端仓库（`git@github.com:farshore07/gdou_helper_backend.git`），与 Flutter 前端 `gdou_helper` 解耦部署。
- 本期实现范围：
  - 健康检查（`/health`、`/api/v1/health`）
  - 教务系统统一身份认证（纯 HTTP 对接 `authserver.gdou.edu.cn`，支持企业微信/短信两步式二次验证、按需图形验证码、信任设备指纹复用）
  - 教务查询接口（会话校验、课表、成绩、成绩分项明细、考试日程）
- 本期暂不实现（后续分阶段接入）：
  - IP 限流与封禁
  - 宿舍电费模块
  - 学习资料库模块
  - 用户体系、管理后台与审计日志

---

## 2. 技术栈与存储方案

- **语言与框架**：Go（1.25+，`go.mod` 最低 `1.25.0`，当前已验证 `go1.27.4`）+ Gin + Go 标准库 `net/http` / `crypto/aes` / `net/http/cookiejar`。
- **零数据库依赖（首版）**：不引入 PostgreSQL / SQLite / Redis / GORM，单二进制直接运行。
- **三类数据策略**：
  1. **二次验证 / 图形验证码临时事务态**：进程内存存储（`sync.Mutex` + TTL 5 分钟自动清理 + 最大并发容量限制），每个 `login_token` 绑定独立 `http.CookieJar` 与 `MfaContext`，杜绝多用户并发串号，用完即删。
  2. **会话 Cookie 与可信设备指纹（方案 A：无状态客户端持有）**：后端不持久化 Cookie；登录成功后向客户端返回教务 `cookie` 与 `device_fingerprint`（即 `MULTIFACTOR_BROWSER_FINGERPRINT`），由客户端存入安全存储，后续查询透传 `cookie`，重登透传 `device_fingerprint` 实现免二次验证。
  3. **教务业务数据（方案 1：不落库）**：成绩、课表、成绩明细、考试日程均为实时代理转发，缓存由 Flutter 客户端负责。

---

## 3. 内外网接入与认证协议要点

### 3.1 内外网分流与 `wfw.gdou.edu.cn` 代理（已通过广州公网服务器实测）

- 公网环境无法直连 `jw.gdou.edu.cn`（443 拒连）；访问 `GET https://netcheck.gdou.edu.cn/go.php?code=jw` 时：
  - 校内网络：`302` → `https://jw.gdou.edu.cn/sso/jziotlogin`
  - 校外公网：`302` → `https://wfw.gdou.edu.cn/https://jw.gdou.edu.cn`
- `wfw.gdou.edu.cn` 是带服务端会话（`WFWSESSID`）与 `urlss` Cookie 路由的校外反代网关（已通过广州公网全链路实测验证）：
  1. 登录前清理事务 CookieJar 中残留的 `wfw.gdou.edu.cn` 旧 Cookie（避免未激活的 `WFWSESSID` 导致后续票据无法激活网关会话）；
  2. 直连 `https://authserver.gdou.edu.cn/authserver/login?service=https%3A%2F%2Fwfw.gdou.edu.cn%2F` 完成账密/图形验证码/二次验证（与校内共用 `MULTIFACTOR_BROWSER_FINGERPRINT` 可信设备指纹）；
  3. 收到 `302 Location: https://wfw.gdou.edu.cn/?ticket=ST-...` 后跟随跳转，`wfw` 签发全新的已激活 `WFWSESSID`；
  4. 请求 `GET https://wfw.gdou.edu.cn/https://jw.gdou.edu.cn` 触发网关后端自动完成教务 SSO 并在 `WFWSESSID` 服务端会话内保存教务 `JSESSIONID`，同时种下 `urlss="https://jw.gdou.edu.cn"`、`urlss_jw="https://jw.gdou.edu.cn"` 与 `ADCCookie-*`；随后访问 `GET https://wfw.gdou.edu.cn/xtgl/dl_loginForward.html?language=` 完成教务主页初始化；
  5. 后续教务业务查询（课表/成绩/考试/菜单）直接映射为 `https://wfw.gdou.edu.cn/<path>?<query>`，客户端仅透传 `wfw.gdou.edu.cn` 的 Cookie（`WFWSESSID`、`urlss`、`urlss_jw`、`ADCCookie-*`）即可无状态复用；
  6. 若在校内网络强制使用 `wfw` 模式，访问 `wfw/https://jw.gdou.edu.cn` 会被 `302` 弹回直连 `jw.gdou.edu.cn`，此时利用已有 `CASTGC` 直连 `authserver/login?service=https://jw.gdou.edu.cn/sso/jziotlogin` 换票即可平滑回退。
  - **公网图形验证码为必经主路径**：广州公网实测 `checkNeedCaptcha.htl` 返回 `{"isNeed":true}`，登录流程必须完整支持图形验证码两步交互（透传图片由用户手动填写，不做任何自动绕过）；
  - **公网会话过期直接返回 `HTTP 200` 登录页 HTML**：未登录通过 `wfw` 请求教务 `POST` 接口时，网关内部跟完跳转直接返回 `200 text/html`（正文为统一身份认证登录页），因此业务接口过期判定必须结合正文 DOM（`#pwdFromId`/`#pwdEncryptSalt`/`reAuthParams`）而不只看 `302`。
- 后端配置项支持 `JWXT_ACCESS_MODE=auto|direct|wfw`（默认 `auto`：启动时通过 `netcheck.gdou.edu.cn/go.php?code=jw` 自动识别校内直连或校外 `wfw` 模式）。

### 3.2 金智 IDS 认证与二次验证协议要点

已通过 `gdou-jwxt` 实盘验证的金智 IDS（`authserver.gdou.edu.cn`）协议细节：

1. **HTTPS 规范化**：`jw.gdou.edu.cn/sso/jziotlogin` 会 302 跳转至 `http://authserver.gdou.edu.cn/authserver/login?service=...`，后端重定向拦截器需自动将 `authserver.gdou.edu.cn` 升级为 `https://`，防止 `Secure` Cookie 丢失。
2. **浏览器指纹注册**：
   - 登录前检查事务 CookieJar 是否已存在 `MULTIFACTOR_BROWSER_FINGERPRINT`（客户端若传入历史 `device_fingerprint` 则先注入该 Cookie，避免触发新设备验证）。
   - 若缺失，随机生成 32 位大写十六进制字符串并请求 `GET /authserver/bfp/info?bfp=<BFP>`，由服务端种下持久 Cookie。
3. **密码加密（对齐 `encrypt.js`）**：
   - 从登录页 `#pwdFromId` 解析 `execution`、`lt`、`cllt`、`dllt`、`_eventId` 与 `#pwdEncryptSalt`（无 `name`，按 `id` 提取）。
   - 明文拼接：`64 个随机 ASCII 字符 + 明文密码`（字符表 `ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678`）。
   - 独立生成 `16 个随机 ASCII 字符` 作为 IV；密钥为 `strings.TrimSpace(salt)` 的 UTF-8 字节；AES-CBC + PKCS7 填充，输出单行无换行标准 Base64。
   - 提交目标 URL 必须保留 `?service=https%3A%2F%2Fjw.gdou.edu.cn%2Fsso%2Fjziotlogin`。
4. **按需图形验证码**：
   - 账密提交前请求 `GET /authserver/checkNeedCaptcha.htl?username=<学号>`；当 `isNeed == true` 时拉取 `GET /authserver/getCaptcha.htl` 返回图片字节。
5. **两步式二次验证（不做自动填码）**：
   - 跳转至 `/authserver/reAuthCheck/reAuthLoginView.do` 时，解析 `reAuthParams`（注意对 Thymeleaf 内联 JS 的 `\/` 等转义序列解码）。
   - 切换方式：`POST /authserver/reAuthCheck/changeReAuthType.do`（`reAuthType`: `"4"`=企业微信、`"3"`=短信；注意兼容服务端返回的 `code` 为字符串 `"1"` 或整数 `1`）。
   - 发码：`POST /authserver/dynamicCode/getDynamicCodeByReauth.do`（`authCodeTypeName`: `reAuthWChatDynamicCodeType` / `reAuthDynamicCodeType`；成功标志 `wechat_success` / `success`）。
   - 验码：`POST /authserver/reAuthCheck/reAuthSubmit.do`（传 `dynamicCode` 与 `skipTmpReAuth="true"|"false"`）；成功后跳回 `GET /authserver/login?service=...` 换取 ST 票据并落地 `jw.gdou.edu.cn`。

---

## 4. API 契约清单

### 通用约定

- 统一响应格式：
  ```json
  { "code": "OK", "message": "ok", "data": {} }
  ```
- 统一错误格式（含自定义 Gin `NoRoute`，避免返回纯文本 404）：
  ```json
  { "code": "SESSION_EXPIRED", "message": "错误原因", "data": null }
  ```
- 会话过期返回 HTTP `401` + `code: "SESSION_EXPIRED"`，与 Flutter `_withAutoReLogin` 保持一致。
- 业务查询接口通过 `response.URL` + 重定向历史链联合检测登录重定向；仅幂等 `GET` 与已确认只读的教务 `POST` 查询识别过期后返回 `401 SESSION_EXPIRED` 由客户端处理。

### 接口列表

| 方法与路径 | 说明 | 请求体核心字段 | 成功响应 `data` 核心字段 |
| --- | --- | --- | --- |
| `GET /health` | 存活检查 | - | `{"status": "ok"}` |
| `GET /api/v1/health` | 详细健康检查 | - | `env`、`started_at`、`database: "disabled"` |
| `POST /api/v1/jwxt/login` | 教务登录（支持免二次验证设备指纹与按需图形验证码） | `username`、`password`、`device_fingerprint?`、`captcha_token?`、`captcha_code?` | 直接成功：`status: "success"`、`cookie`、`device_fingerprint`、`url`<br>需二次验证：`status: "need_mfa"`、`login_token`、`default_method`、`available_methods`、`message`<br>需图形验证码：`status: "need_captcha"`、`captcha_token`、`captcha_image`（Base64） |
| `POST /api/v1/jwxt/mfa/send` | 切换并发送二次验证码 | `login_token`、`method`（`"wechat"` \| `"sms"` \| `"auto"`） | `method`、`countdown`、`message` |
| `POST /api/v1/jwxt/mfa/verify` | 提交二次验证码并信任设备 | `login_token`、`code`、`trust_device?`（默认 `true`） | `status: "success"`、`cookie`、`device_fingerprint`、`url`、`message` |
| `POST /api/v1/jwxt/session/validate` | 校验教务 Cookie 会话（过期返回 `401 SESSION_EXPIRED`，上游异常返回 `502`，超时返回 `504`） | `cookie` | `status`（`"success"`）、`message`、`url` |
| `POST /api/v1/jwxt/timetable` | 查询个人课表 | `cookie`、`academic_year`、`term`、`extra?` | `courses[]`、`student_info`、`raw` |
| `POST /api/v1/jwxt/grades` | 查询个人成绩 | `cookie`、`academic_year`、`term`、`extra?` | `items[]`（含 `raw`）、`total_count`、`total_page`、`current_page`、`page_size`、`raw` |
| `POST /api/v1/jwxt/grade-detail` | 查询单科成绩分项明细 | `cookie`、`query`（`jxb_id`/`kch_id`/`kch`/`xnm`/`xqm`） | `course_name`、`items[]`（`name`/`ratio`/`score`） |
| `POST /api/v1/jwxt/exams` | 查询考试日程 | `cookie`、`academic_year`、`term`、`extra?` | `items[]`、`total_count`、`total_page`、`current_page`、`page_size`、`raw` |

---

## 5. 前端后续配合改动清单（`gdou_helper`）

1. `secure_store.dart` 新增 `device_fingerprint` 读写；`loginJwxt` 与 `silentReLogin` 透传已保存的 `device_fingerprint` 并在登录成功时保存新值（登出时建议保留设备指纹，避免同设备重新登录反复触发二次验证）。
2. `login_page.dart` 与 `auth_provider.dart` 适配 `status == "need_mfa"` 弹窗流程，接入 `/api/v1/jwxt/mfa/send`（支持企微/短信切换）与 `/api/v1/jwxt/mfa/verify`。
3. `auth_provider.dart` 的 `doElectricityLogin` 增加 `try/catch` 容错，避免后端未上线电费模块时 `404` 阻断教务登录与 `silentReLogin`。

---

## 6. 建议代码目录结构

```text
gdou_helper_backend/
├── cmd/
│   └── api/main.go
├── docs/
│   └── architecture-and-api-plan.md
├── internal/
│   ├── config/config.go
│   ├── integration/jwxt/
│   │   ├── crypto.go            # 金智 AES-CBC 密码加密
│   │   ├── detector.go          # 页面状态与重定向链判定
│   │   ├── sso.go               # 纯 HTTP CAS 登录、bfp/info、两步式 MFA
│   │   ├── client.go            # 课表、成绩、考试查询
│   │   ├── grade_detail.go      # 成绩分项 HTML 解析
│   │   └── models.go
│   └── server/
│       ├── router.go
│       ├── response.go
│       ├── mfa_store.go         # 进程内存 TTL 事务存储（MFA / 图形验证码）
│       └── jwxt_handlers.go
├── go.mod
└── README.md
```
