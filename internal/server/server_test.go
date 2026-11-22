package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/farshore07/gdou_helper_backend/internal/config"
	"github.com/farshore07/gdou_helper_backend/internal/integration/jwxt"
)

type stubTransport func(*http.Request) (*http.Response, error)

func (f stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func respWith(req *http.Request, status int, contentType string, headers map[string]string, cookies []*http.Cookie, body string) *http.Response {
	h := make(http.Header)
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		h.Set(k, v)
	}
	for _, c := range cookies {
		h.Add("Set-Cookie", c.String())
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
}

func newTestServer(t *testing.T, rt http.RoundTripper) *Server {
	t.Helper()
	cfg := config.Config{
		Env:              "test",
		HTTPAddr:         ":0",
		HTTPMaxBodyBytes: 1 << 20,
		JWXTAccessMode:   "direct",
		JWXTTimeout:      5 * time.Second,
		AuthTxTTL:        2 * time.Minute,
		AuthTxMaxEntries: 100,
	}
	client := jwxt.NewClient(jwxt.ClientOptions{
		AccessMode: jwxt.NetworkModeCampus,
		Timeout:    5 * time.Second,
		Transport:  rt,
	})
	srv, err := New(cfg, client)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func doJSON(t *testing.T, h http.Handler, method, path string, payload any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not valid JSON (%s %s -> %d): %q", method, path, rec.Code, rec.Body.String())
	}
	return rec, out
}

func TestHealthAndJSONNotFound(t *testing.T) {
	srv := newTestServer(t, stubTransport(func(r *http.Request) (*http.Response, error) {
		return respWith(r, http.StatusOK, "text/html", nil, nil, ""), nil
	}))

	rec, body := doJSON(t, srv.Handler, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("unexpected /health: %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodGet, "/api/v1/health", nil)
	data, _ := body["data"].(map[string]any)
	if rec.Code != http.StatusOK || body["code"] != "OK" || data["database"] != "disabled" {
		t.Fatalf("unexpected /api/v1/health: %d %+v", rec.Code, body)
	}

	// 未上线模块（如电费）必须返回标准 JSON 404，防止前端 Dio 解析纯文本崩溃
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/electricity/login", map[string]any{"username": "1", "password": "2"})
	if rec.Code != http.StatusNotFound || body["code"] != "NOT_FOUND" {
		t.Fatalf("expected JSON 404 NOT_FOUND, got %d %+v", rec.Code, body)
	}

	// 路径存在但 HTTP 方法错误必须返回标准 JSON 405 METHOD_NOT_ALLOWED
	rec, body = doJSON(t, srv.Handler, http.MethodGet, "/api/v1/jwxt/login", nil)
	if rec.Code != http.StatusMethodNotAllowed || body["code"] != "METHOD_NOT_ALLOWED" {
		t.Fatalf("expected JSON 405 METHOD_NOT_ALLOWED, got %d %+v", rec.Code, body)
	}
}

func TestValidateSessionStatusMapping(t *testing.T) {
	const loginHTML = `<form id="pwdFromId" action="/authserver/login"><input id="pwdEncryptSalt" value="1234567890abcdef"/></form>`
	srv := newTestServer(t, stubTransport(func(r *http.Request) (*http.Response, error) {
		cookie := r.Header.Get("Cookie")
		switch {
		case strings.Contains(cookie, "JSESSIONID=OK"):
			return respWith(r, http.StatusOK, "text/html", nil, nil, `<html><title>教学管理信息服务平台</title></html>`), nil
		case strings.Contains(cookie, "JSESSIONID=EXPIRED"):
			return respWith(r, http.StatusOK, "text/html", nil, nil, loginHTML), nil
		case strings.Contains(cookie, "JSESSIONID=MAINT200"):
			return respWith(r, http.StatusOK, "text/html", nil, nil, `<html><body>系统维护中</body></html>`), nil
		case strings.Contains(cookie, "JSESSIONID=AUTH503"):
			if r.URL.Hostname() == "jw.gdou.edu.cn" {
				return respWith(r, http.StatusFound, "", map[string]string{
					"Location": "https://authserver.gdou.edu.cn/authserver/login?service=https%3A%2F%2Fjw.gdou.edu.cn%2Fsso%2Fjziotlogin",
				}, nil, ""), nil
			}
			return respWith(r, http.StatusServiceUnavailable, "text/html", nil, nil, `<html>认证服务不可用</html>`), nil
		case strings.Contains(cookie, "JSESSIONID=MAINT"):
			return respWith(r, http.StatusServiceUnavailable, "text/html", nil, nil, `<html>系统维护中</html>`), nil
		case strings.Contains(cookie, "JSESSIONID=TIMEOUT"):
			return nil, context.DeadlineExceeded
		default:
			return respWith(r, http.StatusInternalServerError, "text/plain", nil, nil, "error"), nil
		}
	}))

	rec, body := doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=OK"})
	if rec.Code != http.StatusOK || body["code"] != "OK" || body["data"].(map[string]any)["status"] != "success" {
		t.Fatalf("expected 200 OK success, got %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=EXPIRED"})
	if rec.Code != http.StatusUnauthorized || body["code"] != "SESSION_EXPIRED" {
		t.Fatalf("expected 401 SESSION_EXPIRED, got %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=MAINT"})
	if rec.Code != http.StatusBadGateway || body["code"] != "JWXT_UPSTREAM_ERROR" {
		t.Fatalf("expected 502 JWXT_UPSTREAM_ERROR, got %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=MAINT200"})
	if rec.Code != http.StatusBadGateway || body["code"] != "JWXT_UPSTREAM_ERROR" {
		t.Fatalf("expected 502 JWXT_UPSTREAM_ERROR for 200 maintenance page, got %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=AUTH503"})
	if rec.Code != http.StatusBadGateway || body["code"] != "JWXT_UPSTREAM_ERROR" {
		t.Fatalf("expected 502 JWXT_UPSTREAM_ERROR for 302->authserver 503, got %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/session/validate", map[string]any{"cookie": "JSESSIONID=TIMEOUT"})
	if rec.Code != http.StatusGatewayTimeout || body["code"] != "JWXT_UPSTREAM_TIMEOUT" {
		t.Fatalf("expected 504 JWXT_UPSTREAM_TIMEOUT, got %d %+v", rec.Code, body)
	}
}

func TestGradeDetailMaintenanceVsEmptyTable(t *testing.T) {
	srv := newTestServer(t, stubTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/cjcx/cjcx_cxCjxqGjh.html" {
			return respWith(r, http.StatusNotFound, "text/plain", nil, nil, "not found"), nil
		}
		switch r.URL.Query().Get("jxb_id") {
		case "MAINT":
			return respWith(r, http.StatusOK, "text/html", nil, nil, `<html><body>系统维护中，请稍后再试</body></html>`), nil
		case "MAINT_TITLE":
			return respWith(r, http.StatusOK, "text/html", nil, nil, `<html><head><title>成绩分项查询维护中</title></head><body>成绩分项查询维护中</body></html>`), nil
		case "EMPTY":
			return respWith(r, http.StatusOK, "text/html", nil, nil, `<div>课程名称：<span class="red2">体育</span></div><table id="subtab"><tr><td>成绩分项</td><td>成绩分项比例</td><td>成绩</td></tr></table>`), nil
		default:
			return respWith(r, http.StatusOK, "text/html", nil, nil, `课程名称：<span class="red2">算法</span><table><tr><td>平时成绩</td><td>40%</td><td>95</td></tr></table>`), nil
		}
	}))

	// 1. HTTP 200 维护页（含标题提及“成绩分项”的维护页）必须返回 502 JWXT_UPSTREAM_ERROR
	for _, id := range []string{"MAINT", "MAINT_TITLE"} {
		rec, body := doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/grade-detail", map[string]any{
			"cookie": "JSESSIONID=OK",
			"query":  map[string]string{"jxb_id": id},
		})
		if rec.Code != http.StatusBadGateway || body["code"] != "JWXT_UPSTREAM_ERROR" {
			t.Fatalf("expected 502 JWXT_UPSTREAM_ERROR for maintenance page %s, got %d %+v", id, rec.Code, body)
		}
	}

	// 2. 合法但无明细行的成绩明细页返回 200 OK 且 items 为空数组
	rec, body := doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/grade-detail", map[string]any{
		"cookie": "JSESSIONID=OK",
		"query":  map[string]string{"jxb_id": "EMPTY"},
	})
	if rec.Code != http.StatusOK || body["code"] != "OK" {
		t.Fatalf("expected 200 OK for valid empty grade detail table, got %d %+v", rec.Code, body)
	}
	data := body["data"].(map[string]any)
	items := data["items"].([]any)
	if data["course_name"] != "体育" || len(items) != 0 {
		t.Fatalf("unexpected empty grade detail payload: %+v", data)
	}
}

func TestJWXTLoginMfaAndProtectedEndpoints(t *testing.T) {
	const loginHTML = `<form id="pwdFromId" action="/authserver/login"><input id="pwdEncryptSalt" value="1234567890abcdef"/><input name="execution" value="e1s1"/></form>`
	const reAuthHTML = `<script>var reAuthParams = {service:"https:\/\/jw.gdou.edu.cn\/sso\/jziotlogin",isMultifactor:"true",reAuthType:"4",reAuthUserId:"202311701234"};</script><div id="4">企微</div><div id="3">短信</div>`

	var mu sync.Mutex
	mfaDone := false

	rt := stubTransport(func(r *http.Request) (*http.Response, error) {
		path := r.URL.Path
		cookie := r.Header.Get("Cookie")
		switch {
		case path == "/authserver/login" && r.Method == http.MethodGet:
			mu.Lock()
			done := mfaDone
			mu.Unlock()
			if done {
				return respWith(r, http.StatusFound, "", map[string]string{
					"Location": "https://jw.gdou.edu.cn/sso/jziotlogin?ticket=ST-OK",
				}, nil, ""), nil
			}
			return respWith(r, http.StatusOK, "text/html", nil, nil, loginHTML), nil
		case path == "/authserver/bfp/info":
			bfp := r.URL.Query().Get("bfp")
			return respWith(r, http.StatusOK, "text/plain", nil, []*http.Cookie{
				{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: bfp, Path: "/", Secure: true},
			}, ""), nil
		case path == "/authserver/checkNeedCaptcha.htl":
			return respWith(r, http.StatusOK, "application/json", nil, nil, `{"isNeed":false}`), nil
		case path == "/authserver/login" && r.Method == http.MethodPost:
			return respWith(r, http.StatusFound, "", map[string]string{
				"Location": "/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service=https%3A%2F%2Fjw.gdou.edu.cn%2Fsso%2Fjziotlogin",
			}, nil, ""), nil
		case path == "/authserver/reAuthCheck/reAuthLoginView.do":
			return respWith(r, http.StatusOK, "text/html", nil, nil, reAuthHTML), nil
		case path == "/authserver/dynamicCode/getDynamicCodeByReauth.do":
			return respWith(r, http.StatusOK, "application/json", nil, nil, `{"res":"wechat_success","returnMessage":"企业微信验证码已发送","codeTime":120}`), nil
		case path == "/authserver/reAuthCheck/reAuthSubmit.do":
			raw, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(raw))
			if vals.Get("dynamicCode") != "888888" {
				return respWith(r, http.StatusOK, "application/json", nil, nil, `{"code":"reAuth_failed","msg":"验证码错误"}`), nil
			}
			mu.Lock()
			mfaDone = true
			mu.Unlock()
			return respWith(r, http.StatusOK, "application/json", nil, nil, `{"code":"reAuth_success"}`), nil
		case path == "/sso/jziotlogin":
			return respWith(r, http.StatusFound, "", map[string]string{"Location": "/xtgl/index_initMenu.html"}, []*http.Cookie{
				{Name: "JSESSIONID", Value: "JW_VALID", Path: "/"},
			}, ""), nil
		case path == "/xtgl/index_initMenu.html":
			if strings.Contains(cookie, "JSESSIONID=JW_VALID") {
				return respWith(r, http.StatusOK, "text/html", nil, nil, `<html><title>教学管理信息服务平台</title></html>`), nil
			}
			return respWith(r, http.StatusFound, "", map[string]string{"Location": "/xtgl/login_slogin.html"}, nil, ""), nil
		case path == "/xtgl/login_slogin.html":
			return respWith(r, http.StatusOK, "text/html", nil, nil, loginHTML), nil
		case path == "/cjcx/cjcx_cxXsgrcj.html":
			if !strings.Contains(cookie, "JSESSIONID=JW_VALID") {
				return respWith(r, http.StatusFound, "", map[string]string{"Location": "/xtgl/login_slogin.html"}, nil, ""), nil
			}
			return respWith(r, http.StatusOK, "application/json", nil, nil, `{"totalCount":1,"totalPage":1,"currentPage":1,"items":[{"kch":"CS1","kcmc":"算法","cj":"95","jd":"4.5","xf":"3","jxb_id":"J1"}]}`), nil
		case path == "/cjcx/cjcx_cxCjxqGjh.html":
			if !strings.Contains(cookie, "JSESSIONID=JW_VALID") {
				return respWith(r, http.StatusOK, "text/html", nil, nil, loginHTML), nil
			}
			return respWith(r, http.StatusOK, "text/html", nil, nil, `课程名称：<span class="red2">算法</span><table><tr><td>期末</td><td>100%</td><td>95</td></tr></table>`), nil
		case path == "/kwgl/kscx_cxXsksxxIndex.html":
			if !strings.Contains(cookie, "JSESSIONID=JW_VALID") {
				return respWith(r, http.StatusOK, "text/html", nil, nil, loginHTML), nil
			}
			return respWith(r, http.StatusOK, "application/json", nil, nil, `{"totalCount":1,"totalPage":1,"currentPage":1,"items":[{"kch":"CS1","kcmc":"算法","kssj":"2026-07-08(14:30-16:30)","cdmc":"钟海楼0201"}]}`), nil
		}
		return respWith(r, http.StatusNotFound, "text/plain", nil, nil, "not found: "+path), nil
	})

	srv := newTestServer(t, rt)

	// 1. 发起登录 -> need_mfa
	rec, body := doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/login", map[string]any{
		"username": "202311701234",
		"password": "secret",
	})
	if rec.Code != http.StatusOK || body["code"] != "OK" {
		t.Fatalf("login failed: %d %+v", rec.Code, body)
	}
	data := body["data"].(map[string]any)
	if data["status"] != "need_mfa" || data["login_token"] == "" {
		t.Fatalf("expected need_mfa, got %+v", data)
	}
	loginToken := data["login_token"].(string)

	// 2. 发送企微验证码
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/mfa/send", map[string]any{
		"login_token": loginToken,
		"method":      "wechat",
	})
	if rec.Code != http.StatusOK || body["code"] != "OK" {
		t.Fatalf("mfa/send failed: %d %+v", rec.Code, body)
	}

	// 3. 错码校验 -> 422 且不销毁 login_token
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/mfa/verify", map[string]any{
		"login_token": loginToken,
		"code":        "000000",
	})
	if rec.Code != http.StatusUnprocessableEntity || body["code"] != "JWXT_VERIFICATION_FAILED" {
		t.Fatalf("expected 422 on bad code, got %d %+v", rec.Code, body)
	}

	// 4. 正确验证码 -> 200 success，返回 cookie + device_fingerprint
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/mfa/verify", map[string]any{
		"login_token": loginToken,
		"code":        "888888",
	})
	if rec.Code != http.StatusOK || body["code"] != "OK" {
		t.Fatalf("mfa/verify failed: %d %+v", rec.Code, body)
	}
	verifyData := body["data"].(map[string]any)
	cookie := verifyData["cookie"].(string)
	if verifyData["status"] != "success" || !strings.Contains(cookie, "JSESSIONID=JW_VALID") || verifyData["device_fingerprint"] == "" {
		t.Fatalf("unexpected verify payload: %+v", verifyData)
	}

	// 5. login_token 已消耗，禁止复用
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/mfa/verify", map[string]any{
		"login_token": loginToken,
		"code":        "888888",
	})
	if rec.Code != http.StatusUnauthorized || body["code"] != "SESSION_EXPIRED" {
		t.Fatalf("expected 401 SESSION_EXPIRED for consumed token, got %d %+v", rec.Code, body)
	}

	// 6. 校验成绩、成绩明细、考试接口
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/grades", map[string]any{
		"cookie":        cookie,
		"academic_year": "2025-2026",
		"term":          "3",
	})
	if rec.Code != http.StatusOK || body["code"] != "OK" {
		t.Fatalf("grades failed: %d %+v", rec.Code, body)
	}
	items := body["data"].(map[string]any)["items"].([]any)
	firstRaw := items[0].(map[string]any)["raw"].(map[string]any)
	if firstRaw["jxb_id"] != "J1" {
		t.Fatalf("expected raw.jxb_id=J1, got %+v", firstRaw)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/grade-detail", map[string]any{
		"cookie": cookie,
		"query":  map[string]string{"jxb_id": "J1"},
	})
	if rec.Code != http.StatusOK || body["data"].(map[string]any)["course_name"] != "算法" {
		t.Fatalf("grade-detail failed: %d %+v", rec.Code, body)
	}

	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/exams", map[string]any{
		"cookie":        cookie,
		"academic_year": "2025-2026",
		"term":          "3",
	})
	if rec.Code != http.StatusOK || len(body["data"].(map[string]any)["items"].([]any)) != 1 {
		t.Fatalf("exams failed: %d %+v", rec.Code, body)
	}

	// 7. 过期 Cookie 查询必须返回 401 SESSION_EXPIRED 以触发前端自动重登
	rec, body = doJSON(t, srv.Handler, http.MethodPost, "/api/v1/jwxt/grades", map[string]any{
		"cookie":        "JSESSIONID=EXPIRED",
		"academic_year": "2025-2026",
		"term":          "3",
	})
	if rec.Code != http.StatusUnauthorized || body["code"] != "SESSION_EXPIRED" {
		t.Fatalf("expected 401 SESSION_EXPIRED, got %d %+v", rec.Code, body)
	}
}

func TestAuthTxStoreTTLAndCapacity(t *testing.T) {
	store := NewAuthTxStore(40*time.Millisecond, 2)
	defer store.Close()

	t1, err := store.PutMFA(&jwxt.MfaTransaction{Username: "u1"})
	if err != nil {
		t.Fatalf("PutMFA 1 failed: %v", err)
	}
	if _, err := store.PutCaptcha(&jwxt.CaptchaTransaction{Username: "u2"}); err != nil {
		t.Fatalf("PutCaptcha 2 failed: %v", err)
	}
	if _, err := store.PutMFA(&jwxt.MfaTransaction{Username: "u3"}); err != errStoreFull {
		t.Fatalf("expected errStoreFull, got %v", err)
	}

	time.Sleep(60 * time.Millisecond)
	if _, _, err := store.AcquireMFA(t1); err != errTokenNotFound {
		t.Fatalf("expected expired token error, got %v", err)
	}
	if _, err := store.PutMFA(&jwxt.MfaTransaction{Username: "u4"}); err != nil {
		t.Fatalf("expected capacity reclaimed after expiry, got %v", err)
	}
}
