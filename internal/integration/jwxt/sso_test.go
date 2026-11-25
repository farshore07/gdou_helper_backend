package jwxt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func makeResponse(req *http.Request, status int, headers map[string]string, cookies []*http.Cookie, body string) *http.Response {
	h := make(http.Header)
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

const sampleLoginHTML = `<!doctype html><html><body>
<form id="pwdFromId" action="/authserver/login" method="post">
  <input id="pwdEncryptSalt" type="hidden" value="1234567890abcdef" />
  <input name="execution" type="hidden" value="e1s1" />
  <input name="lt" type="hidden" value="LT-1" />
  <input name="cllt" type="hidden" value="userNameLogin" />
  <input name="dllt" type="hidden" value="generalLogin" />
  <input name="_eventId" type="hidden" value="submit" />
</form>
</body></html>`

const sampleReAuthHTML = `<!doctype html><html><body>
<script>
var reAuthParams = {
  service: "https:\/\/wfw.gdou.edu.cn\/",
  isMultifactor: "true",
  reAuthType: "4",
  reAuthUserId: "202311701234",
  isSleepAccount: "0"
};
</script>
<div id="4">企业微信</div><div id="3">手机动态码</div>
</body></html>`

func TestDetectNetworkMode(t *testing.T) {
	cExt := NewClient(ClientOptions{
		AccessMode: NetworkModeAuto,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "https://wfw.gdou.edu.cn/https://jw.gdou.edu.cn",
			}, nil, ""), nil
		}),
	})
	if got := cExt.ResolveNetworkMode(context.Background(), NetworkModeAuto); got != NetworkModeExternal {
		t.Fatalf("expected external, got %s", got)
	}

	cCampus := NewClient(ClientOptions{
		AccessMode: NetworkModeAuto,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "https://jw.gdou.edu.cn/sso/jziotlogin",
			}, nil, ""), nil
		}),
	})
	if got := cCampus.ResolveNetworkMode(context.Background(), NetworkModeAuto); got != NetworkModeCampus {
		t.Fatalf("expected campus, got %s", got)
	}
}

func TestExternalWfwFullFlowCaptchaMfaAndQueries(t *testing.T) {
	var (
		mfaVerified    bool
		wfwActivated   bool
		jwEntered      bool
		switchedToSMS  bool
		lastSkipTmp    string
		seenBfp        string
		gradeDetailHit bool
	)

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		host := r.URL.Hostname()
		path := r.URL.Path
		q := r.URL.Query()
		cookie := r.Header.Get("Cookie")

		if host == "jw.gdou.edu.cn" {
			t.Fatalf("校外模式不应直连 jw.gdou.edu.cn: %s", r.URL.String())
		}

		switch {
		case host == "authserver.gdou.edu.cn" && path == "/authserver/login" && r.Method == http.MethodGet:
			if q.Get("service") != "https://wfw.gdou.edu.cn/" {
				t.Fatalf("unexpected external service: %q", q.Get("service"))
			}
			if mfaVerified {
				return makeResponse(r, http.StatusFound, map[string]string{
					"Location": "https://wfw.gdou.edu.cn/?ticket=ST-WFW-1",
				}, nil, ""), nil
			}
			return makeResponse(r, http.StatusOK, nil, []*http.Cookie{
				{Name: "JSESSIONID", Value: "CAS1", Path: "/authserver"},
			}, sampleLoginHTML), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/bfp/info":
			seenBfp = q.Get("bfp")
			return makeResponse(r, http.StatusOK, nil, []*http.Cookie{
				{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: seenBfp, Path: "/", Secure: true},
			}, ""), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/checkNeedCaptcha.htl":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"isNeed":true}`), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/getCaptcha.htl":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "image/jpeg"}, nil, "\xff\xd8\xffFAKEJPG"), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/login" && r.Method == http.MethodPost:
			rawBody, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(rawBody))
			if vals.Get("captcha") != "ABCD" {
				return makeResponse(r, http.StatusOK, nil, nil, `<span id="showErrorTip">验证码错误</span>`+sampleLoginHTML), nil
			}
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service=https%3A%2F%2Fwfw.gdou.edu.cn%2F",
			}, nil, ""), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/reAuthCheck/reAuthLoginView.do":
			return makeResponse(r, http.StatusOK, nil, nil, sampleReAuthHTML), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/reAuthCheck/changeReAuthType.do":
			rawBody, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(rawBody))
			if vals.Get("reAuthType") == "3" {
				switchedToSMS = true
			}
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"code":"1","data":{"reAuthType":"3"}}`), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/dynamicCode/getDynamicCodeByReauth.do":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"res":"success","returnMessage":"短信已发送至","mobile":"138****0000","codeTime":60}`), nil

		case host == "authserver.gdou.edu.cn" && path == "/authserver/reAuthCheck/reAuthSubmit.do":
			rawBody, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(rawBody))
			lastSkipTmp = vals.Get("skipTmpReAuth")
			if vals.Get("dynamicCode") != "654321" {
				return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"code":"reAuth_failed","msg":"动态码错误"}`), nil
			}
			mfaVerified = true
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"code":"reAuth_success","msg":"认证成功"}`), nil

		case host == "wfw.gdou.edu.cn" && path == "/" && q.Get("ticket") != "":
			wfwActivated = true
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "https://wfw.gdou.edu.cn/",
			}, []*http.Cookie{
				{Name: "WFWSESSID", Value: "WFW_ACTIVE_1", Path: "/"},
			}, ""), nil

		case host == "wfw.gdou.edu.cn" && path == "/":
			return makeResponse(r, http.StatusOK, nil, []*http.Cookie{
				{Name: "urlss", Value: "https://file.gdou.edu.cn/", Path: "/"},
			}, `<html><title>文件管理</title></html>`), nil

		case host == "wfw.gdou.edu.cn" && path == "/https://jw.gdou.edu.cn":
			if !strings.Contains(cookie, "WFWSESSID=WFW_ACTIVE_1") {
				return makeResponse(r, http.StatusOK, nil, nil, sampleLoginHTML), nil
			}
			jwEntered = true
			return makeResponse(r, http.StatusOK, nil, []*http.Cookie{
				{Name: "urlss", Value: "https://jw.gdou.edu.cn", Path: "/"},
				{Name: "urlss_jw", Value: "https://jw.gdou.edu.cn", Path: "/"},
			}, `<script>window.location = "/xtgl/dl_loginForward.html?language=";</script>`), nil

		case host == "wfw.gdou.edu.cn" && path == "/xtgl/dl_loginForward.html":
			return makeResponse(r, http.StatusOK, nil, nil, `<html><title>教学管理信息服务平台</title></html>`), nil

		case host == "wfw.gdou.edu.cn" && path == "/xtgl/index_initMenu.html":
			if strings.Contains(cookie, "WFWSESSID=WFW_ACTIVE_1") {
				return makeResponse(r, http.StatusOK, nil, nil, `<html><title>教学管理信息服务平台</title></html>`), nil
			}
			return makeResponse(r, http.StatusOK, nil, nil, sampleLoginHTML), nil

		case host == "wfw.gdou.edu.cn" && path == "/kbcx/xskbcx_cxXsgrkb.html":
			if !strings.Contains(cookie, "WFWSESSID=WFW_ACTIVE_1") {
				return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "text/html"}, nil, sampleLoginHTML), nil
			}
			payload, _ := json.Marshal(map[string]any{
				"xsxx": map[string]any{"XM": "测试"},
				"kbList": []any{
					map[string]any{"kch": "CS101", "kcmc": "计算机网络", "xqj": "2", "jc": "3-4节", "zcd": "1-16周"},
				},
			})
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, string(payload)), nil

		case host == "wfw.gdou.edu.cn" && path == "/jzgl/skxxMobile_cxRsdjc.html":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `[{"jcmc":"1","qssj":"08:10","jssj":"08:55"}]`), nil

		case host == "wfw.gdou.edu.cn" && path == "/kbcx/xskbcxMobile_cxXsKb.html":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{"zs":1,"rqazcList":[{"xqj":1,"xqjmc":"星期一","rq":"2026-03-02"}]}`), nil

		case host == "wfw.gdou.edu.cn" && path == "/cjcx/cjcx_cxCjxqGjh.html":
			gradeDetailHit = true
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "text/html"}, nil,
				`课程名称：<span class="red2">计算机网络</span><table><thead><tr><th>成绩分项</th><th>成绩分项比例</th><th>成绩</th></tr></thead><tbody><tr><td>平时</td><td>30%</td><td>98</td></tr></tbody></table>`), nil
		}

		return makeResponse(r, http.StatusNotFound, nil, nil, "unexpected: "+r.URL.String()), nil
	})

	client := NewClient(ClientOptions{
		AccessMode: NetworkModeExternal,
		Timeout:    5 * time.Second,
		Transport:  transport,
	})

	ctx := context.Background()
	step1, err := client.BeginLogin(ctx, BeginLoginInput{
		Username:    "202311701234",
		Password:    "Pass@123",
		NetworkMode: NetworkModeExternal,
	})
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}
	if step1.Status != "need_captcha" || step1.CaptchaTx == nil || len(step1.CaptchaTx.ImageBytes) == 0 {
		t.Fatalf("expected need_captcha, got %+v", step1)
	}
	if seenBfp == "" || step1.DeviceFingerprint != seenBfp {
		t.Fatalf("expected bfp to be registered, got %q", step1.DeviceFingerprint)
	}

	step2, err := client.CompleteCaptchaLogin(ctx, step1.CaptchaTx, "202311701234", "Pass@123", "ABCD")
	if err != nil {
		t.Fatalf("CompleteCaptchaLogin failed: %v", err)
	}
	if step2.Status != "need_mfa" || step2.MfaTx == nil {
		t.Fatalf("expected need_mfa, got %+v", step2)
	}

	sendRes, err := client.SendMFACode(ctx, step2.MfaTx, MfaMethodSMS)
	if err != nil {
		t.Fatalf("SendMFACode failed: %v", err)
	}
	if !switchedToSMS || sendRes.Method != MfaMethodSMS || sendRes.Countdown != 60 {
		t.Fatalf("unexpected SendMFACode result: %+v", sendRes)
	}

	// 输错一次动态码应返回 ErrorVerificationFailed
	if _, err := client.VerifyMFACode(ctx, step2.MfaTx, "000000", true); err == nil {
		t.Fatalf("expected error on wrong MFA code")
	}

	// 输对动态码完成登录并提取 wfw 业务 Cookie
	step3, err := client.VerifyMFACode(ctx, step2.MfaTx, "654321", true)
	if err != nil {
		t.Fatalf("VerifyMFACode failed: %v", err)
	}
	if step3.Status != "success" || !wfwActivated || !jwEntered || lastSkipTmp != "true" {
		t.Fatalf("unexpected final login outcome: %+v", step3)
	}
	if !strings.Contains(step3.Cookie, "WFWSESSID=WFW_ACTIVE_1") {
		t.Fatalf("expected WFWSESSID in returned cookie, got %q", step3.Cookie)
	}

	// 无状态 Cookie 校验与业务查询
	valRes, err := client.ValidateSession(ctx, step3.Cookie)
	if err != nil || valRes.Status != "success" {
		t.Fatalf("ValidateSession failed: (%+v, %v)", valRes, err)
	}

	kb, err := client.QueryTimetable(ctx, step3.Cookie, "2025-2026", "12", nil)
	if err != nil || len(kb.Courses) != 1 || kb.SemesterStartDate != "2026-03-02" || len(kb.PeriodTimes) != 1 {
		t.Fatalf("QueryTimetable failed: (%+v, %v)", kb, err)
	}

	detail, err := client.QueryGradeDetail(ctx, step3.Cookie, url.Values{"jxb_id": {"J1"}})
	if err != nil || !gradeDetailHit || detail.CourseName != "计算机网络" || len(detail.Items) != 1 {
		t.Fatalf("QueryGradeDetail failed: (%+v, %v)", detail, err)
	}

	// 过期 Cookie 遇到 200 登录页 HTML 时应返回 ErrSessionExpired
	if _, err := client.QueryTimetable(ctx, "WFWSESSID=EXPIRED", "2025-2026", "12", nil); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestExternalModeOnCampusFallsBackToCampus(t *testing.T) {
	var (
		validateHitDirect  bool
		timetableHitDirect bool
	)

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		host := r.URL.Hostname()
		path := r.URL.Path
		q := r.URL.Query()
		cookie := r.Header.Get("Cookie")

		switch {
		case host == "authserver.gdou.edu.cn" && path == "/authserver/login":
			if q.Get("service") == "https://wfw.gdou.edu.cn/" {
				return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://wfw.gdou.edu.cn/?ticket=ST-WFW"}, nil, ""), nil
			}
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://jw.gdou.edu.cn/sso/jziotlogin?ticket=ST-JW"}, nil, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/" && q.Get("ticket") != "":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://wfw.gdou.edu.cn/"}, []*http.Cookie{
				{Name: "WFWSESSID", Value: "WFW1", Path: "/"},
			}, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/":
			return makeResponse(r, http.StatusOK, nil, nil, `<html><title>文件管理</title></html>`), nil
		case host == "wfw.gdou.edu.cn" && path == "/https://jw.gdou.edu.cn":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://jw.gdou.edu.cn/"}, nil, ""), nil
		case host == "wfw.gdou.edu.cn" && (path == "/xtgl/index_initMenu.html" || path == "/kbcx/xskbcx_cxXsgrkb.html"):
			t.Fatalf("校内回退签发的 Cookie 不应再路由回 wfw: %s", r.URL.String())
		case host == "jw.gdou.edu.cn" && path == "/":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "/xtgl/login_slogin.html"}, nil, ""), nil
		case host == "jw.gdou.edu.cn" && path == "/xtgl/login_slogin.html":
			return makeResponse(r, http.StatusOK, nil, nil, sampleLoginHTML), nil
		case host == "jw.gdou.edu.cn" && path == "/sso/jziotlogin":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "/xtgl/index_initMenu.html"}, []*http.Cookie{
				{Name: "JSESSIONID", Value: "JW_DIRECT", Path: "/"},
			}, ""), nil
		case host == "jw.gdou.edu.cn" && path == "/xtgl/index_initMenu.html":
			if strings.Contains(cookie, "JSESSIONID=JW_DIRECT") {
				validateHitDirect = true
			}
			return makeResponse(r, http.StatusOK, nil, nil, `<html><title>教学管理信息服务平台</title></html>`), nil
		case host == "jw.gdou.edu.cn" && path == "/kbcx/xskbcx_cxXsgrkb.html":
			if !strings.Contains(cookie, "JSESSIONID=JW_DIRECT") {
				return makeResponse(r, http.StatusFound, map[string]string{"Location": "/xtgl/login_slogin.html"}, nil, ""), nil
			}
			timetableHitDirect = true
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil,
				`{"xsxx":{"XM":"校内同学"},"kbList":[{"kch":"CS301","kcmc":"编译原理","xqj":"3","jc":"1-2节","zcd":"1-16周"}]}`), nil
		case host == "jw.gdou.edu.cn" && path == "/jzgl/skxxMobile_cxRsdjc.html":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `[]`), nil
		case host == "jw.gdou.edu.cn" && path == "/kbcx/xskbcxMobile_cxXsKb.html":
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "application/json"}, nil, `{}`), nil
		}
		return makeResponse(r, http.StatusNotFound, nil, nil, "unexpected: "+r.URL.String()), nil
	})

	client := NewClient(ClientOptions{
		AccessMode: NetworkModeExternal,
		Transport:  transport,
	})
	ctx := context.Background()
	out, err := client.BeginLogin(ctx, BeginLoginInput{
		Username:    "202311701234",
		Password:    "pwd",
		NetworkMode: NetworkModeExternal,
	})
	if err != nil {
		t.Fatalf("BeginLogin fallback failed: %v", err)
	}
	if out.Status != "success" || out.NetworkMode != NetworkModeCampus || !strings.Contains(out.Cookie, "JSESSIONID=JW_DIRECT") {
		t.Fatalf("expected campus fallback success, got %+v", out)
	}

	// 即使客户端配置为强制 external，使用回退签发的校内 Cookie 校验和查课表也应继续走校内直连
	valRes, err := client.ValidateSession(ctx, out.Cookie)
	if err != nil || valRes.Status != "success" || !validateHitDirect {
		t.Fatalf("expected direct ValidateSession success, got (%+v, %v, hit=%v)", valRes, err, validateHitDirect)
	}

	kb, err := client.QueryTimetable(ctx, out.Cookie, "2025-2026", "12", nil)
	if err != nil || !timetableHitDirect || len(kb.Courses) != 1 || kb.Courses[0].CourseName != "编译原理" {
		t.Fatalf("expected direct QueryTimetable success, got (%+v, %v, hit=%v)", kb, err, timetableHitDirect)
	}
}

func TestValidateSessionDistinguishesExpiredUpstreamAndTimeout(t *testing.T) {
	ctx := context.Background()

	// 1. 明确跳转到登录页 -> ErrSessionExpired
	expiredClient := NewClient(ClientOptions{
		AccessMode: NetworkModeCampus,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/xtgl/index_initMenu.html" {
				return makeResponse(r, http.StatusFound, map[string]string{"Location": "/xtgl/login_slogin.html"}, nil, ""), nil
			}
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "text/html"}, nil, sampleLoginHTML), nil
		}),
	})
	if _, err := expiredClient.ValidateSession(ctx, "JSESSIONID=OLD"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	// 2. 上游 503 维护 -> ErrorUpstreamError
	upstreamClient := NewClient(ClientOptions{
		AccessMode: NetworkModeCampus,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return makeResponse(r, http.StatusServiceUnavailable, map[string]string{"Content-Type": "text/html"}, nil, "<html>系统维护中</html>"), nil
		}),
	})
	_, err := upstreamClient.ValidateSession(ctx, "JSESSIONID=VALID")
	var jwErr *Error
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamError {
		t.Fatalf("expected ErrorUpstreamError for 503, got %v", err)
	}

	// 3. 上游超时 -> ErrorUpstreamTimeout
	timeoutClient := NewClient(ClientOptions{
		AccessMode: NetworkModeCampus,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		}),
	})
	_, err = timeoutClient.ValidateSession(ctx, "JSESSIONID=VALID")
	jwErr = nil
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamTimeout {
		t.Fatalf("expected ErrorUpstreamTimeout, got %v", err)
	}

	// 4. 教务主页返回 HTTP 200 但正文为"系统维护中" -> ErrorUpstreamError（绝不误判为登录成功）
	maint200Client := NewClient(ClientOptions{
		AccessMode: NetworkModeCampus,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "text/html"}, nil, "<html><body>系统维护中</body></html>"), nil
		}),
	})
	_, err = maint200Client.ValidateSession(ctx, "JSESSIONID=VALID")
	jwErr = nil
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamError {
		t.Fatalf("expected ErrorUpstreamError for 200 maintenance page, got %v", err)
	}

	// 5. 教务主页先 302 到统一认证，认证服务随后返回 503 -> ErrorUpstreamError（不误报 SESSION_EXPIRED）
	redirectAuth503Client := NewClient(ClientOptions{
		AccessMode: NetworkModeCampus,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Hostname() == "jw.gdou.edu.cn" {
				return makeResponse(r, http.StatusFound, map[string]string{
					"Location": "https://authserver.gdou.edu.cn/authserver/login?service=https%3A%2F%2Fjw.gdou.edu.cn%2Fsso%2Fjziotlogin",
				}, nil, ""), nil
			}
			return makeResponse(r, http.StatusServiceUnavailable, map[string]string{"Content-Type": "text/html"}, nil, "<html>认证服务维护中</html>"), nil
		}),
	})
	_, err = redirectAuth503Client.ValidateSession(ctx, "JSESSIONID=VALID")
	jwErr = nil
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamError {
		t.Fatalf("expected ErrorUpstreamError for 302->authserver 503, got %v", err)
	}
}

func TestWfw502TargetUnreachableMessage(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		host := r.URL.Hostname()
		path := r.URL.Path
		q := r.URL.Query()
		switch {
		case host == "authserver.gdou.edu.cn" && path == "/authserver/login":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://wfw.gdou.edu.cn/?ticket=ST-1"}, nil, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/" && q.Get("ticket") != "":
			return makeResponse(r, http.StatusFound, map[string]string{"Location": "https://wfw.gdou.edu.cn/"}, []*http.Cookie{
				{Name: "WFWSESSID", Value: "WFW1", Path: "/"},
			}, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/":
			return makeResponse(r, http.StatusOK, nil, nil, `<html><title>文件管理</title></html>`), nil
		case host == "wfw.gdou.edu.cn" && path == "/https://jw.gdou.edu.cn":
			return makeResponse(r, http.StatusBadGateway, map[string]string{"Content-Type": "text/html"}, nil,
				`<html><head><title>无法访问目标服务器</title></head><body><h2>无法访问目标服务器</h2><p>教务或统一认证系统短暂繁忙，请稍候重试。</p></body></html>`), nil
		}
		return makeResponse(r, http.StatusNotFound, nil, nil, "unexpected"), nil
	})

	client := NewClient(ClientOptions{
		AccessMode: NetworkModeExternal,
		Transport:  transport,
	})
	_, err := client.BeginLogin(context.Background(), BeginLoginInput{
		Username:    "202311701234",
		Password:    "pwd",
		NetworkMode: NetworkModeExternal,
	})
	var jwErr *Error
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamError {
		t.Fatalf("expected ErrorUpstreamError, got %v", err)
	}
	if !strings.Contains(jwErr.Error(), "校外网关（wfw）当前无法连接校内教务系统") {
		t.Fatalf("unexpected error message: %q", jwErr.Error())
	}
}

func TestWfwJwEntryLoginPageReturnsUpstreamError(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		host := r.URL.Hostname()
		path := r.URL.Path
		q := r.URL.Query()
		switch {
		case host == "authserver.gdou.edu.cn" && path == "/authserver/login":
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "https://wfw.gdou.edu.cn/?ticket=ST-WFW",
			}, nil, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/" && q.Get("ticket") == "ST-WFW":
			return makeResponse(r, http.StatusFound, map[string]string{
				"Location": "https://wfw.gdou.edu.cn/",
			}, []*http.Cookie{
				{Name: "WFWSESSID", Value: "WFW-ACTIVE", Path: "/"},
			}, ""), nil
		case host == "wfw.gdou.edu.cn" && path == "/":
			return makeResponse(r, http.StatusOK, nil, nil, `<html><title>文件管理</title></html>`), nil
		case host == "wfw.gdou.edu.cn" && path == "/https://jw.gdou.edu.cn":
			// 复现学校 wfw 网关异常：已激活 WFWSESSID 但教务入口直接以 200 返回统一身份认证登录页
			return makeResponse(r, http.StatusOK, map[string]string{"Content-Type": "text/html"}, []*http.Cookie{
				{Name: "urlss", Value: "https://jw.gdou.edu.cn", Path: "/"},
				{Name: "urlss_jw", Value: "https://jw.gdou.edu.cn", Path: "/"},
			}, `<html><head><title>统一身份认证平台</title></head><body><form id="pwdFromId"><input id="pwdEncryptSalt" value="1234567890abcdef"/></form></body></html>`), nil
		}
		return makeResponse(r, http.StatusNotFound, nil, nil, "unexpected: "+r.URL.String()), nil
	})

	client := NewClient(ClientOptions{
		AccessMode: NetworkModeExternal,
		Transport:  transport,
	})
	_, err := client.BeginLogin(context.Background(), BeginLoginInput{
		Username:    "202311701234",
		Password:    "pwd",
		NetworkMode: NetworkModeExternal,
	})
	var jwErr *Error
	if !errors.As(err, &jwErr) || jwErr.Kind != ErrorUpstreamError {
		t.Fatalf("expected ErrorUpstreamError, got %v", err)
	}
	if !strings.Contains(jwErr.Error(), "校外网关（wfw）当前单点登录异常") {
		t.Fatalf("unexpected error message: %q", jwErr.Error())
	}
}
