package jwxt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"
)

const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	maxResponseBytes = 4 << 20
	maxRedirectHops  = 15
)

var (
	reAuthBlockRE = regexp.MustCompile(`(?s)reAuthParams\s*=\s*\{(.*?)\}`)
	reMethod4RE   = regexp.MustCompile(`id=["']4["']`)
	reMethod3RE   = regexp.MustCompile(`id=["']3["']`)
	htmlTitleRE   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	htmlStyleRE   = regexp.MustCompile(`(?is)<(style|script)[^>]*>.*?</(style|script)>`)
)

type httpResult struct {
	StatusCode    int
	FinalURL      string
	Headers       http.Header
	Body          []byte
	RedirectChain []string
}

// BeginLoginInput 描述一次登录请求的参数。
type BeginLoginInput struct {
	Username          string
	Password          string
	DeviceFingerprint string
	NetworkMode       NetworkMode
	CaptchaCode       string
}

func (c *Client) newIsolatedHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: c.transport,
		Jar:       jar,
		Timeout:   c.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// ResolveNetworkMode 解析本次操作应使用的具体网络模式（campus 或 external）。
func (c *Client) ResolveNetworkMode(ctx context.Context, requested NetworkMode) NetworkMode {
	mode := requested
	if mode == "" {
		mode = c.defaultMode
	}
	if mode != NetworkModeAuto {
		return mode
	}

	c.modeMu.RLock()
	cached := c.detectedMode
	checkedAt := c.detectedAt
	c.modeMu.RUnlock()
	if cached != "" && time.Since(checkedAt) < 5*time.Minute {
		return cached
	}

	detected := c.detectNetworkMode(ctx)
	c.modeMu.Lock()
	c.detectedMode = detected
	c.detectedAt = time.Now()
	c.modeMu.Unlock()
	return detected
}

func (c *Client) detectNetworkMode(ctx context.Context) NetworkMode {
	detectCtx, cancel := context.WithTimeout(ctx, minDuration(c.timeout, 8*time.Second))
	defer cancel()

	req, err := http.NewRequestWithContext(detectCtx, http.MethodGet, c.netcheckURL, nil)
	if err != nil {
		return NetworkModeExternal
	}
	req.Header.Set("User-Agent", c.userAgent)

	client := &http.Client{
		Transport: c.transport,
		Timeout:   minDuration(c.timeout, 8*time.Second),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return NetworkModeExternal
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(location, strings.ToLower(c.wfwHost)) {
		return NetworkModeExternal
	}
	if strings.Contains(location, strings.ToLower(c.jwxtHost)) {
		return NetworkModeCampus
	}
	return NetworkModeExternal
}

// BeginLogin 发起纯 HTTP CAS 登录（支持校内直连 / 校外 wfw、设备指纹、图形验证码、两步 MFA）。
func (c *Client) BeginLogin(ctx context.Context, input BeginLoginInput) (LoginOutcome, error) {
	httpClient, err := c.newIsolatedHTTPClient()
	if err != nil {
		return LoginOutcome{}, newError(ErrorUpstreamError, "初始化登录会话失败", err)
	}

	mode := c.ResolveNetworkMode(ctx, input.NetworkMode)
	if mode == NetworkModeExternal {
		c.clearWfwCookies(httpClient.Jar)
	}

	bfp := strings.ToUpper(strings.TrimSpace(input.DeviceFingerprint))
	if bfp != "" {
		c.injectBrowserFingerprint(httpClient.Jar, bfp)
	}

	serviceURL := c.serviceURLFor(mode)
	loginURL := c.authserverLoginURLFor(mode)

	loginPage, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, loginURL, nil, nil, mode)
	if err != nil {
		return LoginOutcome{}, classifyTransportError(err)
	}

	if c.isSSOLanding(loginPage, mode) {
		return c.finalizeLogin(ctx, httpClient, loginPage, mode, "已通过统一身份认证静默登录")
	}

	if isReAuthURL(loginPage.FinalURL) || isReAuthPageHTML(string(loginPage.Body)) {
		tx := c.buildMfaTransaction(string(loginPage.Body), loginPage.FinalURL, input.Username, serviceURL, mode, httpClient)
		return LoginOutcome{
			Status:            "need_mfa",
			Message:           "统一身份认证平台要求二次验证",
			URL:               loginPage.FinalURL,
			DeviceFingerprint: tx.DeviceFingerprint,
			NetworkMode:       mode,
			MfaTx:             tx,
		}, nil
	}

	form, err := parsePwdLoginForm(string(loginPage.Body), loginPage.FinalURL, serviceURL)
	if err != nil {
		return LoginOutcome{}, newError(ErrorUpstreamError, err.Error(), err)
	}

	bfp = c.ensureBrowserFingerprint(ctx, httpClient, bfp)

	captchaCode := strings.TrimSpace(input.CaptchaCode)
	if captchaCode == "" {
		needCaptcha := c.checkNeedCaptcha(ctx, httpClient, input.Username)
		if needCaptcha {
			imgBytes, contentType, err := c.fetchCaptchaImage(ctx, httpClient)
			if err != nil {
				return LoginOutcome{}, classifyTransportError(err)
			}
			return LoginOutcome{
				Status:            "need_captcha",
				Message:           "页面要求输入图形验证码",
				URL:               loginPage.FinalURL,
				DeviceFingerprint: bfp,
				NetworkMode:       mode,
				CaptchaTx: &CaptchaTransaction{
					Username:          input.Username,
					NetworkMode:       mode,
					DeviceFingerprint: bfp,
					Form:              form,
					ImageBytes:        imgBytes,
					ContentType:       contentType,
					HTTPClient:        httpClient,
				},
			}, nil
		}
	}

	return c.submitLoginForm(ctx, httpClient, input.Username, input.Password, captchaCode, form, serviceURL, mode)
}

// CompleteCaptchaLogin 在已创建的图形验证码事务会话上提交密码与用户手动输入的验证码。
func (c *Client) CompleteCaptchaLogin(
	ctx context.Context,
	tx *CaptchaTransaction,
	username, password, captchaCode string,
) (LoginOutcome, error) {
	if tx == nil || tx.HTTPClient == nil {
		return LoginOutcome{}, newError(ErrorVerificationFailed, "图形验证码会话已失效，请重新登录", nil)
	}
	if tx.Username != "" && username != "" && tx.Username != username {
		return LoginOutcome{}, newError(ErrorVerificationFailed, "图形验证码与当前学号不匹配，请重新登录", nil)
	}
	code := strings.TrimSpace(captchaCode)
	if code == "" {
		return LoginOutcome{}, newError(ErrorVerificationFailed, "图形验证码不能为空", nil)
	}
	serviceURL := c.serviceURLFor(tx.NetworkMode)
	return c.submitLoginForm(ctx, tx.HTTPClient, tx.Username, password, code, tx.Form, serviceURL, tx.NetworkMode)
}

func (c *Client) submitLoginForm(
	ctx context.Context,
	httpClient *http.Client,
	username, password, captchaCode string,
	form PwdLoginForm,
	serviceURL string,
	mode NetworkMode,
) (LoginOutcome, error) {
	encrypted, err := EncryptPassword(password, form.PwdEncryptSalt)
	if err != nil {
		return LoginOutcome{}, newError(ErrorUpstreamError, "密码加密失败: "+err.Error(), err)
	}

	payload := url.Values{
		"username":  {username},
		"password":  {encrypted},
		"captcha":   {captchaCode},
		"_eventId":  {form.EventID},
		"cllt":      {form.CLLT},
		"dllt":      {form.DLLT},
		"lt":        {form.LT},
		"execution": {form.Execution},
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Referer":      form.PageURL,
	}

	resp, err := c.doRequestFollowing(ctx, httpClient, http.MethodPost, form.ActionURL, []byte(payload.Encode()), headers, mode)
	if err != nil {
		return LoginOutcome{}, classifyTransportError(err)
	}

	if c.isSSOLanding(resp, mode) {
		return c.finalizeLogin(ctx, httpClient, resp, mode, "已获得教务系统登录态")
	}

	bodyStr := string(resp.Body)
	if isReAuthURL(resp.FinalURL) || isReAuthPageHTML(bodyStr) {
		tx := c.buildMfaTransaction(bodyStr, resp.FinalURL, username, serviceURL, mode, httpClient)
		return LoginOutcome{
			Status:            "need_mfa",
			Message:           "统一身份认证平台要求二次验证",
			URL:               resp.FinalURL,
			DeviceFingerprint: tx.DeviceFingerprint,
			NetworkMode:       mode,
			MfaTx:             tx,
		}, nil
	}

	errMsg := extractLoginError(bodyStr)
	if isCaptchaErrorMessage(errMsg) {
		// 验证码错误时刷新表单与验证码图片，便于客户端直接重试
		if refreshedForm, parseErr := parsePwdLoginForm(bodyStr, resp.FinalURL, serviceURL); parseErr == nil {
			if imgBytes, contentType, fetchErr := c.fetchCaptchaImage(ctx, httpClient); fetchErr == nil {
				bfp := c.readBrowserFingerprint(httpClient.Jar)
				return LoginOutcome{
					Status:            "need_captcha",
					Message:           errMsg,
					URL:               resp.FinalURL,
					DeviceFingerprint: bfp,
					NetworkMode:       mode,
					CaptchaTx: &CaptchaTransaction{
						Username:          username,
						NetworkMode:       mode,
						DeviceFingerprint: bfp,
						Form:              refreshedForm,
						ImageBytes:        imgBytes,
						ContentType:       contentType,
						HTTPClient:        httpClient,
					},
				}, nil
			}
		}
		return LoginOutcome{}, newError(ErrorVerificationFailed, errMsg, nil)
	}

	if isInvalidCredentialsMessage(errMsg) {
		return LoginOutcome{}, newError(ErrorInvalidCredentials, errMsg, nil)
	}

	if errMsg != "" {
		return LoginOutcome{}, newError(ErrorVerificationFailed, errMsg, nil)
	}

	return LoginOutcome{}, newError(ErrorUpstreamError, "未能完成教务系统登录，请稍后重试", nil)
}

// SendMFACode 切换（如需）并发送企业微信或短信二次验证码。
func (c *Client) SendMFACode(ctx context.Context, tx *MfaTransaction, method MfaMethod) (MfaSendResult, error) {
	if tx == nil || tx.HTTPClient == nil {
		return MfaSendResult{}, newError(ErrorSessionExpired, "二次验证会话已失效，请重新登录", nil)
	}

	if err := c.switchMFAMethod(ctx, tx, method); err != nil {
		return MfaSendResult{}, err
	}

	activeMethod := MfaMethodFromReAuthType(tx.ReAuthType)
	codeTypeName := activeMethod.AuthCodeTypeName()
	if codeTypeName == "" {
		return MfaSendResult{}, newError(ErrorVerificationFailed, "不支持的二次验证方式编码: "+tx.ReAuthType, nil)
	}

	form := url.Values{
		"userName":         {tx.ReAuthUserID},
		"authCodeTypeName": {codeTypeName},
	}
	endpoint := c.authserverEndpoint("dynamicCode/getDynamicCodeByReauth.do")
	body, err := c.postJSONForm(ctx, tx.HTTPClient, endpoint, form)
	if err != nil {
		return MfaSendResult{}, err
	}

	resCode := textField(body, "res")
	msg := textField(body, "returnMessage")
	if mobile := textField(body, "mobile"); mobile != "" {
		msg += mobile
	}

	switch resCode {
	case "success":
		if msg == "" {
			msg = "短信验证码已发送"
		}
		return MfaSendResult{
			Method:    activeMethod,
			Countdown: defaultInt(intField(body, "codeTime"), 120),
			Message:   msg,
		}, nil
	case "wechat_success":
		if msg == "" {
			msg = "企业微信验证码已发送"
		}
		return MfaSendResult{
			Method:    activeMethod,
			Countdown: defaultInt(intField(body, "codeTime"), 120),
			Message:   msg,
		}, nil
	case "code_time_fail":
		if msg == "" {
			msg = "验证码发送过于频繁，请稍后再试"
		}
		return MfaSendResult{}, newError(ErrorVerificationFailed, msg, nil)
	default:
		if msg == "" {
			msg = "发送" + activeMethod.Label() + "失败"
		}
		return MfaSendResult{}, newError(ErrorVerificationFailed, msg, nil)
	}
}

func (c *Client) switchMFAMethod(ctx context.Context, tx *MfaTransaction, method MfaMethod) error {
	if method == "" || method == MfaMethodAuto {
		if tx.ReAuthType == "3" || tx.ReAuthType == "4" {
			tx.DefaultMethod = MfaMethodFromReAuthType(tx.ReAuthType)
			return nil
		}
		for _, candidate := range []MfaMethod{MfaMethodWechat, MfaMethodSMS} {
			if err := c.switchMFAMethod(ctx, tx, candidate); err == nil {
				return nil
			}
		}
		return newError(ErrorVerificationFailed, "当前账号无可用的企业微信或短信二次验证方式", nil)
	}

	targetType := method.ReAuthType()
	if tx.ReAuthType == targetType {
		tx.DefaultMethod = method
		return nil
	}

	form := url.Values{
		"isMultifactor": {tx.IsMultifactor},
		"reAuthType":    {targetType},
		"service":       {tx.Service},
	}
	endpoint := c.authserverEndpoint("reAuthCheck/changeReAuthType.do")
	body, err := c.postJSONForm(ctx, tx.HTTPClient, endpoint, form)
	if err != nil {
		return err
	}

	if textField(body, "code") == "1" {
		newType := targetType
		if dataMap, ok := body["data"].(map[string]any); ok {
			if parsed := textField(dataMap, "reAuthType"); parsed != "" {
				newType = parsed
			}
		}
		tx.ReAuthType = newType
		tx.DefaultMethod = MfaMethodFromReAuthType(newType)
		return nil
	}

	msg := textField(body, "message", "msg")
	if msg == "" {
		msg = "切换到" + method.Label() + "失败"
	}
	return newError(ErrorVerificationFailed, msg, nil)
}

// VerifyMFACode 提交二次验证码并换取教务系统登录态。
func (c *Client) VerifyMFACode(ctx context.Context, tx *MfaTransaction, code string, trustDevice bool) (LoginOutcome, error) {
	if tx == nil || tx.HTTPClient == nil {
		return LoginOutcome{}, newError(ErrorSessionExpired, "二次验证会话已失效，请重新登录", nil)
	}
	cleanCode := strings.TrimSpace(code)
	if cleanCode == "" {
		return LoginOutcome{}, newError(ErrorVerificationFailed, "二次验证码不能为空", nil)
	}

	skipTmp := "false"
	if trustDevice {
		skipTmp = "true"
	}

	form := url.Values{
		"service":       {tx.Service},
		"reAuthType":    {tx.ReAuthType},
		"isMultifactor": {tx.IsMultifactor},
		"password":      {""},
		"dynamicCode":   {cleanCode},
		"uuid":          {""},
		"answer1":       {""},
		"answer2":       {""},
		"otpCode":       {""},
		"skipTmpReAuth": {skipTmp},
	}

	endpoint := c.authserverEndpoint("reAuthCheck/reAuthSubmit.do")
	body, err := c.postJSONForm(ctx, tx.HTTPClient, endpoint, form)
	if err != nil {
		return LoginOutcome{}, err
	}

	codeVal := textField(body, "code")
	switch codeVal {
	case "reAuth_failed":
		msg := textField(body, "msg")
		if msg == "" {
			msg = "二次验证码校验失败"
		}
		return LoginOutcome{}, newError(ErrorVerificationFailed, msg, nil)
	case "reAuth_unauthorized":
		msg := textField(body, "msg")
		if msg == "" {
			msg = "二次验证会话已失效，请重新登录"
		}
		return LoginOutcome{}, newError(ErrorSessionExpired, msg, nil)
	}

	if tx.NetworkMode == NetworkModeExternal {
		c.clearWfwCookies(tx.HTTPClient.Jar)
	}

	nextURL := c.authserverEndpoint("login")
	if tx.Service != "" {
		nextURL += "?service=" + url.QueryEscape(tx.Service)
	}

	finalResp, err := c.doRequestFollowing(ctx, tx.HTTPClient, http.MethodGet, nextURL, nil, nil, tx.NetworkMode)
	if err != nil {
		return LoginOutcome{}, classifyTransportError(err)
	}

	if c.isSSOLanding(finalResp, tx.NetworkMode) {
		return c.finalizeLogin(ctx, tx.HTTPClient, finalResp, tx.NetworkMode, "二次验证通过，已获得教务系统登录态")
	}

	errMsg := extractLoginError(string(finalResp.Body))
	if errMsg == "" {
		errMsg = "二次验证后未能完成教务系统跳转"
	}
	return LoginOutcome{}, newError(ErrorVerificationFailed, errMsg, nil)
}

func (c *Client) finalizeLogin(
	ctx context.Context,
	httpClient *http.Client,
	landing httpResult,
	mode NetworkMode,
	successMsg string,
) (LoginOutcome, error) {
	finalResp, err := c.completeExternalJwxtSSO(ctx, httpClient, landing, mode)
	if err != nil {
		return LoginOutcome{}, err
	}

	activeMode := c.modeFromURL(finalResp.FinalURL, mode)
	cookieStr := c.extractBusinessCookie(httpClient.Jar, activeMode)
	if cookieStr == "" {
		return LoginOutcome{}, newError(ErrorUpstreamError, "登录成功但未能提取有效教务 Cookie", nil)
	}

	return LoginOutcome{
		Status:            "success",
		Message:           successMsg,
		URL:               finalResp.FinalURL,
		Cookie:            cookieStr,
		DeviceFingerprint: c.readBrowserFingerprint(httpClient.Jar),
		NetworkMode:       activeMode,
	}, nil
}

func (c *Client) completeExternalJwxtSSO(
	ctx context.Context,
	httpClient *http.Client,
	landing httpResult,
	mode NetworkMode,
) (httpResult, error) {
	if mode != NetworkModeExternal {
		return landing, nil
	}

	landedHost := hostOf(landing.FinalURL)
	if strings.EqualFold(landedHost, c.jwxtHost) &&
		isJwxtAuthenticatedResponse(landing.StatusCode, landing.FinalURL, string(landing.Body), c.jwxtHost, c.authserverHost, c.wfwHost) {
		return landing, nil
	}

	jwEntry, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, c.wfwJwxtInitURL(), nil, nil, mode)
	if err != nil {
		return httpResult{}, classifyTransportError(err)
	}

	entryHost := hostOf(jwEntry.FinalURL)
	// 校园网环境强制使用 external 时，wfw 可能 302 弹回直连 jw.gdou.edu.cn，利用已有 CASTGC 直连换票
	if strings.EqualFold(entryHost, c.jwxtHost) {
		if isJwxtAuthenticatedResponse(jwEntry.StatusCode, jwEntry.FinalURL, string(jwEntry.Body), c.jwxtHost, c.authserverHost, c.wfwHost) {
			return jwEntry, nil
		}
		campusResp, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, c.authserverLoginURLFor(NetworkModeCampus), nil, nil, NetworkModeCampus)
		if err != nil {
			return httpResult{}, classifyTransportError(err)
		}
		if isJwxtAuthenticatedResponse(campusResp.StatusCode, campusResp.FinalURL, string(campusResp.Body), c.jwxtHost, c.authserverHost, c.wfwHost) {
			return campusResp, nil
		}
		return httpResult{}, newError(ErrorVerificationFailed, "校外网关跳转至直连教务系统后未能完成换票", nil)
	}

	if isWfwGatewayResponse(jwEntry.StatusCode, jwEntry.FinalURL, string(jwEntry.Body), c.wfwHost, c.authserverHost) {
		forwardResp, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, c.wfwJwxtForwardURL(), nil, nil, mode)
		if err != nil {
			return httpResult{}, classifyTransportError(err)
		}
		if isJwxtAuthenticatedResponse(forwardResp.StatusCode, forwardResp.FinalURL, string(forwardResp.Body), c.jwxtHost, c.authserverHost, c.wfwHost) {
			return forwardResp, nil
		}
		fwdBody := string(forwardResp.Body)
		slog.Warn("wfw 教务主页初始化失败",
			"stage", "wfw_jwxt_forward",
			"landing_url", redactURL(landing.FinalURL),
			"jw_entry_status", jwEntry.StatusCode,
			"forward_status", forwardResp.StatusCode,
			"forward_url", redactURL(forwardResp.FinalURL),
			"forward_len", len(forwardResp.Body),
			"forward_title", extractHTMLTitle(fwdBody),
			"forward_text", htmlSnippet(fwdBody, 200),
			"forward_is_login", isLoginPageHTML(fwdBody),
			"wfw_cookies", c.cookieNamesForHost(httpClient.Jar, c.wfwBaseURL),
		)
		if forwardResp.StatusCode >= http.StatusInternalServerError && forwardResp.StatusCode < 600 {
			return httpResult{}, newError(ErrorUpstreamError, extractUpstreamErrorMessage(forwardResp.StatusCode, fwdBody, true), nil)
		}
		return httpResult{}, newError(ErrorVerificationFailed, "已进入校外网关教务入口，但初始化教务主页失败", nil)
	}

	jwBody := string(jwEntry.Body)
	slog.Warn("wfw 激活后换取教务登录态失败",
		"stage", "wfw_to_jwxt",
		"landing_status", landing.StatusCode,
		"landing_url", redactURL(landing.FinalURL),
		"landing_chain", redactURLs(landing.RedirectChain),
		"landing_title", extractHTMLTitle(string(landing.Body)),
		"jw_entry_status", jwEntry.StatusCode,
		"jw_entry_url", redactURL(jwEntry.FinalURL),
		"jw_entry_chain", redactURLs(jwEntry.RedirectChain),
		"jw_entry_len", len(jwEntry.Body),
		"jw_entry_title", extractHTMLTitle(jwBody),
		"jw_entry_text", htmlSnippet(jwBody, 200),
		"jw_entry_is_login", isLoginPageHTML(jwBody),
		"jw_entry_is_reauth", isReAuthPageHTML(jwBody),
		"wfw_cookies", c.cookieNamesForHost(httpClient.Jar, c.wfwBaseURL),
	)
	if jwEntry.StatusCode >= http.StatusInternalServerError && jwEntry.StatusCode < 600 {
		return httpResult{}, newError(ErrorUpstreamError, extractUpstreamErrorMessage(jwEntry.StatusCode, jwBody, true), nil)
	}
	if jwEntry.StatusCode == http.StatusOK && isLoginPageHTML(jwBody) {
		return httpResult{}, newError(ErrorUpstreamError, "校外网关（wfw）当前单点登录异常，暂时无法进入教务系统，请稍后重试", nil)
	}
	return httpResult{}, newError(ErrorVerificationFailed, "已激活校外网关，但换取教务系统登录态失败", nil)
}

func (c *Client) doRequestFollowing(
	ctx context.Context,
	httpClient *http.Client,
	method, rawURL string,
	body []byte,
	headers map[string]string,
	mode NetworkMode,
) (httpResult, error) {
	currentMethod := strings.ToUpper(method)
	effectiveMode := mode
	currentURL := RewriteURLForMode(rawURL, effectiveMode, c.jwxtBaseURL, c.authserverBaseURL, c.wfwBaseURL)
	currentBody := body
	chain := make([]string, 0, 4)

	for hop := 0; hop <= maxRedirectHops; hop++ {
		chain = append(chain, currentURL)

		var bodyReader io.Reader
		if len(currentBody) > 0 {
			bodyReader = bytes.NewReader(currentBody)
		}
		req, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, bodyReader)
		if err != nil {
			return httpResult{}, err
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		for k, v := range headers {
			if hop == 0 || !strings.EqualFold(k, "Content-Type") {
				req.Header.Set(k, v)
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return httpResult{}, err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		resp.Body.Close()
		if readErr != nil {
			return httpResult{}, readErr
		}

		location := resp.Header.Get("Location")
		if !isRedirectStatus(resp.StatusCode) || location == "" {
			return httpResult{
				StatusCode:    resp.StatusCode,
				FinalURL:      currentURL,
				Headers:       resp.Header.Clone(),
				Body:          data,
				RedirectChain: chain,
			}, nil
		}

		joined := resolveRelativeURL(currentURL, location)
		chain = append(chain, joined)

		if effectiveMode == NetworkModeExternal &&
			strings.EqualFold(hostOf(currentURL), c.wfwHost) &&
			strings.EqualFold(hostOf(joined), c.jwxtHost) {
			effectiveMode = NetworkModeCampus
		}

		nextURL := RewriteURLForMode(joined, effectiveMode, c.jwxtBaseURL, c.authserverBaseURL, c.wfwBaseURL)
		if nextURL == currentURL && joined != currentURL {
			nextURL = NormalizeAuthserverURL(joined, c.authserverBaseURL)
		}
		currentURL = nextURL

		if (resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusSeeOther) && currentMethod == http.MethodPost {
			currentMethod = http.MethodGet
			currentBody = nil
		}
	}

	return httpResult{}, fmt.Errorf("重定向次数超过限制 (%d)", maxRedirectHops)
}

func (c *Client) postJSONForm(ctx context.Context, httpClient *http.Client, endpoint string, data url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, newError(ErrorUpstreamError, "构造请求失败", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, classifyTransportError(err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, newError(ErrorUpstreamError, "读取统一身份认证响应失败", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, newError(ErrorUpstreamError, "统一身份认证接口返回了非 JSON 内容", err)
	}
	return out, nil
}

func (c *Client) checkNeedCaptcha(ctx context.Context, httpClient *http.Client, username string) bool {
	endpoint := c.authserverEndpoint("checkNeedCaptcha.htl") + "?username=" + url.QueryEscape(username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json, */*")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var body struct {
		IsNeed any `json:"isNeed"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return false
	}
	switch v := body.IsNeed.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func (c *Client) fetchCaptchaImage(ctx context.Context, httpClient *http.Client) ([]byte, string, error) {
	endpoint := c.authserverEndpoint("getCaptcha.htl")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	img, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK || len(img) == 0 {
		return nil, "", fmt.Errorf("获取图形验证码图片失败: HTTP %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "image/jpeg"
	}
	return img, ct, nil
}

func (c *Client) injectBrowserFingerprint(jar http.CookieJar, bfp string) {
	if jar == nil || bfp == "" {
		return
	}
	u, err := url.Parse(c.authserverBaseURL)
	if err != nil {
		return
	}
	u.Path = "/"
	jar.SetCookies(u, []*http.Cookie{
		{
			Name:     "MULTIFACTOR_BROWSER_FINGERPRINT",
			Value:    bfp,
			Path:     "/",
			Secure:   strings.EqualFold(u.Scheme, "https"),
			HttpOnly: true,
		},
	})
}

func (c *Client) readBrowserFingerprint(jar http.CookieJar) string {
	if jar == nil {
		return ""
	}
	u, err := url.Parse(c.authserverBaseURL)
	if err != nil {
		return ""
	}
	u.Path = "/"
	for _, cookie := range jar.Cookies(u) {
		if cookie.Name == "MULTIFACTOR_BROWSER_FINGERPRINT" && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

func (c *Client) ensureBrowserFingerprint(ctx context.Context, httpClient *http.Client, preferred string) string {
	if existing := c.readBrowserFingerprint(httpClient.Jar); existing != "" {
		return existing
	}
	bfp := strings.ToUpper(strings.TrimSpace(preferred))
	if bfp == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err == nil {
			bfp = strings.ToUpper(hex.EncodeToString(raw[:]))
		}
	}
	if bfp == "" {
		return ""
	}

	endpoint := c.authserverEndpoint("bfp/info") + "?bfp=" + url.QueryEscape(bfp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err == nil {
		req.Header.Set("User-Agent", c.userAgent)
		if resp, doErr := httpClient.Do(req); doErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
	}
	if registered := c.readBrowserFingerprint(httpClient.Jar); registered != "" {
		return registered
	}
	return bfp
}

func (c *Client) clearWfwCookies(jar http.CookieJar) {
	if jar == nil {
		return
	}
	for _, path := range []string{"/", "/authserver"} {
		u, err := url.Parse(strings.TrimRight(c.wfwBaseURL, "/") + path)
		if err != nil {
			continue
		}
		existing := jar.Cookies(u)
		if len(existing) == 0 {
			continue
		}
		expired := make([]*http.Cookie, 0, len(existing))
		for _, ck := range existing {
			expired = append(expired, &http.Cookie{
				Name:   ck.Name,
				Value:  "",
				Path:   path,
				MaxAge: -1,
			})
		}
		jar.SetCookies(u, expired)
	}
}

func (c *Client) extractBusinessCookie(jar http.CookieJar, mode NetworkMode) string {
	if jar == nil {
		return ""
	}
	var target string
	if mode == NetworkModeExternal {
		target = strings.TrimRight(c.wfwBaseURL, "/") + "/xtgl/index_initMenu.html"
	} else {
		target = strings.TrimRight(c.jwxtBaseURL, "/") + "/xtgl/index_initMenu.html"
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	cookies := jar.Cookies(u)
	parts := make([]string, 0, len(cookies))
	seen := make(map[string]struct{}, len(cookies))
	for _, ck := range cookies {
		if ck.Name == "" || strings.EqualFold(ck.Name, "rememberMe") {
			continue
		}
		if _, dup := seen[ck.Name]; dup {
			continue
		}
		seen[ck.Name] = struct{}{}
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

func (c *Client) isSSOLanding(resp httpResult, mode NetworkMode) bool {
	body := string(resp.Body)
	if isJwxtAuthenticatedResponse(resp.StatusCode, resp.FinalURL, body, c.jwxtHost, c.authserverHost, c.wfwHost) {
		return true
	}
	if mode == NetworkModeExternal && isWfwGatewayResponse(resp.StatusCode, resp.FinalURL, body, c.wfwHost, c.authserverHost) {
		return true
	}
	return false
}

func (c *Client) modeFromURL(rawURL string, fallback NetworkMode) NetworkMode {
	host := hostOf(rawURL)
	if strings.EqualFold(host, c.jwxtHost) {
		return NetworkModeCampus
	}
	if strings.EqualFold(host, c.wfwHost) {
		return NetworkModeExternal
	}
	return fallback
}

func (c *Client) buildMfaTransaction(
	body, pageURL, username, defaultService string,
	mode NetworkMode,
	httpClient *http.Client,
) *MfaTransaction {
	parsedURL, _ := url.Parse(pageURL)
	var pageQuery url.Values
	if parsedURL != nil {
		pageQuery = parsedURL.Query()
	}

	rawService := extractJSParam(body, "service")
	if rawService == "" && pageQuery != nil {
		rawService = pageQuery.Get("service")
	}
	if rawService == "" {
		rawService = defaultService
	}
	service := normalizeServiceURL(rawService)
	if !strings.HasPrefix(service, "http://") && !strings.HasPrefix(service, "https://") {
		if pageQuery != nil && pageQuery.Get("service") != "" {
			service = normalizeServiceURL(pageQuery.Get("service"))
		}
	}
	if !strings.HasPrefix(service, "http://") && !strings.HasPrefix(service, "https://") {
		service = defaultService
	}

	isMultifactor := extractJSParam(body, "isMultifactor")
	if isMultifactor == "" && pageQuery != nil {
		isMultifactor = pageQuery.Get("isMultifactor")
	}
	if isMultifactor == "" {
		isMultifactor = "true"
	}

	reAuthType := extractJSParam(body, "reAuthType")
	if reAuthType == "" {
		reAuthType = "4"
	}
	reAuthUserID := extractJSParam(body, "reAuthUserId")
	if reAuthUserID == "" {
		reAuthUserID = username
	}
	isSleep := extractJSParam(body, "isSleepAccount")
	if isSleep == "" {
		isSleep = "0"
	}

	available := make([]MfaMethod, 0, 2)
	if reAuthType == "4" || reMethod4RE.MatchString(body) || strings.Contains(body, "企业微信") {
		available = append(available, MfaMethodWechat)
	}
	if reAuthType == "3" || reMethod3RE.MatchString(body) || strings.Contains(body, "手机动态码") || strings.Contains(body, "短信验证码") {
		available = append(available, MfaMethodSMS)
	}
	if len(available) == 0 {
		available = append(available, MfaMethodWechat, MfaMethodSMS)
	}

	return &MfaTransaction{
		Username:          username,
		ReAuthUserID:      reAuthUserID,
		ReAuthType:        reAuthType,
		DefaultMethod:     MfaMethodFromReAuthType(reAuthType),
		AvailableMethods:  available,
		Service:           service,
		IsMultifactor:     isMultifactor,
		IsSleepAccount:    isSleep,
		NetworkMode:       mode,
		DeviceFingerprint: c.readBrowserFingerprint(httpClient.Jar),
		HTTPClient:        httpClient,
	}
}

func parsePwdLoginForm(body, pageURL, defaultService string) (PwdLoginForm, error) {
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return PwdLoginForm{}, fmt.Errorf("解析登录页 HTML 失败: %w", err)
	}

	var forms []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "form") {
			forms = append(forms, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	var targetForm *xhtml.Node
	for _, f := range forms {
		if nodeAttr(f, "id") == "pwdFromId" {
			targetForm = f
			break
		}
	}
	if targetForm == nil {
		for _, f := range forms {
			if formHasInputID(f, "pwdEncryptSalt") {
				targetForm = f
				break
			}
		}
	}
	if targetForm == nil {
		return PwdLoginForm{}, errors.New("登录页中未找到账号密码登录表单 (#pwdFromId)")
	}

	byName := make(map[string]string)
	byID := make(map[string]string)
	var collectInputs func(*xhtml.Node)
	collectInputs = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "input") {
			name := nodeAttr(n, "name")
			id := nodeAttr(n, "id")
			val := nodeAttr(n, "value")
			if name != "" {
				if _, exists := byName[name]; !exists {
					byName[name] = val
				}
			}
			if id != "" {
				if _, exists := byID[id]; !exists {
					byID[id] = val
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			collectInputs(child)
		}
	}
	collectInputs(targetForm)

	rawAction := nodeAttr(targetForm, "action")
	if rawAction == "" {
		rawAction = "/authserver/login"
	}
	actionURL := resolveRelativeURL(pageURL, rawAction)

	service := defaultService
	if parsedPage, err := url.Parse(pageURL); err == nil {
		if s := parsedPage.Query().Get("service"); s != "" {
			service = s
		}
	}
	actionURL = ensureServiceQuery(actionURL, service)

	salt := byID["pwdEncryptSalt"]
	if salt == "" {
		salt = byName["pwdEncryptSalt"]
	}
	execution := byName["execution"]
	if execution == "" {
		execution = byID["execution"]
	}
	cllt := byName["cllt"]
	if cllt == "" {
		cllt = "userNameLogin"
	}
	dllt := byName["dllt"]
	if dllt == "" {
		dllt = "generalLogin"
	}
	eventID := byName["_eventId"]
	if eventID == "" {
		eventID = "submit"
	}

	return PwdLoginForm{
		ActionURL:      actionURL,
		PageURL:        pageURL,
		PwdEncryptSalt: salt,
		Execution:      execution,
		LT:             byName["lt"],
		CLLT:           cllt,
		DLLT:           dllt,
		EventID:        eventID,
	}, nil
}

func nodeAttr(n *xhtml.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func formHasInputID(root *xhtml.Node, targetID string) bool {
	found := false
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if found {
			return
		}
		if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "input") && nodeAttr(n, "id") == targetID {
			found = true
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return found
}

func ensureServiceQuery(actionURL, service string) string {
	if service == "" {
		return actionURL
	}
	parsed, err := url.Parse(actionURL)
	if err != nil {
		return actionURL
	}
	q := parsed.Query()
	if q.Get("service") != "" {
		return actionURL
	}
	q.Set("service", service)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func unescapeJSString(raw string) string {
	if raw == "" {
		return ""
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(raw, `\'`, `'`), `"`, `\"`)
	var decoded string
	if err := json.Unmarshal([]byte(`"`+escaped+`"`), &decoded); err == nil {
		return strings.TrimSpace(decoded)
	}
	return strings.TrimSpace(html.UnescapeString(strings.ReplaceAll(raw, `\/`, "/")))
}

func normalizeServiceURL(raw string) string {
	cleaned := unescapeJSString(raw)
	lower := strings.ToLower(cleaned)
	if strings.HasPrefix(lower, "http%3a") || strings.HasPrefix(lower, "https%3a") {
		if unescaped, err := url.QueryUnescape(cleaned); err == nil {
			cleaned = unescaped
		}
	}
	return cleaned
}

func extractJSParam(body, key string) string {
	quotedKey := regexp.QuoteMeta(key)
	directPatterns := []string{
		`reAuthParams\.` + quotedKey + `\s*=\s*['"]([^'"]*)['"]`,
		`reAuthParams\[['"]` + quotedKey + `['"]\]\s*=\s*['"]([^'"]*)['"]`,
	}
	for _, pat := range directPatterns {
		if m := regexp.MustCompile(pat).FindStringSubmatch(body); len(m) > 1 {
			return unescapeJSString(m[1])
		}
	}

	if blockMatch := reAuthBlockRE.FindStringSubmatch(body); len(blockMatch) > 1 {
		blockPat := `['"]?` + quotedKey + `['"]?\s*:\s*['"]([^'"]*)['"]`
		if m := regexp.MustCompile(blockPat).FindStringSubmatch(blockMatch[1]); len(m) > 1 {
			return unescapeJSString(m[1])
		}
	}

	fallbackPatterns := []string{
		`['"]?` + quotedKey + `['"]?\s*:\s*['"]([^'"]*)['"]`,
		`<input[^>]*\b(?:id|name)=['"]` + quotedKey + `['"][^>]*\bvalue=['"]([^'"]*)['"]`,
		`<input[^>]*\bvalue=['"]([^'"]*)['"][^>]*\b(?:id|name)=['"]` + quotedKey + `['"]`,
	}
	for _, pat := range fallbackPatterns {
		if m := regexp.MustCompile(pat).FindStringSubmatch(body); len(m) > 1 {
			return unescapeJSString(m[1])
		}
	}
	return ""
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func resolveRelativeURL(baseRaw, refRaw string) string {
	base, err1 := url.Parse(baseRaw)
	ref, err2 := url.Parse(refRaw)
	if err1 != nil || err2 != nil {
		return refRaw
	}
	return base.ResolveReference(ref).String()
}

func hostOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func extractHTMLTitle(body string) string {
	m := htmlTitleRE.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(htmlTagStripRE.ReplaceAllString(m[1], "")))
}

func htmlSnippet(body string, maxRunes int) string {
	noStyle := htmlStyleRE.ReplaceAllString(body, " ")
	cleaned := cleanHTMLText(noStyle)
	runes := []rune(cleaned)
	if len(runes) <= maxRunes {
		return cleaned
	}
	return string(runes[:maxRunes])
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for _, sensitive := range []string{"ticket", "bfp", "dynamicCode", "password"} {
		if q.Has(sensitive) {
			q.Set(sensitive, "***")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func redactURLs(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, redactURL(u))
	}
	return out
}

func (c *Client) cookieNamesForHost(jar http.CookieJar, baseURL string) []string {
	if jar == nil {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return nil
	}
	cookies := jar.Cookies(u)
	names := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		if ck.Name != "" {
			names = append(names, ck.Name)
		}
	}
	return names
}
