package jwxt

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	authPathMarkers = []string{
		"/xtgl/login_slogin.html",
		"/sso/jziotlogin",
		"/authserver/login",
		"/authserver/reauthcheck/",
	}
	reAuthPathMarkers = []string{
		"/reauthcheck/reauthloginview.do",
		"/reauthcheck/",
	}
	invalidCredentialMarkers = []string{
		"用户名或密码",
		"用户名或者密码",
		"密码有误",
		"密码错误",
		"账号或密码",
		"帐号或密码",
		"账号不存在",
		"帐号不存在",
		"账户被锁定",
		"账号已锁定",
		"invalid password",
		"bad credentials",
	}
	captchaErrorMarkers = []string{
		"验证码错误",
		"无效的验证码",
		"请输入验证码",
		"验证码已过期",
	}
	jwxtHomeMarkers = []string{
		"教学管理信息服务平台",
		"index_initmenu",
		"dl_loginforward",
		"gnmkdm=",
		"sessionuserkey",
		"cdnav",
		"jwglxt",
	}
	errorElementPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<span[^>]*\bid=["']showErrorTip["'][^>]*>(.*?)</span>`),
		regexp.MustCompile(`(?is)<div[^>]*\bid=["']msg["'][^>]*>(.*?)</div>`),
		regexp.MustCompile(`(?is)<span[^>]*\bclass=["'][^"']*form-error[^"']*["'][^>]*>(.*?)</span>`),
	}
	loginFormActionRE = regexp.MustCompile(`(?i)<form[^>]*\baction=["'][^"']*login_slogin`)
)

// NormalizeAuthserverURL 将 authserver 的 HTTP 地址升级为 HTTPS，防止丢失 Secure Cookie。
func NormalizeAuthserverURL(rawURL, authserverBaseURL string) string {
	if rawURL == "" {
		return rawURL
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	base, err := url.Parse(authserverBaseURL)
	if err != nil {
		return rawURL
	}
	if strings.EqualFold(base.Scheme, "https") &&
		strings.EqualFold(target.Scheme, "http") &&
		target.Hostname() != "" &&
		strings.EqualFold(target.Hostname(), base.Hostname()) {
		target.Scheme = "https"
		return target.String()
	}
	return rawURL
}

// RewriteURLForMode 按校内直连 / 校外 wfw 网关模式重写目标 URL。
func RewriteURLForMode(rawURL string, mode NetworkMode, jwxtBaseURL, authserverBaseURL, wfwBaseURL string) string {
	if rawURL == "" {
		return rawURL
	}
	normalized := NormalizeAuthserverURL(rawURL, authserverBaseURL)
	if mode != NetworkModeExternal {
		return normalized
	}
	wfwParsed, errWfw := url.Parse(strings.TrimRight(wfwBaseURL, "/"))
	jwParsed, errJW := url.Parse(strings.TrimRight(jwxtBaseURL, "/"))
	parsed, errTarget := url.Parse(normalized)
	if errWfw != nil || errJW != nil || errTarget != nil {
		return normalized
	}
	host := strings.ToLower(parsed.Hostname())
	wfwHost := strings.ToLower(wfwParsed.Hostname())
	jwHost := strings.ToLower(jwParsed.Hostname())

	if host == wfwHost {
		if wfwParsed.Scheme != "" {
			parsed.Scheme = wfwParsed.Scheme
		}
		return parsed.String()
	}
	if host == jwHost {
		if wfwParsed.Scheme != "" {
			parsed.Scheme = wfwParsed.Scheme
		}
		parsed.Host = wfwParsed.Host
		return parsed.String()
	}
	return normalized
}

func isReAuthURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, marker := range reAuthPathMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func isAuthURL(rawURL, authserverHost string) bool {
	if rawURL == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if authserverHost != "" && strings.EqualFold(parsed.Hostname(), authserverHost) {
		return true
	}
	path := strings.ToLower(parsed.Path)
	for _, marker := range authPathMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func isLoginPageHTML(body string) bool {
	if body == "" {
		return false
	}
	return strings.Contains(body, `id="pwdFromId"`) ||
		strings.Contains(body, `id='pwdFromId'`) ||
		strings.Contains(body, `id="pwdEncryptSalt"`) ||
		strings.Contains(body, "正在跳转到统一认证") ||
		loginFormActionRE.MatchString(body)
}

func isReAuthPageHTML(body string) bool {
	if body == "" {
		return false
	}
	return strings.Contains(body, "reAuthParams") ||
		strings.Contains(body, "reAuthCheck/reAuthSubmit.do") ||
		strings.Contains(body, "reAuthLoginView")
}

func isJwxtHomeHTML(body string) bool {
	if body == "" {
		return false
	}
	lower := strings.ToLower(body)
	for _, marker := range jwxtHomeMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func extractLoginError(body string) string {
	if body == "" {
		return ""
	}
	for _, pattern := range errorElementPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			text := strings.TrimSpace(html.UnescapeString(htmlTagStripRE.ReplaceAllString(m[1], "")))
			if text != "" {
				return text
			}
		}
	}
	return ""
}

func isCaptchaErrorMessage(msg string) bool {
	lower := strings.ToLower(msg)
	for _, marker := range captchaErrorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isInvalidCredentialsMessage(msg string) bool {
	lower := strings.ToLower(msg)
	for _, marker := range invalidCredentialMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isWfwGatewayResponse(statusCode int, finalURL, body, wfwHost, authserverHost string) bool {
	if statusCode != 200 {
		return false
	}
	parsed, err := url.Parse(finalURL)
	if err != nil {
		return false
	}
	if !strings.EqualFold(parsed.Hostname(), wfwHost) {
		return false
	}
	if isAuthURL(finalURL, authserverHost) {
		return false
	}
	if strings.TrimSpace(body) == "" {
		return false
	}
	if isLoginPageHTML(body) || isReAuthPageHTML(body) {
		return false
	}
	return true
}

func isWfwPortalRoot(statusCode int, finalURL, body, wfwHost, authserverHost string) bool {
	if !isWfwGatewayResponse(statusCode, finalURL, body, wfwHost, authserverHost) {
		return false
	}
	parsed, err := url.Parse(finalURL)
	if err != nil {
		return false
	}
	return parsed.Path == "" || parsed.Path == "/"
}

func isJwxtAuthenticatedResponse(statusCode int, finalURL, body, jwxtHost, authserverHost, wfwHost string) bool {
	if statusCode != 200 {
		return false
	}
	parsed, err := url.Parse(finalURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host != strings.ToLower(jwxtHost) && host != strings.ToLower(wfwHost) {
		return false
	}
	if isAuthURL(finalURL, authserverHost) {
		return false
	}
	if strings.TrimSpace(body) == "" {
		return false
	}
	if isLoginPageHTML(body) || isReAuthPageHTML(body) {
		return false
	}
	if host == strings.ToLower(wfwHost) && (parsed.Path == "" || parsed.Path == "/") {
		return false
	}
	return isJwxtHomeHTML(body)
}

func hasAuthRedirectInChain(chain []string, authserverHost string) bool {
	for _, raw := range chain {
		if isAuthURL(raw, authserverHost) {
			return true
		}
	}
	return false
}

// extractUpstreamErrorMessage 根据上游状态码与页面文本提取面向用户的具体故障说明。
func extractUpstreamErrorMessage(statusCode int, body string, viaWfw bool) string {
	title := extractHTMLTitle(body)
	text := htmlSnippet(body, 260)
	combined := title + " " + text

	if strings.Contains(combined, "无法访问目标服务器") || strings.Contains(combined, "教务或统一认证系统短暂繁忙") {
		return "校外网关（wfw）当前无法连接校内教务系统（教务或统一认证系统繁忙或维护中），请稍后重试"
	}
	if strings.Contains(combined, "系统维护") || strings.Contains(combined, "维护中") || strings.Contains(combined, "暂停服务") {
		return "教务系统当前正在维护中，请稍后重试"
	}

	prefix := "教务系统"
	if viaWfw {
		prefix = "校外网关（wfw）转发教务系统"
	}
	switch statusCode {
	case 502:
		return prefix + "返回 502（目标服务不可达），请稍后重试"
	case 503:
		return prefix + "当前繁忙或维护中（HTTP 503），请稍后重试"
	case 504:
		return prefix + "响应超时（HTTP 504），请稍后重试"
	default:
		if statusCode >= 500 && statusCode < 600 {
			return prefix + "服务异常（HTTP " + strconv.Itoa(statusCode) + "），请稍后重试"
		}
		return prefix + "返回了异常响应，请稍后重试"
	}
}
