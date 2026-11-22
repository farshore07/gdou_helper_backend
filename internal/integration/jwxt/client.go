package jwxt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultJWXTBaseURL       = "https://jw.gdou.edu.cn"
	defaultAuthserverBaseURL = "https://authserver.gdou.edu.cn/authserver"
	defaultWfwBaseURL        = "https://wfw.gdou.edu.cn"
	defaultNetcheckURL       = "https://netcheck.gdou.edu.cn/go.php?code=jw"

	pathHome            = "/xtgl/index_initMenu.html"
	pathSSOService      = "/sso/jziotlogin"
	pathGrade           = "/cjcx/cjcx_cxXsgrcj.html?doType=query&gnmkdm=N305005"
	pathGradeReferer    = "/cjcx/cjcx_cxDgXscj.html?gnmkdm=N305005&layout=default"
	pathGradeDetail     = "/cjcx/cjcx_cxCjxqGjh.html"
	pathTimetable       = "/kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2151"
	pathMobileTimetable = "/kbcx/xskbcxMobile_cxXsKb.html?gnmkdm=N2154"
	pathPeriodTime      = "/jzgl/skxxMobile_cxRsdjc.html?gnmkdm=N2154"
	pathExam            = "/kwgl/kscx_cxXsksxxIndex.html?doType=query&gnmkdm=N358105"
)

// ClientOptions 用于初始化 Client（测试时可替换 Transport 与上游 URL）。
type ClientOptions struct {
	AccessMode        NetworkMode
	Timeout           time.Duration
	Transport         http.RoundTripper
	JWXTBaseURL       string
	AuthserverBaseURL string
	WfwBaseURL        string
	NetcheckURL       string
	UserAgent         string
}

// Client 提供纯 HTTP 的教务统一身份认证与无状态业务查询能力。
type Client struct {
	transport         http.RoundTripper
	timeout           time.Duration
	defaultMode       NetworkMode
	jwxtBaseURL       string
	authserverBaseURL string
	wfwBaseURL        string
	netcheckURL       string
	jwxtHost          string
	authserverHost    string
	wfwHost           string
	userAgent         string

	modeMu       sync.RWMutex
	detectedMode NetworkMode
	detectedAt   time.Time
}

// NewClient 创建教务集成客户端。
func NewClient(opts ClientOptions) *Client {
	transport := opts.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	mode := opts.AccessMode
	if mode == "" {
		mode = NetworkModeAuto
	}
	jwBase := strings.TrimRight(orDefault(opts.JWXTBaseURL, defaultJWXTBaseURL), "/")
	authBase := strings.TrimRight(orDefault(opts.AuthserverBaseURL, defaultAuthserverBaseURL), "/")
	wfwBase := strings.TrimRight(orDefault(opts.WfwBaseURL, defaultWfwBaseURL), "/")
	netcheck := orDefault(opts.NetcheckURL, defaultNetcheckURL)
	ua := orDefault(opts.UserAgent, defaultUserAgent)

	return &Client{
		transport:         transport,
		timeout:           timeout,
		defaultMode:       mode,
		jwxtBaseURL:       jwBase,
		authserverBaseURL: authBase,
		wfwBaseURL:        wfwBase,
		netcheckURL:       netcheck,
		jwxtHost:          hostOf(jwBase),
		authserverHost:    hostOf(authBase),
		wfwHost:           hostOf(wfwBase),
		userAgent:         ua,
	}
}

// DefaultAccessMode 返回配置的默认网络模式。
func (c *Client) DefaultAccessMode() NetworkMode {
	return c.defaultMode
}

func (c *Client) authserverEndpoint(path string) string {
	return c.authserverBaseURL + "/" + strings.TrimLeft(path, "/")
}

func (c *Client) serviceURLFor(mode NetworkMode) string {
	if mode == NetworkModeExternal {
		return c.wfwBaseURL + "/"
	}
	return c.jwxtBaseURL + pathSSOService
}

func (c *Client) authserverLoginURLFor(mode NetworkMode) string {
	return c.authserverEndpoint("login") + "?service=" + url.QueryEscape(c.serviceURLFor(mode))
}

func (c *Client) wfwJwxtInitURL() string {
	return c.wfwBaseURL + "/" + c.jwxtBaseURL
}

func (c *Client) wfwJwxtForwardURL() string {
	return c.wfwBaseURL + "/xtgl/dl_loginForward.html?language="
}

func (c *Client) resolveQueryMode(ctx context.Context, cookie string) NetworkMode {
	if isWfwCookie(cookie) {
		return NetworkModeExternal
	}
	if len(parseCookieHeader(cookie)) > 0 {
		return NetworkModeCampus
	}
	return c.ResolveNetworkMode(ctx, c.defaultMode)
}

func (c *Client) businessBaseURL(mode NetworkMode) string {
	if mode == NetworkModeExternal {
		return c.wfwBaseURL
	}
	return c.jwxtBaseURL
}

// ValidateSession 校验客户端持有的教务 Cookie 是否仍有效。
func (c *Client) ValidateSession(ctx context.Context, cookie string) (AuthResult, error) {
	mode := c.resolveQueryMode(ctx, cookie)
	httpClient, err := c.newCookieHTTPClient(cookie, mode)
	if err != nil {
		return AuthResult{}, newError(ErrorUpstreamError, "初始化查询会话失败", err)
	}

	targetURL := c.businessBaseURL(mode) + pathHome
	res, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, targetURL, nil, nil, mode)
	if err != nil {
		return AuthResult{}, classifyTransportError(err)
	}

	body := string(res.Body)
	// 上游 5xx（含 302 跳转至统一认证后认证服务返回 503）优先归类为上游服务异常，不误报会话过期
	if res.StatusCode >= http.StatusInternalServerError && res.StatusCode < 600 {
		return AuthResult{}, newError(ErrorUpstreamError, fmt.Sprintf("教务系统服务异常: HTTP %d", res.StatusCode), nil)
	}

	if isJwxtAuthenticatedResponse(res.StatusCode, res.FinalURL, body, c.jwxtHost, c.authserverHost, c.wfwHost) {
		return AuthResult{
			Status:  "success",
			Message: "已获得教务系统登录态",
			URL:     res.FinalURL,
		}, nil
	}

	if c.isExpiredBusinessResponse(res, body, false) ||
		isWfwPortalRoot(res.StatusCode, res.FinalURL, body, c.wfwHost, c.authserverHost) {
		return AuthResult{}, ErrSessionExpired
	}

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return AuthResult{}, newError(ErrorUpstreamError, fmt.Sprintf("教务系统服务异常: HTTP %d", res.StatusCode), nil)
	}

	return AuthResult{}, newError(ErrorUpstreamError, "教务系统维护或返回了异常页面", nil)
}

// QueryTimetable 查询个人课表（附带节次时间与学期起始日期，附加信息失败不阻断主课表）。
func (c *Client) QueryTimetable(ctx context.Context, cookie, academicYear, term string, extra map[string]string) (TimetableResult, error) {
	mode := c.resolveQueryMode(ctx, cookie)
	data := url.Values{
		"xnm":    {academicYearCode(academicYear)},
		"xqm":    {term},
		"kzlx":   {"ck"},
		"xsdm":   {""},
		"kclbdm": {""},
		"kclxdm": {""},
	}
	mergeValues(data, extra)

	base := c.businessBaseURL(mode)
	raw, err := c.postBusinessForm(ctx, cookie, mode, base+pathTimetable, base+pathHome, data)
	if err != nil {
		return TimetableResult{}, err
	}

	parsed := parseTimetable(raw)
	if periods := c.queryPeriodTimes(ctx, cookie, mode, academicYear, term, extra); len(periods) > 0 {
		parsed.PeriodTimes = periods
	}
	parsed.SemesterStartDate = c.querySemesterStartDate(ctx, cookie, mode, academicYear, term)
	return parsed, nil
}

func (c *Client) queryPeriodTimes(ctx context.Context, cookie string, mode NetworkMode, academicYear, term string, extra map[string]string) []PeriodTime {
	data := url.Values{
		"xnm":    {academicYearCode(academicYear)},
		"xqm":    {term},
		"xqh_id": {"1"},
	}
	mergeValues(data, extra)
	base := c.businessBaseURL(mode)
	raw, err := c.postBusinessFormValue(ctx, cookie, mode, base+pathPeriodTime, base+pathMobileTimetable, data)
	if err != nil {
		slog.Warn("教务节次时间查询失败，继续返回主课表", "error", err)
		return nil
	}
	return parsePeriodTimes(raw)
}

func (c *Client) querySemesterStartDate(ctx context.Context, cookie string, mode NetworkMode, academicYear, term string) string {
	data := url.Values{
		"xnm":    {academicYearCode(academicYear)},
		"zs":     {"1"},
		"doType": {"app"},
		"xqm":    {term},
		"kblx":   {"1"},
		"xh":     {""},
	}
	base := c.businessBaseURL(mode)
	raw, err := c.postBusinessFormValue(ctx, cookie, mode, base+pathMobileTimetable, base+pathMobileTimetable, data)
	if err != nil {
		slog.Warn("教务学期起始日期查询失败，继续返回主课表", "error", err)
		return ""
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	calendar, err := parseSemesterCalendar(obj)
	if err != nil {
		slog.Warn("教务学期起始日期解析失败，继续返回主课表", "error", err)
		return ""
	}
	return calendar.StartDate
}

// QueryGrades 查询个人成绩分页数据（每条记录保留 raw 字段以支撑前端查成绩明细）。
func (c *Client) QueryGrades(ctx context.Context, cookie, academicYear, term string, extra map[string]string) (PageResult[GradeRecord], error) {
	mode := c.resolveQueryMode(ctx, cookie)
	data := url.Values{
		"xnm":                    {academicYearCode(academicYear)},
		"xqm":                    {term},
		"sfzgcj":                 {""},
		"kcbj":                   {""},
		"pkey":                   {""},
		"_search":                {"false"},
		"nd":                     {strconv.FormatInt(time.Now().UnixMilli(), 10)},
		"queryModel.showCount":   {"50"},
		"queryModel.currentPage": {"1"},
		"queryModel.sortName":    {" "},
		"queryModel.sortOrder":   {"asc"},
		"time":                   {"0"},
	}
	mergeValues(data, extra)

	base := c.businessBaseURL(mode)
	raw, err := c.postBusinessForm(ctx, cookie, mode, base+pathGrade, base+pathGradeReferer, data)
	if err != nil {
		return PageResult[GradeRecord]{}, err
	}
	return parsePage(raw, parseGrade), nil
}

// QueryGradeDetail 查询单科成绩分项明细（如平时/期末占比与分项分）。
func (c *Client) QueryGradeDetail(ctx context.Context, cookie string, query url.Values) (GradeDetail, error) {
	mode := c.resolveQueryMode(ctx, cookie)
	httpClient, err := c.newCookieHTTPClient(cookie, mode)
	if err != nil {
		return GradeDetail{}, newError(ErrorUpstreamError, "初始化查询会话失败", err)
	}

	params := url.Values{}
	for k, vals := range query {
		for _, v := range vals {
			params.Add(k, v)
		}
	}
	params.Set("gnmkdm", "N305005")
	if params.Get("time") == "" {
		params.Set("time", strconv.FormatInt(time.Now().UnixMilli(), 10))
	}

	base := c.businessBaseURL(mode)
	endpoint := base + pathGradeDetail + "?" + params.Encode()
	headers := map[string]string{
		"Referer": base + pathGradeReferer,
	}

	res, err := c.doRequestFollowing(ctx, httpClient, http.MethodGet, endpoint, nil, headers, mode)
	if err != nil {
		return GradeDetail{}, classifyTransportError(err)
	}
	body := string(res.Body)
	if c.isExpiredBusinessResponse(res, body, false) {
		return GradeDetail{}, ErrSessionExpired
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return GradeDetail{}, newError(ErrorUpstreamError, fmt.Sprintf("查询成绩明细失败: HTTP %d", res.StatusCode), nil)
	}
	return parseGradeDetail(body), nil
}

// QueryExams 查询考试日程安排。
func (c *Client) QueryExams(ctx context.Context, cookie, academicYear, term string, extra map[string]string) (PageResult[ExamScheduleRecord], error) {
	mode := c.resolveQueryMode(ctx, cookie)
	data := url.Values{
		"xnm":                    {academicYearCode(academicYear)},
		"xqm":                    {term},
		"ksmcdmb_id":             {""},
		"kch":                    {""},
		"kc":                     {""},
		"ksrq":                   {""},
		"kkbm_id":                {""},
		"_search":                {"false"},
		"nd":                     {"0"},
		"queryModel.showCount":   {"50"},
		"queryModel.currentPage": {"1"},
		"queryModel.sortName":    {" "},
		"queryModel.sortOrder":   {"asc"},
		"time":                   {"1"},
	}
	mergeValues(data, extra)

	base := c.businessBaseURL(mode)
	raw, err := c.postBusinessForm(ctx, cookie, mode, base+pathExam, base+pathHome, data)
	if err != nil {
		return PageResult[ExamScheduleRecord]{}, err
	}
	return parsePage(raw, parseExam), nil
}

func (c *Client) postBusinessForm(
	ctx context.Context,
	cookie string,
	mode NetworkMode,
	endpoint, referer string,
	data url.Values,
) (map[string]any, error) {
	raw, err := c.postBusinessFormValue(ctx, cookie, mode, endpoint, referer, data)
	if err != nil {
		return nil, err
	}
	out, ok := raw.(map[string]any)
	if !ok {
		return nil, newError(ErrorUpstreamError, "教务系统返回了非对象 JSON", nil)
	}
	return out, nil
}

func (c *Client) postBusinessFormValue(
	ctx context.Context,
	cookie string,
	mode NetworkMode,
	endpoint, referer string,
	data url.Values,
) (any, error) {
	httpClient, err := c.newCookieHTTPClient(cookie, mode)
	if err != nil {
		return nil, newError(ErrorUpstreamError, "初始化查询会话失败", err)
	}

	headers := map[string]string{
		"Content-Type":     "application/x-www-form-urlencoded;charset=UTF-8",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Origin":           c.businessBaseURL(mode),
		"Referer":          referer,
		"X-Requested-With": "XMLHttpRequest",
	}

	res, err := c.doRequestFollowing(ctx, httpClient, http.MethodPost, endpoint, []byte(data.Encode()), headers, mode)
	if err != nil {
		return nil, classifyTransportError(err)
	}

	body := string(res.Body)
	if c.isExpiredBusinessResponse(res, body, true) {
		return nil, ErrSessionExpired
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, newError(ErrorUpstreamError, fmt.Sprintf("教务系统 HTTP 状态异常: %d", res.StatusCode), nil)
	}

	var out any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		if strings.Contains(body, "统一身份认证") || strings.Contains(body, "authserver") || isLoginPageHTML(body) {
			return nil, ErrSessionExpired
		}
		return nil, newError(ErrorUpstreamError, "解析教务系统响应 JSON 失败", err)
	}
	return out, nil
}

func (c *Client) isExpiredBusinessResponse(res httpResult, body string, expectJSON bool) bool {
	if res.StatusCode >= http.StatusInternalServerError && res.StatusCode < 600 {
		return false
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden || res.StatusCode == 901 {
		return true
	}
	if hasAuthRedirectInChain(res.RedirectChain, c.authserverHost) {
		return true
	}
	contentType := strings.ToLower(res.Headers.Get("Content-Type"))
	if !strings.Contains(contentType, "json") && (isLoginPageHTML(body) || isReAuthPageHTML(body)) {
		return true
	}
	if expectJSON && !strings.Contains(contentType, "json") && res.StatusCode == http.StatusOK {
		if strings.Contains(body, "统一身份认证") || strings.Contains(body, "authserver") {
			return true
		}
	}
	return false
}

func (c *Client) newCookieHTTPClient(cookie string, mode NetworkMode) (*http.Client, error) {
	httpClient, err := c.newIsolatedHTTPClient()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.businessBaseURL(mode) + "/")
	if err != nil {
		return nil, err
	}
	httpClient.Jar.SetCookies(u, parseCookieHeader(cookie))
	return httpClient, nil
}

func parseCookieHeader(raw string) []*http.Cookie {
	parts := strings.Split(raw, ";")
	cookies := make([]*http.Cookie, 0, len(parts))
	for _, part := range parts {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.EqualFold(name, "rememberMe") {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: strings.Trim(strings.TrimSpace(value), `"`),
			Path:  "/",
		})
	}
	return cookies
}

func isWfwCookie(raw string) bool {
	for _, part := range strings.Split(raw, ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "WFWSESSID") && strings.TrimSpace(val) != "" {
			return true
		}
	}
	return false
}

func academicYearCode(academicYear string) string {
	before, _, ok := strings.Cut(academicYear, "-")
	if ok {
		return strings.TrimSpace(before)
	}
	return strings.TrimSpace(academicYear)
}

func mergeValues(data url.Values, extra map[string]string) {
	for key, value := range extra {
		data.Set(key, value)
	}
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}
