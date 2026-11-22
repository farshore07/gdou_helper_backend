package jwxt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NetworkMode 表示教务系统访问模式。
type NetworkMode string

const (
	NetworkModeAuto     NetworkMode = "auto"
	NetworkModeCampus   NetworkMode = "campus"
	NetworkModeExternal NetworkMode = "external"
)

// ParseNetworkMode 解析网络模式（兼容 campus/direct、external/wfw、auto）。
func ParseNetworkMode(raw string, fallback NetworkMode) (NetworkMode, error) {
	cleaned := strings.ToLower(strings.TrimSpace(raw))
	if cleaned == "" {
		if fallback != "" {
			return fallback, nil
		}
		return NetworkModeAuto, nil
	}
	switch cleaned {
	case "auto":
		return NetworkModeAuto, nil
	case "campus", "direct", "intranet", "internal":
		return NetworkModeCampus, nil
	case "external", "wfw", "extranet", "public":
		return NetworkModeExternal, nil
	default:
		return "", fmt.Errorf("不支持的网络模式: %q（可选 auto/campus/external/direct/wfw）", raw)
	}
}

// MfaMethod 表示统一身份认证二次验证方式。
type MfaMethod string

const (
	MfaMethodAuto   MfaMethod = "auto"
	MfaMethodWechat MfaMethod = "wechat"
	MfaMethodSMS    MfaMethod = "sms"
)

// ParseMfaMethod 解析二次验证方式。
func ParseMfaMethod(raw string) (MfaMethod, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return MfaMethodAuto, nil
	case "wechat", "wx", "4":
		return MfaMethodWechat, nil
	case "sms", "phone", "3":
		return MfaMethodSMS, nil
	default:
		return "", fmt.Errorf("不支持的二次验证方式: %q（可选 auto/wechat/sms）", raw)
	}
}

func (m MfaMethod) ReAuthType() string {
	switch m {
	case MfaMethodWechat:
		return "4"
	case MfaMethodSMS:
		return "3"
	default:
		return ""
	}
}

func (m MfaMethod) AuthCodeTypeName() string {
	switch m {
	case MfaMethodWechat:
		return "reAuthWChatDynamicCodeType"
	case MfaMethodSMS:
		return "reAuthDynamicCodeType"
	default:
		return ""
	}
}

func (m MfaMethod) Label() string {
	switch m {
	case MfaMethodWechat:
		return "企业微信验证码"
	case MfaMethodSMS:
		return "手机短信验证码"
	default:
		return "自动选择"
	}
}

func MfaMethodFromReAuthType(code string) MfaMethod {
	switch strings.TrimSpace(code) {
	case "4":
		return MfaMethodWechat
	case "3":
		return MfaMethodSMS
	default:
		return MfaMethodAuto
	}
}

// AuthResult 对齐前端 /api/v1/jwxt/session/validate 的返回格式。
type AuthResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
}

// PwdLoginForm 保存 CAS 登录页 #pwdFromId 解析结果。
type PwdLoginForm struct {
	ActionURL      string
	PageURL        string
	PwdEncryptSalt string
	Execution      string
	LT             string
	CLLT           string
	DLLT           string
	EventID        string
}

// CaptchaTransaction 保存等待用户手动输入图形验证码时的短期隔离会话（不存密码）。
type CaptchaTransaction struct {
	Username          string
	NetworkMode       NetworkMode
	DeviceFingerprint string
	Form              PwdLoginForm
	ImageBytes        []byte
	ContentType       string
	HTTPClient        *http.Client
}

// MfaTransaction 保存等待二次验证的短期隔离会话。
type MfaTransaction struct {
	Username          string
	ReAuthUserID      string
	ReAuthType        string
	DefaultMethod     MfaMethod
	AvailableMethods  []MfaMethod
	Service           string
	IsMultifactor     string
	IsSleepAccount    string
	NetworkMode       NetworkMode
	DeviceFingerprint string
	HTTPClient        *http.Client
}

// MfaSendResult 表示切换并发送二次验证码的结果。
type MfaSendResult struct {
	Method    MfaMethod `json:"method"`
	Countdown int       `json:"countdown"`
	Message   string    `json:"message"`
}

// LoginOutcome 表示登录接口的统一阶段性输出。
type LoginOutcome struct {
	Status            string
	Message           string
	URL               string
	Cookie            string
	DeviceFingerprint string
	NetworkMode       NetworkMode
	MfaTx             *MfaTransaction
	CaptchaTx         *CaptchaTransaction
}

type PageResult[T any] struct {
	Items       []T            `json:"items"`
	TotalCount  int            `json:"total_count"`
	TotalPage   int            `json:"total_page"`
	CurrentPage int            `json:"current_page"`
	PageSize    int            `json:"page_size"`
	Raw         map[string]any `json:"raw"`
}

type GradeRecord struct {
	CourseCode   string         `json:"course_code"`
	CourseName   string         `json:"course_name"`
	AcademicYear string         `json:"academic_year"`
	Term         string         `json:"term"`
	Credit       string         `json:"credit"`
	Grade        string         `json:"grade"`
	GradePoint   string         `json:"grade_point"`
	CourseNature string         `json:"course_nature"`
	Raw          map[string]any `json:"raw"`
}

type TimetableCourse struct {
	CourseCode    string         `json:"course_code"`
	CourseName    string         `json:"course_name"`
	Teacher       string         `json:"teacher"`
	Weekday       string         `json:"weekday"`
	WeekdayName   string         `json:"weekday_name"`
	Periods       string         `json:"periods"`
	Weeks         string         `json:"weeks"`
	WeekNumbers   []int          `json:"week_numbers,omitempty"`
	Classroom     string         `json:"classroom"`
	Campus        string         `json:"campus"`
	Credit        string         `json:"credit"`
	TeachingClass string         `json:"teaching_class"`
	Raw           map[string]any `json:"raw"`
}

type TimetableResult struct {
	Courses           []TimetableCourse `json:"courses"`
	PeriodTimes       []PeriodTime      `json:"period_times"`
	SemesterStartDate string            `json:"semester_start_date,omitempty"`
	StudentInfo       map[string]any    `json:"student_info"`
	Raw               map[string]any    `json:"raw"`
}

type WeekDate struct {
	Weekday int    `json:"weekday"`
	Name    string `json:"name,omitempty"`
	Date    string `json:"date"`
}

type SemesterCalendar struct {
	Week      int        `json:"week"`
	WeekDates []WeekDate `json:"week_dates"`
	StartDate string     `json:"semester_start_date,omitempty"`
}

type PeriodTime struct {
	Period    int    `json:"period"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

type ExamScheduleRecord struct {
	CourseCode       string         `json:"course_code"`
	CourseName       string         `json:"course_name"`
	ExamName         string         `json:"exam_name"`
	ExamTime         string         `json:"exam_time"`
	Classroom        string         `json:"classroom"`
	ExamPlace        string         `json:"exam_place"`
	Campus           string         `json:"campus"`
	ExamMethod       string         `json:"exam_method"`
	AssessmentMethod string         `json:"assessment_method"`
	Credit           string         `json:"credit"`
	Raw              map[string]any `json:"raw"`
}

func parsePage[T any](data map[string]any, parse func(map[string]any) T) PageResult[T] {
	items := make([]T, 0)
	if rawItems, ok := data["items"].([]any); ok {
		items = make([]T, 0, len(rawItems))
		for _, raw := range rawItems {
			if item, ok := raw.(map[string]any); ok {
				items = append(items, parse(item))
			}
		}
	}
	return PageResult[T]{
		Items:       items,
		TotalCount:  intField(data, "totalCount"),
		TotalPage:   intField(data, "totalPage"),
		CurrentPage: defaultInt(intField(data, "currentPage"), 1),
		PageSize:    defaultInt(firstInt(data, "pageSize", "showCount"), 15),
		Raw:         data,
	}
}

func parseGrade(data map[string]any) GradeRecord {
	return GradeRecord{
		CourseCode:   textField(data, "kch", "kch_id"),
		CourseName:   textField(data, "kcmc"),
		AcademicYear: textField(data, "xnmmc", "xnm"),
		Term:         textField(data, "xqmmc", "xqm"),
		Credit:       textField(data, "xf"),
		Grade:        textField(data, "cj", "bfzcj", "zcj"),
		GradePoint:   textField(data, "jd"),
		CourseNature: textField(data, "kcxzmc", "kcxz"),
		Raw:          data,
	}
}

func parseTimetable(data map[string]any) TimetableResult {
	courses := make([]TimetableCourse, 0)
	if rawCourses, ok := data["kbList"].([]any); ok {
		courses = make([]TimetableCourse, 0, len(rawCourses))
		for _, raw := range rawCourses {
			if item, ok := raw.(map[string]any); ok {
				courses = append(courses, parseTimetableCourse(item))
			}
		}
	}
	studentInfo, _ := data["xsxx"].(map[string]any)
	if studentInfo == nil {
		studentInfo = map[string]any{}
	}
	return TimetableResult{
		Courses:     courses,
		PeriodTimes: []PeriodTime{},
		StudentInfo: studentInfo,
		Raw:         data,
	}
}

func parseTimetableCourse(data map[string]any) TimetableCourse {
	weeks := textField(data, "zcd", "zcmc")
	return TimetableCourse{
		CourseCode:    textField(data, "kch", "kch_id"),
		CourseName:    textField(data, "kcmc"),
		Teacher:       textField(data, "xm"),
		Weekday:       textField(data, "xqj"),
		WeekdayName:   textField(data, "xqjmc"),
		Periods:       textField(data, "jc", "jcs"),
		Weeks:         weeks,
		WeekNumbers:   parseWeekNumbers(weeks),
		Classroom:     textField(data, "cdmc"),
		Campus:        textField(data, "xqmc"),
		Credit:        textField(data, "xf"),
		TeachingClass: textField(data, "jxbmc"),
		Raw:           data,
	}
}

func parseWeekNumbers(value string) []int {
	cleaned := strings.NewReplacer("周", "", "，", ",", "（", "(", "）", ")").Replace(strings.TrimSpace(value))
	if cleaned == "" {
		return nil
	}
	seen := map[int]struct{}{}
	for _, part := range strings.Split(cleaned, ",") {
		part = strings.TrimSpace(part)
		isOdd, isEven := strings.Contains(part, "单"), strings.Contains(part, "双")
		part = strings.ReplaceAll(strings.ReplaceAll(part, "(单)", ""), "(双)", "")
		bounds := strings.Split(strings.TrimSpace(part), "-")
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil {
			continue
		}
		end := start
		if len(bounds) > 1 {
			end, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				continue
			}
		}
		for week := start; week <= end; week++ {
			if week > 0 && (!isOdd || week%2 == 1) && (!isEven || week%2 == 0) {
				seen[week] = struct{}{}
			}
		}
	}
	result := make([]int, 0, len(seen))
	for week := range seen {
		result = append(result, week)
	}
	sort.Ints(result)
	return result
}

func parseSemesterCalendar(data map[string]any) (SemesterCalendar, error) {
	week := intField(data, "zs")
	if week != 1 {
		return SemesterCalendar{}, fmt.Errorf("学期日期响应必须是第 1 周")
	}
	rawDates, ok := data["rqazcList"].([]any)
	if !ok || len(rawDates) == 0 {
		return SemesterCalendar{}, fmt.Errorf("学期日期响应缺少 rqazcList")
	}
	result := SemesterCalendar{Week: week, WeekDates: make([]WeekDate, 0, len(rawDates))}
	seenWeekday := map[int]struct{}{}
	seenDate := map[string]struct{}{}
	for _, raw := range rawDates {
		item, ok := raw.(map[string]any)
		if !ok {
			return SemesterCalendar{}, fmt.Errorf("学期日期响应包含无效日期项")
		}
		weekday := intField(item, "xqj")
		if weekday < 1 || weekday > 7 {
			return SemesterCalendar{}, fmt.Errorf("学期日期星期无效")
		}
		date := strings.TrimSpace(textField(item, "rq"))
		parsedDate, err := time.Parse("2006-01-02", date)
		if err != nil {
			return SemesterCalendar{}, fmt.Errorf("学期日期格式无效")
		}
		actualWeekday := int(parsedDate.Weekday())
		if actualWeekday == 0 {
			actualWeekday = 7
		}
		if actualWeekday != weekday {
			return SemesterCalendar{}, fmt.Errorf("学期日期与星期不一致")
		}
		if _, exists := seenWeekday[weekday]; exists {
			return SemesterCalendar{}, fmt.Errorf("学期日期星期重复")
		}
		if _, exists := seenDate[date]; exists {
			return SemesterCalendar{}, fmt.Errorf("学期日期重复")
		}
		seenWeekday[weekday], seenDate[date] = struct{}{}, struct{}{}
		result.WeekDates = append(result.WeekDates, WeekDate{Weekday: weekday, Name: textField(item, "xqjmc"), Date: date})
	}
	sort.Slice(result.WeekDates, func(i, j int) bool { return result.WeekDates[i].Weekday < result.WeekDates[j].Weekday })
	for _, item := range result.WeekDates {
		if item.Weekday == 1 {
			result.StartDate = item.Date
			break
		}
	}
	if result.StartDate == "" {
		return SemesterCalendar{}, fmt.Errorf("学期日期缺少周一")
	}
	if len(result.WeekDates) == 7 {
		start, _ := time.Parse("2006-01-02", result.StartDate)
		for index, item := range result.WeekDates {
			date, _ := time.Parse("2006-01-02", item.Date)
			if date.Sub(start) != time.Duration(index)*24*time.Hour {
				return SemesterCalendar{}, fmt.Errorf("学期日期不连续")
			}
		}
	}
	return result, nil
}

func parsePeriodTimes(raw any) []PeriodTime {
	items, ok := raw.([]any)
	if !ok {
		return []PeriodTime{}
	}
	result := make([]PeriodTime, 0, len(items))
	seen := make(map[int]struct{}, len(items))
	for _, item := range items {
		data, ok := item.(map[string]any)
		if !ok {
			continue
		}
		period, err := strconv.Atoi(strings.TrimSpace(textField(data, "jcmc")))
		if err != nil || period < 1 || period > 12 {
			continue
		}
		start, okStart := normalizeClock(textField(data, "qssj"))
		end, okEnd := normalizeClock(textField(data, "jssj"))
		if !okStart || !okEnd {
			continue
		}
		if clockMinutes(start) >= clockMinutes(end) {
			continue
		}
		if _, exists := seen[period]; exists {
			continue
		}
		seen[period] = struct{}{}
		result = append(result, PeriodTime{Period: period, StartTime: start, EndTime: end})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Period < result[j].Period })
	return result
}

func normalizeClock(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", false
	}
	hour, errHour := strconv.Atoi(parts[0])
	minute, errMinute := strconv.Atoi(parts[1])
	if errHour != nil || errMinute != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return "", false
	}
	if len(parts) == 3 {
		second, errSecond := strconv.Atoi(parts[2])
		if errSecond != nil || second < 0 || second > 59 {
			return "", false
		}
	}
	return fmt.Sprintf("%02d:%02d", hour, minute), true
}

func clockMinutes(value string) int {
	parts := strings.Split(value, ":")
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	return hour*60 + minute
}

func parseExam(data map[string]any) ExamScheduleRecord {
	return ExamScheduleRecord{
		CourseCode:       textField(data, "kch"),
		CourseName:       textField(data, "kcmc"),
		ExamName:         textField(data, "ksmc"),
		ExamTime:         textField(data, "kssj", "sksj"),
		Classroom:        textField(data, "cdmc", "cdjc"),
		ExamPlace:        textField(data, "jxdd"),
		Campus:           textField(data, "cdxqmc", "xqmc"),
		ExamMethod:       textField(data, "ksfs"),
		AssessmentMethod: textField(data, "khfs"),
		Credit:           textField(data, "xf"),
		Raw:              data,
	}
}

func textField(data map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		return fmt.Sprint(value)
	}
	return ""
}

func intField(data map[string]any, key string) int {
	value, ok := data[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := strconv.Atoi(string(v))
		return n
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func firstInt(data map[string]any, keys ...string) int {
	for _, key := range keys {
		if value := intField(data, key); value != 0 {
			return value
		}
	}
	return 0
}

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
