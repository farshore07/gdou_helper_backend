package jwxt

import (
	"reflect"
	"testing"
)

func TestParseTimetableAndWeeks(t *testing.T) {
	raw := map[string]any{
		"xsxx": map[string]any{"XM": "测试同学", "XH": "202311701234"},
		"kbList": []any{
			map[string]any{
				"kch":   "CS101",
				"kcmc":  "数据结构",
				"xm":    "张老师",
				"xqj":   "1",
				"xqjmc": "星期一",
				"jc":    "1-2节",
				"zcd":   "1-5周(单),8-10周(双)",
				"cdmc":  "钟海楼0301",
				"xqmc":  "湖光校区",
				"xf":    "4.0",
				"jxbmc": "软件1241",
			},
		},
	}

	res := parseTimetable(raw)
	if len(res.Courses) != 1 {
		t.Fatalf("expected 1 course, got %d", len(res.Courses))
	}
	c := res.Courses[0]
	wantWeeks := []int{1, 3, 5, 8, 10}
	if !reflect.DeepEqual(c.WeekNumbers, wantWeeks) {
		t.Fatalf("week_numbers mismatch: got %v, want %v", c.WeekNumbers, wantWeeks)
	}
	if c.CourseName != "数据结构" || c.Classroom != "钟海楼0301" {
		t.Fatalf("unexpected course fields: %+v", c)
	}
	if res.PeriodTimes == nil {
		t.Fatalf("PeriodTimes must be non-nil slice")
	}

	empty := parseTimetable(map[string]any{})
	if empty.Courses == nil || empty.StudentInfo == nil {
		t.Fatalf("empty timetable must have non-nil slices and maps")
	}

	cases := []struct {
		raw  string
		want []int
	}{
		{"第4周", []int{4}},
		{"第1-3周", []int{1, 2, 3}},
		{"第4周 第8周", []int{4, 8}},
		{"1-5单周", []int{1, 3, 5}},
		{"1-5,7-9周(单)", []int{1, 3, 5, 7, 9}},
		{"1-3周、6~8周(双)", []int{1, 2, 3, 6, 8}},
	}
	for _, tc := range cases {
		got := parseWeekNumbers(tc.raw)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseWeekNumbers(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestParseGradeAndDetail(t *testing.T) {
	page := parsePage(map[string]any{
		"totalCount":  1,
		"totalPage":   1,
		"currentPage": 1,
		"showCount":   50,
		"items": []any{
			map[string]any{
				"kch":    "CS102",
				"kch_id": "KCH_102",
				"jxb_id": "JXB_999",
				"xnm":    "2025",
				"xqm":    "3",
				"kcmc":   "操作系统",
				"cj":     "92",
				"jd":     "4.2",
				"xf":     "3.5",
				"kcxzmc": "必修",
			},
		},
	}, parseGrade)

	if len(page.Items) != 1 || page.Items[0].Raw["jxb_id"] != "JXB_999" {
		t.Fatalf("grade raw jxb_id missing: %+v", page)
	}

	htmlBody := `
	<div>课程名称：<span class="red2">操作系统&nbsp;</span></div>
	<table><tr><td>无关列1</td><td>无关列2</td><td>无关列3</td></tr></table>
	<table>
		<tr><th>成绩分项</th><th>成绩分项比例</th><th>成绩</th></tr>
		<tr><td>平时成绩</td><td>40%</td><td>95</td></tr>
		<tr><td>期末成绩</td><td>60%</td><td>90</td></tr>
	</table>`
	detail, ok := parseGradeDetailHTML(htmlBody)
	if !ok {
		t.Fatalf("valid grade detail page should be recognized")
	}
	if detail.CourseName != "操作系统" {
		t.Fatalf("unexpected course name: %q", detail.CourseName)
	}
	if len(detail.Items) != 2 || detail.Items[0].Name != "平时成绩" || detail.Items[1].Score != "90" {
		t.Fatalf("unexpected grade detail items: %+v", detail.Items)
	}

	emptyTableHTML := `<div>课程名称：<span class="red2">体育</span></div><table><tr><td>成绩分项</td><td>成绩分项比例</td><td>成绩</td></tr></table>`
	emptyDetail, ok := parseGradeDetailHTML(emptyTableHTML)
	if !ok {
		t.Fatalf("valid empty grade detail table should be recognized")
	}
	if emptyDetail.Items == nil || len(emptyDetail.Items) != 0 || emptyDetail.CourseName != "体育" {
		t.Fatalf("empty grade detail must return non-nil empty items: %+v", emptyDetail)
	}

	for _, invalidHTML := range []string{
		"<html><body>系统维护中</body></html>",
		"<html><head><title>成绩分项查询维护中</title></head><body>成绩分项查询维护中</body></html>",
		"<html><body><table><tr><td>成绩分项查询维护中</td></tr></table></body></html>",
		"<html><body><table><tr><td>请求路径</td><td>/cjcx/cjcx_cxCjxqGjh.html</td><td>维护中</td></tr></table></body></html>",
	} {
		if _, ok := parseGradeDetailHTML(invalidHTML); ok {
			t.Fatalf("invalid maintenance HTML must be rejected: %s", invalidHTML)
		}
	}
}

func TestParseSemesterCalendarAndPeriodTimes(t *testing.T) {
	cal, err := parseSemesterCalendar(map[string]any{
		"zs": 1,
		"rqazcList": []any{
			map[string]any{"xqj": 1, "xqjmc": "星期一", "rq": "2026-03-02"},
			map[string]any{"xqj": 2, "xqjmc": "星期二", "rq": "2026-03-03"},
		},
	})
	if err != nil || cal.StartDate != "2026-03-02" {
		t.Fatalf("unexpected semester calendar: (%+v, %v)", cal, err)
	}

	periods := parsePeriodTimes([]any{
		map[string]any{"jcmc": "2", "qssj": "09:05", "jssj": "09:50"},
		map[string]any{"jcmc": "1", "qssj": "8:10:00", "jssj": "8:55:00"},
	})
	if len(periods) != 2 || periods[0].Period != 1 || periods[0].StartTime != "08:10" || periods[1].Period != 2 {
		t.Fatalf("unexpected period times: %+v", periods)
	}
}
