package jwxt

import (
	"html"
	"regexp"
	"strings"
)

// GradeDetail 对齐前端 /api/v1/jwxt/grade-detail 返回格式。
type GradeDetail struct {
	CourseName string            `json:"course_name"`
	Items      []GradeDetailItem `json:"items"`
}

// GradeDetailItem 表示单科成绩的分项构成。
type GradeDetailItem struct {
	Name  string `json:"name"`
	Ratio string `json:"ratio"`
	Score string `json:"score"`
}

var (
	gradeDetailCourseRE = regexp.MustCompile(`(?s)课程名称.*?<span[^>]*class=["']red2["'][^>]*>(.*?)</span>`)
	gradeDetailHeaderRE = regexp.MustCompile(`(?is)<t[hd][^>]*>\s*(?:成绩分项|成绩分项比例)\s*</t[hd]>`)
	gradeDetailTableRE  = regexp.MustCompile(`(?is)<table\b[^>]*>`)
	gradeDetailRowRE    = regexp.MustCompile(`(?s)<tr[^>]*>\s*<td[^>]*>\s*(.*?)\s*</td>\s*<td[^>]*>\s*(.*?)\s*</td>\s*<td[^>]*>\s*(.*?)\s*</td>\s*</tr>`)
	htmlTagStripRE      = regexp.MustCompile(`<[^>]+>`)
)

func cleanHTMLText(value string) string {
	stripped := htmlTagStripRE.ReplaceAllString(value, "")
	unescaped := html.UnescapeString(stripped)
	return strings.Join(strings.Fields(strings.ReplaceAll(unescaped, "\u00a0", " ")), " ")
}

func isGradeDetailPageHTML(body string) bool {
	if !gradeDetailTableRE.MatchString(body) {
		return false
	}
	if gradeDetailCourseRE.MatchString(body) || gradeDetailHeaderRE.MatchString(body) {
		return true
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "subtab") ||
		strings.Contains(lower, "cjxq") ||
		strings.Contains(lower, "xmcj")
}

func parseGradeDetail(body string) GradeDetail {
	result := GradeDetail{
		Items: make([]GradeDetailItem, 0),
	}
	if match := gradeDetailCourseRE.FindStringSubmatch(body); len(match) > 1 {
		result.CourseName = cleanHTMLText(match[1])
	}
	for _, match := range gradeDetailRowRE.FindAllStringSubmatch(body, -1) {
		if len(match) < 4 {
			continue
		}
		name := cleanHTMLText(match[1])
		if name == "" || name == "成绩分项" {
			continue
		}
		result.Items = append(result.Items, GradeDetailItem{
			Name:  name,
			Ratio: cleanHTMLText(match[2]),
			Score: cleanHTMLText(match[3]),
		})
	}
	return result
}
