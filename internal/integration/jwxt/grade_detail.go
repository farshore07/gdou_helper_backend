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
	gradeDetailCourseRE   = regexp.MustCompile(`(?s)课程名称.*?<span[^>]*class=["']red2["'][^>]*>(.*?)</span>`)
	gradeDetailTableTagRE = regexp.MustCompile(`(?is)</?table\b[^>]*>`)
	gradeDetailRowRE      = regexp.MustCompile(`(?is)<tr\b[^>]*>(.*?)</tr>`)
	gradeDetailCellRE     = regexp.MustCompile(`(?is)<(t[hd])\b[^>]*>(.*?)</t[hd]>`)
	htmlTagStripRE        = regexp.MustCompile(`<[^>]+>`)
)

func extractInnermostTables(body string) []string {
	type frame struct {
		start    int
		hasChild bool
	}
	locs := gradeDetailTableTagRE.FindAllStringIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	var stack []frame
	var tables []string
	for _, loc := range locs {
		tag := body[loc[0]:loc[1]]
		if len(tag) >= 2 && tag[1] == '/' {
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !top.hasChild {
				tables = append(tables, body[top.start:loc[1]])
			}
		} else {
			if len(stack) > 0 {
				stack[len(stack)-1].hasChild = true
			}
			stack = append(stack, frame{start: loc[0]})
		}
	}
	return tables
}

func cleanHTMLText(value string) string {
	stripped := htmlTagStripRE.ReplaceAllString(value, "")
	unescaped := html.UnescapeString(stripped)
	return strings.Join(strings.Fields(strings.ReplaceAll(unescaped, "\u00a0", " ")), " ")
}

type htmlTableCell struct {
	tag  string
	text string
}

func extractTableRowCells(rowHTML string) []htmlTableCell {
	matches := gradeDetailCellRE.FindAllStringSubmatch(rowHTML, -1)
	if len(matches) == 0 {
		return nil
	}
	cells := make([]htmlTableCell, 0, len(matches))
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		cells = append(cells, htmlTableCell{
			tag:  strings.ToLower(m[1]),
			text: cleanHTMLText(m[2]),
		})
	}
	return cells
}

func isGradeDetailHeaderRow(cells []htmlTableCell) bool {
	if len(cells) != 3 {
		return false
	}
	col0 := cells[0].text
	col1 := cells[1].text
	col2 := cells[2].text
	ok0 := col0 == "成绩分项" || col0 == "分项名称"
	ok1 := col1 == "成绩分项比例" || col1 == "分项比例" || col1 == "比例"
	ok2 := col2 == "成绩" || col2 == "分项成绩"
	return ok0 && ok1 && ok2
}

// parseGradeDetailHTML 校验成绩明细表自身表头，并仅解析该表内表头之后的数据行。
// 若未找到合法成绩分项表头，返回 ok=false，供上层识别为异常/维护页而非合法空表。
func parseGradeDetailHTML(body string) (GradeDetail, bool) {
	result := GradeDetail{
		Items: make([]GradeDetailItem, 0),
	}
	if match := gradeDetailCourseRE.FindStringSubmatch(body); len(match) > 1 {
		result.CourseName = cleanHTMLText(match[1])
	}

	tables := extractInnermostTables(body)
	for _, tableHTML := range tables {
		rows := gradeDetailRowRE.FindAllStringSubmatch(tableHTML, -1)
		headerIdx := -1
		for idx, row := range rows {
			if len(row) < 2 {
				continue
			}
			if isGradeDetailHeaderRow(extractTableRowCells(row[1])) {
				headerIdx = idx
				break
			}
		}
		if headerIdx < 0 {
			continue
		}

		for _, row := range rows[headerIdx+1:] {
			if len(row) < 2 {
				continue
			}
			cells := extractTableRowCells(row[1])
			if len(cells) != 3 {
				continue
			}
			if cells[0].tag != "td" || cells[1].tag != "td" || cells[2].tag != "td" {
				continue
			}
			if isGradeDetailHeaderRow(cells) || cells[0].text == "" {
				continue
			}
			result.Items = append(result.Items, GradeDetailItem{
				Name:  cells[0].text,
				Ratio: cells[1].text,
				Score: cells[2].text,
			})
		}
		return result, true
	}

	return result, false
}

func parseGradeDetail(body string) GradeDetail {
	detail, _ := parseGradeDetailHTML(body)
	return detail
}
