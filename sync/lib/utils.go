package syncpki

import (
	"strings"
)

type Logger interface {
	Infof(string, ...interface{})
	Info(...interface{})
	Debugf(string, ...interface{})
	Debug(...interface{})
	Errorf(string, ...interface{})
	Error(...interface{})
}

type SubMap struct {
	Subitem map[string]SubMap
	Count   int
}

func AddInMap(item string, m map[string]SubMap) {
	if !(len(item) > 8 && item[0:8] == "rsync://") {
		return
	}
	itemSplit := strings.Split(item[8:len(item)], "/")
	curm := m
	for i, s := range itemSplit {
		mm, ok := curm[s]

		if i == len(itemSplit)-1 {
			mm.Count++
		}
		if !ok {
			mm.Subitem = make(map[string]SubMap)
			curm[s] = mm
		}
		curm = mm.Subitem
	}
}

func ReduceMap(m map[string]SubMap) []string {
	explore := make([]map[string]SubMap, 1)
	explore[0] = m
	explorePath := make([]string, 1)
	explorePath[0] = "rsync:/"
	exploreDepth := make([]int, 1)
	exploreDepth[0] = 0

	final := make([]string, 0)

	for len(explore) > 0 {
		curExplore := explore[0]
		explore = explore[1:len(explore)]
		curPath := explorePath[0]
		explorePath = explorePath[1:len(explorePath)]
		curDepth := exploreDepth[0]
		exploreDepth = exploreDepth[1:len(exploreDepth)]
		for pathItem, pathMap := range curExplore {
			pathMapC := pathMap.Subitem

			curPathComputed := curPath + "/" + pathItem

			if len(pathMapC) == 1 && pathMap.Count == 0 || curDepth < 1 {
				explorePath = append(explorePath, curPathComputed)
				explore = append(explore, pathMapC)
				exploreDepth = append(exploreDepth, curDepth+1)
			} else {
				final = append(final, curPathComputed)
			}
		}
	}
	return final
}
