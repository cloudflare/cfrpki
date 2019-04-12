// Origin validator

package ov

import (
	"errors"
	"net"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/int64_tree"
)

const (
	STATE_UNKNOWN = iota
	STATE_INVALID
	STATE_VALID
)

var (
	StateToName = map[int]string{
		STATE_UNKNOWN: "NotFound",
		STATE_INVALID: "Invalid",
		STATE_VALID:   "Valid",
	}
)

type AbstractROA interface {
	GetASN() uint32
	GetMaxLen() int
	GetPrefix() *net.IPNet
}

type AbstractRoute interface {
	GetPrefix() *net.IPNet
	GetASN() uint32
}

type OriginValidator struct {
	vrp []AbstractROA
	t4  *int64_tree.TreeV4
	t6  *int64_tree.TreeV6
}

// vrp: Validated ROA Payload https://tools.ietf.org/html/rfc6811
func NewOV(vrp []AbstractROA) *OriginValidator {
	t4 := int64_tree.NewTreeV4()
	t6 := int64_tree.NewTreeV6()

	for i, r := range vrp {
		ip4, ip6, _ := patricia.ParseFromIPAddr(r.GetPrefix())
		if ip4 != nil {
			t4.Add(*ip4, int64(i), nil)
		} else if ip6 != nil {
			t6.Add(*ip6, int64(i), nil)
		}
	}

	return &OriginValidator{vrp: vrp, t4: t4, t6: t6}
}

type curValidation struct {
	state    int
	route    AbstractRoute
	ov       *OriginValidator
	matching []AbstractROA
}

func (cv *curValidation) Filter(payload int64) bool {
	roa := cv.ov.vrp[payload]
	// Specs https://tools.ietf.org/html/rfc6811
	if cv.state != STATE_VALID {
		mask, _ := cv.route.GetPrefix().Mask.Size()
		if cv.route.GetASN() == roa.GetASN() && mask <= roa.GetMaxLen() {
			cv.state = STATE_VALID
		} else {
			cv.state = STATE_INVALID
		}
	}
	cv.matching = append(cv.matching, roa)
	return true
}

func (ov *OriginValidator) Validate(route AbstractRoute) ([]AbstractROA, int, error) {
	matching := make([]AbstractROA, 0)
	ip4, ip6, err := patricia.ParseFromIPAddr(route.GetPrefix())

	if err != nil {
		return matching, STATE_UNKNOWN, err
	}

	cv := curValidation{
		route:    route,
		ov:       ov,
		state:    STATE_UNKNOWN,
		matching: matching,
	}
	if ip4 != nil {
		ov.t4.FindTagsWithFilter(*ip4, cv.Filter)
	} else if ip6 != nil {
		ov.t6.FindTagsWithFilter(*ip6, cv.Filter)
	} else {
		return cv.matching, cv.state, errors.New("Unknown IP type")
	}

	return cv.matching, cv.state, nil
}
