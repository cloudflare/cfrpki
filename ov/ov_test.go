package ov

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

type TestROA struct {
	ASN       uint32
	Prefix    *net.IPNet
	MaxLength int
}

func (r *TestROA) GetPrefix() *net.IPNet {
	return r.Prefix
}

func (r *TestROA) GetASN() uint32 {
	return r.ASN
}

func (r *TestROA) GetMaxLen() int {
	return r.MaxLength
}

type TestRoute struct {
	ASN    uint32
	Prefix *net.IPNet
}

func (r *TestRoute) GetPrefix() *net.IPNet {
	return r.Prefix
}

func (r *TestRoute) GetASN() uint32 {
	return r.ASN
}

func MakeData() ([]AbstractROA, AbstractRoute) {
	_, ip1, _ := net.ParseCIDR("10.0.0.0/16")
	_, ip2, _ := net.ParseCIDR("10.0.0.0/22")
	_, ip3, _ := net.ParseCIDR("10.0.0.0/24")
	_, ip4, _ := net.ParseCIDR("10.0.0.0/25")

	vrp := []AbstractROA{
		&TestROA{
			65001,
			ip1,
			24,
		},
		&TestROA{
			65002,
			ip2,
			23,
		},
		&TestROA{
			65003,
			ip3,
			24,
		},
		&TestROA{
			65004,
			ip4,
			26,
		},
	}
	_, ip5, _ := net.ParseCIDR("10.0.0.0/24")
	route := &TestRoute{
		65003,
		ip5,
	}
	return vrp, route
}

func TestValid(t *testing.T) {
	vrp, route := MakeData()
	ov := NewOV(vrp)
	matching, state, err := ov.Validate(route)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(matching))
	assert.Equal(t, STATE_VALID, state)
}

func TestInvalid(t *testing.T) {
	vrp, route := MakeData()
	ov := NewOV(vrp[0:2])
	matching, state, err := ov.Validate(route)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(matching))
	assert.Equal(t, STATE_INVALID, state)
}

func TestUnknown(t *testing.T) {
	vrp, route := MakeData()
	ov := NewOV(vrp[3:3])
	matching, state, err := ov.Validate(route)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(matching))
	assert.Equal(t, STATE_UNKNOWN, state)
}
