package main

import (
	"testing"

	"github.com/cloudflare/gortr/prefixfile"
	"github.com/stretchr/testify/assert"
)

func TestFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    []prefixfile.ROAJson
		expected []prefixfile.ROAJson
	}{
		{
			name: "Invalid IPv4 prefix",
			input: []prefixfile.ROAJson{
				{
					Prefix: "1.1.1.0/25",
					ASN:    13335,
					Length: 32,
				},
			},
			expected: []prefixfile.ROAJson{},
		},
		{
			name: "Invalid IPv6 prefix",
			input: []prefixfile.ROAJson{
				{
					Prefix: "2001:db8::/64",
					ASN:    13335,
					Length: 128,
				},
			},
			expected: []prefixfile.ROAJson{},
		},
		{
			name: "All valid",
			input: []prefixfile.ROAJson{
				{
					Prefix: "2001:db8::/48",
					ASN:    13335,
					Length: 48,
				},
				{
					Prefix: "1.1.1.0/24",
					ASN:    13335,
					Length: 32,
				},
			},
			expected: []prefixfile.ROAJson{
				{
					Prefix: "2001:db8::/48",
					ASN:    13335,
					Length: 48,
				},
				{
					Prefix: "1.1.1.0/24",
					ASN:    13335,
					Length: 32,
				},
			},
		},
	}

	for _, test := range tests {
		res := FilterInvalidPrefixLen(test.input)
		assert.Equal(t, test.expected, res, test.name)
	}
}
