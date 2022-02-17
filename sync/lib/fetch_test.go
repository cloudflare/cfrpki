package syncpki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLocalPath(t *testing.T) {
	tests := []struct {
		name     string
		pathRep  string
		replace  map[string]string
		expected string
	}{
		{
			name:    "With trailing slash",
			pathRep: "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
			replace: map[string]string{
				"rsync://": "cache/",
			},
			expected: "cache/rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
		},
		{
			name:    "Without trailing slash (this is a regresion test)",
			pathRep: "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
			replace: map[string]string{
				"rsync://": "cache",
			},
			expected: "cache/rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
		},
	}

	for _, test := range tests {
		res := GetLocalPath(test.pathRep, test.replace)
		assert.Equal(t, test.expected, res, test.name)
	}
}
