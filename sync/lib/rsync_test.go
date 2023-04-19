package syncpki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFoldersPathFromRsyncURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantFail bool
		expected string
	}{
		{
			name:     "Valid URL",
			url:      "rsync://r.magellan.ipxo.com/repo",
			wantFail: false,
			expected: "r.magellan.ipxo.com/repo",
		},
		{
			name:     "Invalid URL",
			url:      "xxxx://r.magellan.ipxo.com/repo",
			wantFail: true,
		},
		{
			name:     "Valid URL with file",
			url:      "rsync://r.magellan.ipxo.com/repo/foo.roa",
			wantFail: false,
			expected: "r.magellan.ipxo.com/repo",
		},
	}

	for _, test := range tests {
		res, err := ExtractFoldersPathFromRsyncURL(test.url)
		if test.wantFail && err == nil {
			t.Errorf("unexpected success for %q", test.name)
			continue
		}

		if !test.wantFail && err != nil {
			t.Errorf("unexpected error for %q: %v", test.name, err)
			continue
		}

		assert.Equal(t, test.expected, res, test.name)
	}
}
