package main

import (
	"testing"

	"github.com/cloudflare/cfrpki/sync/lib"
	"github.com/stretchr/testify/assert"
)

func TestReduceMap(t *testing.T) {
	rsyncMap := make(map[string]syncpki.SubMap)
	syncpki.AddInMap("rsync://rpki.example.com/member_repository/a", rsyncMap)
	syncpki.AddInMap("rsync://rpki.example.com/repository/a/", rsyncMap)
	syncpki.AddInMap("rsync://rpki.example.com/repository/b/", rsyncMap)
	syncpki.AddInMap("rsync://rpki.example.com/repository/c/", rsyncMap)
	syncpki.AddInMap("rsync://rpki2.example.com/repository/a", rsyncMap)
	syncpki.AddInMap("rsync://rpki2.example.com/repository/b", rsyncMap)
	syncpki.AddInMap("rsync://rpki2.example.com/repository/c", rsyncMap)
	out := syncpki.ReduceMap(rsyncMap)
	assert.Equal(t, 3, len(out))
	assert.ElementsMatch(t,
		[]string{"rsync://rpki.example.com/repository",
			"rsync://rpki2.example.com/repository",
			"rsync://rpki.example.com/member_repository/a"},
		out)
}
