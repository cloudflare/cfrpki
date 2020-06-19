package syncpki

import (
	"fmt"
	"github.com/getsentry/sentry-go"
	"net/http"
	"runtime"
)

const (
	ERROR_RRDP_UNKNOWN = iota
	ERROR_RRDP_FETCH
)

type stack []uintptr
type Frame uintptr

var (
	ErrorTypeToName = map[int]string{
		ERROR_RRDP_UNKNOWN: "unknown",
		ERROR_RRDP_FETCH:   "fetch",
	}
)

type RRDPError struct {
	EType int

	InnerErr error
	Message  string

	Request *http.Request

	URL, Rsync string

	Stack *stack
}

func callers() *stack {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	var st stack = pcs[0:n]
	return &st
}

// This function returns the Stacktrace of the error.
// The naming scheme corresponds to what Sentry fetches
// https://github.com/getsentry/sentry-go/blob/master/stacktrace.go#L49
func StackTrace(s *stack) []Frame {
	f := make([]Frame, len(*s))
	for i := 0; i < len(f); i++ {
		f[i] = Frame((*s)[i])
	}
	return f
}

func (e *RRDPError) StackTrace() []Frame {
	return StackTrace(e.Stack)
}

func (e *RRDPError) Error() string {
	repoinfo := "for repo"
	if e.URL != "" {
		repoinfo = fmt.Sprintf("for repo rrdp:%s (rsync:%s)", e.URL, e.Rsync)
	}

	var err string
	if e.InnerErr != nil {
		err = fmt.Sprintf(": %s", e.InnerErr.Error())
	}

	return fmt.Sprintf("%s %s%v", e.Message, repoinfo, err)
}

func (e *RRDPError) SetSentryScope(scope *sentry.Scope) {
	scope.SetTag("Type", ErrorTypeToName[e.EType])
	if e.URL != "" {
		scope.SetTag("Repository.RRDP", e.URL)
	}
	if e.Rsync != "" {
		scope.SetTag("Repository.rsync", e.Rsync)
	}
	if e.Request != nil {
		scope.SetRequest(e.Request)
	}
}

func (e *RRDPError) SetURL(rrdp, rsync string) {
	e.URL = rrdp
	e.Rsync = rsync
}

func NewRRDPErrorFetch(request *http.Request, err error) *RRDPError {
	return &RRDPError{
		EType:    ERROR_RRDP_FETCH,
		Request:  request,
		InnerErr: err,
		Message:  "error fetching",
		Stack:    callers(),
	}
}
