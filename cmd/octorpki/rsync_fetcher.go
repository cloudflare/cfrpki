package main

import (
	"sync"

	"github.com/opentracing/opentracing-go"
)

type rsyncFetcher struct {
	octoRPKI *OctoRPKI
	jobsCh   chan string
	wg       sync.WaitGroup
	span     opentracing.Span
}

func newRsyncFetcher(octoRPKI *OctoRPKI, workers int, span opentracing.Span) *rsyncFetcher {
	rf := &rsyncFetcher{
		octoRPKI: octoRPKI,
		jobsCh:   make(chan string),
		span:     span,
	}

	for i := 0; i < workers; i++ {
		rf.wg.Add(1)
		go rf.worker()
	}

	return rf
}

func (r *rsyncFetcher) worker() {
	defer r.wg.Done()

	for rsyncURL := range r.jobsCh {
		r.octoRPKI.fetchRsync(rsyncURL, r.span)
	}
}

func (r *rsyncFetcher) done() {
	close(r.jobsCh)
}

func (r *rsyncFetcher) wait() {
	r.wg.Wait()
}

func (r *rsyncFetcher) fetch(rsync string) {
	r.jobsCh <- rsync
}
