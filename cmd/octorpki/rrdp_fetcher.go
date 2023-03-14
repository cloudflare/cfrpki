package main

import (
	"sync"

	"github.com/opentracing/opentracing-go"
)

type rrdpFetchJob struct {
	path  string
	rsync string
}

type rrdpFetcher struct {
	octoRPKI *OctoRPKI
	jobsCh   chan rrdpFetchJob
	wg       sync.WaitGroup
	span     opentracing.Span
}

func newRRDPFetcher(octoRPKI *OctoRPKI, workers int, span opentracing.Span) *rrdpFetcher {
	rf := &rrdpFetcher{
		octoRPKI: octoRPKI,
		jobsCh:   make(chan rrdpFetchJob),
		span:     span,
	}

	for i := 0; i < workers; i++ {
		rf.wg.Add(1)
		go rf.worker()
	}

	return rf
}

func (r *rrdpFetcher) worker() {
	defer r.wg.Done()

	for job := range r.jobsCh {
		r.octoRPKI.fetchRRDP(job.path, job.rsync, r.span)
	}
}

func (r *rrdpFetcher) done() {
	close(r.jobsCh)
}

func (r *rrdpFetcher) wait() {
	r.wg.Wait()
}

func (r *rrdpFetcher) fetch(path string, rsync string) {
	r.jobsCh <- rrdpFetchJob{
		path:  path,
		rsync: rsync,
	}
}
