package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	syncpki "github.com/cloudflare/cfrpki/sync/lib"
	librpki "github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"

	"github.com/rs/cors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cloudflare/gortr/prefixfile"
	log "github.com/sirupsen/logrus"

	// Debugging
	"net/http/pprof"

	"github.com/getsentry/sentry-go"
	"github.com/opentracing/opentracing-go"
	jcfg "github.com/uber/jaeger-client-go/config"
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "OctoRPKI " + version + " " + buildinfos
	AllowRoot  = flag.Bool("allow.root", false, "Allow starting as root")

	// Validator Options
	RootTAL       = flag.String("tal.root", "tals/afrinic.tal,tals/apnic.tal,tals/arin.tal,tals/lacnic.tal,tals/ripe.tal", "List of TAL separated by comma")
	TALNames      = flag.String("tal.name", "AFRINIC,APNIC,ARIN,LACNIC,RIPE", "Name of the TALs")
	UseManifest   = flag.Bool("manifest.use", true, "Use manifests file to explore instead of going into the repository")
	Basepath      = flag.String("cache", "cache/", "Base directory to store certificates")
	LogLevel      = flag.String("loglevel", "info", "Log level")
	Refresh       = flag.Duration("refresh", time.Minute*20, "Revalidation interval")
	MaxIterations = flag.Int("max.iterations", 32, "Specify the max number of iterations octorpki will make before failing to generate output.json")

	StrictManifests = flag.Bool("strict.manifests", true, "Manifests must be complete or invalidate CA")
	StrictHash      = flag.Bool("strict.hash", true, "Check the hash of files")
	StrictCms       = flag.Bool("strict.cms", false, "Decode CMS with strict settings")

	// Rsync Options
	RsyncTimeout = flag.Duration("rsync.timeout", time.Minute*20, "Rsync command timeout")
	RsyncBin     = flag.String("rsync.bin", DefaultBin(), "The rsync binary to use")

	// RRDP Options
	RRDP         = flag.Bool("rrdp", true, "Enable RRDP fetching")
	RRDPFile     = flag.String("rrdp.file", "cache/rrdp.json", "Save RRDP state")
	RRDPFailover = flag.Bool("rrdp.failover", true, "Failover to rsync when RRDP fails")
	UserAgent    = flag.String("useragent", fmt.Sprintf("Cloudflare-RRDP-%v (+https://github.com/cloudflare/cfrpki)", AppVersion), "User-Agent header")

	Mode       = flag.String("mode", "server", "Select output mode (server/oneoff)")
	WaitStable = flag.Bool("output.wait", true, "Wait until stable state to create the file (returns 503 when unstable on HTTP)")

	// Serving Options
	Addr        = flag.String("http.addr", ":8081", "Listening address")
	CacheHeader = flag.Bool("http.cache", true, "Enable cache header")
	MetricsPath = flag.String("http.metrics", "/metrics", "Prometheus metrics endpoint")
	InfoPath    = flag.String("http.info", "/infos", "Information URL")
	HealthPath  = flag.String("http.health", "/health", "Health URL")

	CorsOrigins = flag.String("cors.origins", "*", "Cors origins separated by comma")
	CorsCreds   = flag.Bool("cors.creds", false, "Cors enable credentials")

	// File option
	Output           = flag.String("output.roa", "output.json", "Output ROA file or URL")
	Sign             = flag.Bool("output.sign", true, "Sign output (GoRTR compatible)")
	SignKey          = flag.String("output.sign.key", "private.pem", "ECDSA signing key")
	ValidityDuration = flag.Duration("output.sign.validity", time.Hour, "Validity")

	// Debugging options
	Pprof     = flag.Bool("pprof", false, "Enable pprof endpoint")
	Tracer    = flag.Bool("tracer", false, "Enable tracer")
	SentryDSN = flag.String("sentry.dsn", "", "Send errors to Sentry")

	Version = flag.Bool("version", false, "Print version")

	CertRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	CertRRDP       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 13}
)

var (
	MetricSIACounts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "file_count_sia",
			Help: "Counts of file per SIA.",
		},
		[]string{"address", "type"},
	)
	MetricRsyncErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rsync_errors",
			Help: "Rsync error count.",
		},
		[]string{"address"},
	)
	MetricRRDPErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rrdp_errors",
			Help: "RRDP error count.",
		},
		[]string{"address"},
	)
	MetricRRDPSerial = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rrdp_serial",
			Help: "RRDP serial number.",
		},
		[]string{"address"},
	)
	MetricROAsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "roas",
			Help: "Bytes received by the application.",
		},
		[]string{"ta"},
	)
	MetricState = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "state",
			Help: "State of the Relying party (1 = stable, 0 = unstable).",
		},
	)
	MetricLastStableValidation = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "last_stable_validation",
			Help: "Timestamp of last stable validation.",
		},
	)
	MetricLastValidation = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "last_validation",
			Help: "Timestamp of last validation.",
		},
	)
	MetricOperationTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "operation_time",
			Help:       "Time to run an operation.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"type"},
	)
	MetricLastFetch = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "last_fetch",
			Help: "RRDP/Rsync last timestamp.",
		},
		[]string{"address", "type"},
	)
)

func DefaultBin() string {
	path, _ := exec.LookPath("rsync")
	return path
}

type RRDPInfo struct {
	RsyncURL  string `json:"rsync"`
	Path      string `json:"path"`
	SessionID string `json:"sessionid"`
	Serial    int64  `json:"serial"`
}

var errKeyNotParsed = fmt.Errorf("Failed to PEM decode key")

func ReadKey(key []byte, isPem bool) (*ecdsa.PrivateKey, error) {
	if isPem {
		block, _ := pem.Decode(key)
		if block == nil {
			return nil, errKeyNotParsed
		}
		key = block.Bytes
	}

	k, err := x509.ParseECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return k, nil
}

type Stats struct {
	URI       string  `json:"uri"`
	Count     int     `json:"file-count"`
	Iteration int     `json:"iteration"`
	Errors    int     `json:"errors"`
	Duration  float64 `json:"duration"`

	LastFetch      int `json:"last-fetch"`
	LastFetchError int `json:"last-fetch-error,omitempty"`

	RRDPSerial    int64  `json:"rrdp-serial,omitempty"`
	RRDPSessionID string `json:"rrdp-sessionid,omitempty"`
	RRDPLastFile  string `json:"rrdp-last-file,omitempty"`

	LastError string `json:"last-error,omitempty"`
}

type OctoRPKI struct {
	Tals      []*pki.PKIFile
	TalsFetch map[string]*librpki.RPKITAL
	TalNames  []string

	LastComputed time.Time
	Key          *ecdsa.PrivateKey

	Stable            atomic.Bool // Indicates something has been added to the fetch list (rsync or rrdp)
	HasPreviousStable atomic.Bool
	Fetcher           *syncpki.LocalFetch
	HTTPFetcher       *syncpki.HTTPFetcher

	PrevRepos    map[string]time.Time
	CurrentRepos map[string]time.Time

	RRDPFetch       map[string]string // maps from RRDP Url to rsync URL
	RRDPFetchDomain map[string]string

	RsyncFetchJobs map[string]string

	RRDPInfo map[string]RRDPInfo

	ROAList   *prefixfile.ROAList
	ROAListMu sync.RWMutex

	InfoAuthorities     [][]SIA
	InfoAuthoritiesLock sync.RWMutex

	stats  *octoRPKIStats
	tracer opentracing.Tracer
}

type octoRPKIStats struct {
	RRDPStats          map[string]*Stats
	RsyncStats         map[string]*Stats
	ValidationDuration time.Duration
	Iteration          int
	ROAsTALsCount      []ROAsTAL
}

func newOctoRPKIStats() *octoRPKIStats {
	return &octoRPKIStats{
		RsyncStats:    make(map[string]*Stats),
		RRDPStats:     make(map[string]*Stats),
		ROAsTALsCount: make([]ROAsTAL, 0),
	}
}

func (s *OctoRPKI) MainReduce() bool {
	t1 := time.Now()
	defer func() {
		t2 := time.Now()
		MetricOperationTime.With(prometheus.Labels{"type": "reduce"}).Observe(float64(t2.Sub(t1).Seconds()))
	}()

	var hasChanged bool
	for rsync, ts := range s.CurrentRepos {
		if _, ok := s.PrevRepos[rsync]; !ok {
			s.PrevRepos[rsync] = ts
			hasChanged = true
			log.Debugf("Repository %s has appeared at %v", rsync, ts)
		}
	}

	// Init deletion of folder if missing from current

	s.Fetcher.SetRepositories(s.CurrentRepos)

	if len(s.PrevRepos) != len(s.CurrentRepos) {
		return true
	}

	return hasChanged
}

func ExtractRsyncDomain(rsyncURL string) (string, error) {
	if !strings.HasPrefix(rsyncURL, syncpki.RsyncProtoPrefix) {
		return "", fmt.Errorf("%q is not an rsync URL", rsyncURL)
	}

	return strings.Split(strings.TrimPrefix(rsyncURL, syncpki.RsyncProtoPrefix), "/")[0], nil
}

func (s *OctoRPKI) WriteRsyncFileOnDisk(rsyncURL string, data []byte) error {
	fPath := mustExtractFoldersPathFromRsyncURL(rsyncURL)
	mustMkdirAll(fPath)
	filePath := mustExtractFilePathFromRsyncURL(rsyncURL)

	// GHSA-8459-6rc9-8vf8: Prevent parent directory writes outside of Basepath
	if strings.Contains(filePath, "../") || strings.Contains(filePath, "..\\") {
		return fmt.Errorf("Path %q contains illegal path element", filePath)
	}

	fp := filepath.Join(*Basepath, filePath)
	err := ioutil.WriteFile(fp, data, 0600)
	if err != nil {
		return fmt.Errorf("Unable to write file %q: %v", fp, err)
	}

	return nil
}

func mustMkdirAll(fPath string) {
	err := os.MkdirAll(filepath.Join(*Basepath, fPath), os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}
}

func mustExtractFilePathFromRsyncURL(rsyncURL string) string {
	fPath, err := syncpki.ExtractFilePathFromRsyncURL(rsyncURL)
	if err != nil {
		log.Fatalf("Unable to extract file path from rsync url: %v", err)
	}

	return fPath
}

func (s *OctoRPKI) ReceiveRRDPFileCallback(main string, url string, path string, data []byte, withdraw bool, snapshot bool, serial int64, args ...interface{}) error {
	if len(args) > 0 {
		rsync, ok := args[0].(string)
		if ok && !strings.Contains(path, rsync) {
			log.Errorf("rrdp: %s is outside directory %s", path, rsync)
			return nil
		}
	}

	err := s.WriteRsyncFileOnDisk(path, data)
	if err != nil {
		return fmt.Errorf("Unable to write sync file %q on disk: %v", path, err)
	}

	MetricSIACounts.With(prometheus.Labels{"address": main, "type": "rrdp"}).Inc()
	s.stats.RRDPStats[main].Count++
	s.stats.RRDPStats[main].RRDPLastFile = url
	return nil
}

func (s *OctoRPKI) LoadRRDPInfo(file string) error {
	fc, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("Unable to read file %q: %v", file, err)
	}

	s.RRDPInfo = make(map[string]RRDPInfo)
	err = json.Unmarshal(fc, &s.RRDPInfo)
	if err != nil {
		return fmt.Errorf("JSON unmarshal failed: %v", err)
	}

	return nil
}

func (s *OctoRPKI) saveRRDPInfo(file string) error {
	fc, err := json.Marshal(s.RRDPInfo)
	if err != nil {
		return fmt.Errorf("JSON marshal failed: %v", err)
	}

	err = ioutil.WriteFile(file, fc, 0600)
	if err != nil {
		return fmt.Errorf("Unable to write file %q: %v", file, err)
	}

	return nil
}

func (s *OctoRPKI) mainRRDP(pSpan opentracing.Span) {
	span := s.tracer.StartSpan("rrdp", opentracing.ChildOf(pSpan.Context()))
	defer span.Finish()

	for path, rsync := range s.RRDPFetch {
		s.fetchRRDP(path, rsync, span)
	}
}

func (s *OctoRPKI) fetchRRDP(path string, rsyncURL string, span opentracing.Span) {
	rSpan := s.tracer.StartSpan("sync", opentracing.ChildOf(span.Context()))
	defer rSpan.Finish()

	rSpan.SetTag("rrdp", path)
	rSpan.SetTag("rsync", rsyncURL)
	rSpan.SetTag("type", "rrdp")
	log.Infof("RRDP sync %v", path)

	MetricSIACounts.With(prometheus.Labels{"address": path, "type": "rrdp"}).Set(0)

	if _, exists := s.stats.RRDPStats[path]; !exists {
		s.stats.RRDPStats[path] = &Stats{}
	}

	s.stats.RRDPStats[path].URI = path
	s.stats.RRDPStats[path].Iteration++
	s.stats.RRDPStats[path].Count = 0

	t1 := time.Now()

	rrdp := s.getRRDPSystem(path, rsyncURL)

	err := rrdp.FetchRRDP(s.RRDPFetchDomain[path])
	t2 := time.Now()
	if err != nil {
		s.rrdpError(rsyncURL, path, err, t1, t2, rSpan, rrdp)
		return
	}

	log.Debugf("Success fetching %s, removing rsync %s", path, rsyncURL)
	delete(s.RsyncFetchJobs, rsyncURL)

	rSpan.LogKV("event", "rrdp", "type", "success", "message", "rrdp successfully fetched")
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelInfo)
		scope.SetTag("Rsync", rsyncURL)
		scope.SetTag("RRDP", path)
		rrdp.SetSentryScope(scope)
		sentry.CaptureMessage("fetched rrdp successfully")
	})

	MetricRRDPSerial.With(prometheus.Labels{"address": path}).Set(float64(rrdp.Serial))

	lastFetch := time.Now().Unix()
	MetricLastFetch.With(prometheus.Labels{"address": path, "type": "rrdp"}).Set(float64(lastFetch))

	s.stats.RRDPStats[path].LastFetch = int(lastFetch)
	s.stats.RRDPStats[path].RRDPSerial = rrdp.Serial
	s.stats.RRDPStats[path].RRDPSessionID = rrdp.SessionID
	s.stats.RRDPStats[path].Duration = t2.Sub(t1).Seconds()

	s.RRDPInfo[rsyncURL] = RRDPInfo{
		RsyncURL:  rsyncURL,
		Path:      path,
		SessionID: rrdp.SessionID,
		Serial:    rrdp.Serial,
	}
}

func (s *OctoRPKI) getRRDPSystem(path string, rsync string) *syncpki.RRDPSystem {
	return &syncpki.RRDPSystem{
		Callback:  s.ReceiveRRDPFileCallback,
		Path:      path,
		Fetcher:   s.HTTPFetcher,
		SessionID: s.RRDPInfo[rsync].SessionID,
		Serial:    s.RRDPInfo[rsync].Serial,
		Log:       log.StandardLogger(),
	}
}

func (s *OctoRPKI) rrdpError(rsyncURL string, path string, err error, t1 time.Time, t2 time.Time, rSpan opentracing.Span, rrdp *syncpki.RRDPSystem) {
	rSpan.SetTag("error", true)
	sentry.WithScope(func(scope *sentry.Scope) {
		if errC, ok := err.(interface{ SetURL(string, string) }); ok {
			errC.SetURL(path, rsyncURL)
		}
		if errC, ok := err.(interface{ SetSentryScope(*sentry.Scope) }); ok {
			errC.SetSentryScope(scope)
		}
		rrdp.SetSentryScope(scope)
		scope.SetTag("Rsync", rsyncURL)
		scope.SetTag("RRDP", path)
		sentry.CaptureException(err)
	})

	// GHSA-g9wh-3vrx-r7hg: Do not process responses that are too large
	if *RRDPFailover && err.Error() != "http: request body too large" {
		log.Errorf("Error when processing %v (for %v): %v. Will add to rsync.", path, rsyncURL, err)
		rSpan.LogKV("event", "rrdp failure", "type", "failover to rsync", "message", err)
	} else {
		log.Errorf("Error when processing %v (for %v): %v.Skipping failover to rsync.", path, rsyncURL, err)
		rSpan.LogKV("event", "rrdp failure", "type", "skipping failover to rsync", "message", err)
		delete(s.RsyncFetchJobs, rsyncURL)
	}

	MetricRRDPErrors.With(prometheus.Labels{"address": path}).Inc()
	s.stats.RRDPStats[path].Errors++
	s.stats.RRDPStats[path].LastFetchError = int(time.Now().Unix())
	s.stats.RRDPStats[path].LastError = err.Error()
	s.stats.RRDPStats[path].Duration = t2.Sub(t1).Seconds()
}

func (s *OctoRPKI) mainRsync(pSpan opentracing.Span) {
	t1 := time.Now()
	span := s.tracer.StartSpan("rsync", opentracing.ChildOf(pSpan.Context()))
	defer span.Finish()

	for uri := range s.RsyncFetchJobs {
		s.fetchRsync(uri, span)
	}

	t2 := time.Now()
	MetricOperationTime.With(prometheus.Labels{"type": "rsync"}).Observe(float64(t2.Sub(t1).Seconds()))
}

func mustExtractFoldersPathFromRsyncURL(rsyncURL string) string {
	downloadPath, err := syncpki.ExtractFoldersPathFromRsyncURL(rsyncURL)
	if err != nil {
		log.Fatalf("Failed to extract folder path from rsync URL: %v", err)
	}

	return downloadPath
}

func (s *OctoRPKI) fetchRsync(uri string, span opentracing.Span) {
	rSpan := s.tracer.StartSpan("sync", opentracing.ChildOf(span.Context()))
	defer rSpan.Finish()
	rSpan.SetTag("rsync", uri)
	rSpan.SetTag("type", "rsync")

	log.Infof("Rsync sync %v", uri)
	downloadPath := mustExtractFoldersPathFromRsyncURL(uri)

	if _, exists := s.stats.RsyncStats[uri]; !exists {
		s.stats.RsyncStats[uri] = &Stats{}
	}

	s.stats.RsyncStats[uri].URI = uri
	s.stats.RsyncStats[uri].Iteration++
	s.stats.RsyncStats[uri].Count = 0

	path := filepath.Join(*Basepath, downloadPath)
	ctxRsync, cancelRsync := context.WithTimeout(context.Background(), *RsyncTimeout)
	t1 := time.Now()
	files, err := syncpki.RunRsync(ctxRsync, uri, *RsyncBin, path)
	t2 := time.Now()
	if err != nil {
		s.rsyncError(uri, path, err, t1, t2, rSpan)
	} else {
		rSpan.LogKV("event", "rsync", "type", "success", "message", "rsync successfully fetched")
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelInfo)
			scope.SetTag("Rsync", uri)
			sentry.CaptureMessage("fetched rsync successfully")
		})
	}
	cancelRsync()

	MetricSIACounts.With(prometheus.Labels{"address": uri, "type": "rsync"}).Set(float64(len(files)))
	lastFetch := time.Now().Unix()
	MetricLastFetch.With(prometheus.Labels{"address": uri, "type": "rsync"}).Set(float64(lastFetch))

	s.stats.RsyncStats[uri].LastFetch = int(lastFetch)
	s.stats.RsyncStats[uri].Count = len(files)
	s.stats.RsyncStats[uri].Duration = t2.Sub(t1).Seconds()

}

func (s *OctoRPKI) rsyncError(uri string, path string, err error, t1 time.Time, t2 time.Time, rSpan opentracing.Span) {
	rSpan.SetTag("error", true)
	rSpan.LogKV("event", "rsync failure", "message", err)
	log.Errorf("Error when processing %v: %v. Will add to rsync.", path, err)
	sentry.WithScope(func(scope *sentry.Scope) {
		if errC, ok := err.(interface{ SetRsync(string) }); ok {
			errC.SetRsync(uri)
		}
		if errC, ok := err.(interface{ SetSentryScope(*sentry.Scope) }); ok {
			errC.SetSentryScope(scope)
		}
		scope.SetTag("Rsync", uri)
		sentry.CaptureException(err)
	})

	MetricRsyncErrors.With(prometheus.Labels{"address": uri}).Inc()

	s.stats.RsyncStats[uri].Errors++
	s.stats.RsyncStats[uri].LastFetchError = int(time.Now().Unix())
	s.stats.RsyncStats[uri].LastError = err.Error()
}

func filterDuplicates(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	roaListNoDup := make([]prefixfile.ROAJson, 0)
	hmap := make(map[string]bool)
	for _, roa := range roalist {
		k := roa.String()
		_, present := hmap[k]
		if !present {
			hmap[k] = true
			roaListNoDup = append(roaListNoDup, roa)
		}
	}
	return roaListNoDup
}

func setJaegerError(l []interface{}, err error) []interface{} {
	return append(l, "error", true, "message", err)
}

// Fetches RFC8630-type TAL
func (s *OctoRPKI) mainTAL(pSpan opentracing.Span) {
	t1 := time.Now()
	span := s.tracer.StartSpan("tal", opentracing.ChildOf(pSpan.Context()))
	defer span.Finish()

	for path, tal := range s.TalsFetch {
		s.fetchTAL(path, tal, span)
	}

	t2 := time.Now()
	MetricOperationTime.With(prometheus.Labels{"type": "tal"}).Observe(float64(t2.Sub(t1).Seconds()))
}

func (s *OctoRPKI) fetchTAL(path string, tal *librpki.RPKITAL, span opentracing.Span) {
	tSpan := s.tracer.StartSpan("tal-fetch", opentracing.ChildOf(span.Context()))
	defer tSpan.Finish()
	tSpan.SetTag("tal", path)

	success, successURL := s._fetchTAL(tal, path, span)
	if success {
		log.Infof("Successfully downloaded root certificate for %s at %s", path, successURL)
		return
	}

	// Fail over to rsync
	if *RRDPFailover && tal.HasRsync() {
		rsync := tal.GetRsyncURI()
		log.Infof("Root certificate for %s will be downloaded using rsync: %s", path, rsync)
		s.RsyncFetchJobs[rsync] = ""
		tSpan.SetTag("failover-rsync", true)
		return
	}

	log.Errorf("Could not download root certificate for %s", path)
	tSpan.SetTag("error", true)

}

func (s *OctoRPKI) _fetchTAL(tal *librpki.RPKITAL, path string, tSpan opentracing.Span) (success bool, successURL string) {
	for _, uri := range tal.URI {
		success, successURL := s.fetchTALurl(tal, uri, path, tSpan)
		if success {
			return success, successURL
		}
	}

	return false, ""
}

func (s *OctoRPKI) fetchTALurl(tal *librpki.RPKITAL, uri string, path string, tSpan opentracing.Span) (success bool, successURL string) {
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		return false, ""
	}

	tfSpan := s.tracer.StartSpan("tal-fetch-uri", opentracing.ChildOf(tSpan.Context()))
	defer tfSpan.Finish()
	tfSpan.SetTag("uri", uri)

	sHub := sentry.CurrentHub().Clone()
	sHub.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("tal.uri", uri)
		scope.SetTag("tal.path", path)
	})

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		tfSpan.SetTag("error", true)
		tfSpan.SetTag("message", err)
		log.Errorf("error while trying to fetch: %s: %v", uri, err)
		return false, ""
	}
	req.Header.Set("User-Agent", s.HTTPFetcher.UserAgent)

	sHub.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetRequest(req)
	})

	sbc := &sentry.Breadcrumb{
		Message:  fmt.Sprintf("GET | %s", uri),
		Category: "http",
	}

	// maybe add a limit in the client? To avoid downloading huge files (that wouldn't be certs)
	resp, err := s.HTTPFetcher.Client.Do(req)
	if err != nil {
		tfSpan.SetTag("error", true)
		tfSpan.SetTag("message", err)

		sbc.Level = sentry.LevelError
		sHub.AddBreadcrumb(sbc, nil)
		log.Errorf("error while trying to fetch: %s: %v", uri, err)
		sHub.CaptureException(err)
		return false, ""
	}

	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("http server replied: %s", resp.Status)

		tfSpan.SetTag("error", true)
		tfSpan.SetTag("message", msg)

		sHub.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelError)
		})
		sbc.Level = sentry.LevelError
		sHub.AddBreadcrumb(sbc, nil)

		log.Errorf("http server replied: %s while trying to fetch %s", resp.Status, uri)
		sHub.CaptureMessage(msg)
		return false, ""
	}

	sHub.AddBreadcrumb(sbc, nil)

	// check body / status code
	data, err := ioutil.ReadAll(resp.Body)
	tfSpan.LogKV("size", len(data))
	if err != nil {
		tfSpan.SetTag("error", true)
		tfSpan.SetTag("message", err)

		log.Errorf("error while trying to fetch: %s: %v", uri, err)
		sHub.CaptureException(err)
		return false, ""
	}

	// Plan option to store everything in memory
	err = s.WriteRsyncFileOnDisk(tal.GetRsyncURI(), data)
	if err != nil {
		tfSpan.SetTag("error", true)
		tfSpan.SetTag("message", err)

		log.Errorf("error while trying to fetch: %s: %v", uri, err)
		sHub.CaptureException(err)
		return false, ""
	}

	sHub.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelInfo)
		sHub.CaptureMessage("fetched http tal cert successfully")
	})

	return true, uri
}

func logCollector(sm *pki.SimpleManager, tal *pki.PKIFile, tSpan opentracing.Span) {
	for err := range sm.Errors {
		tSpan.SetTag("error", true)
		tSpan.LogKV("event", "resource issue", "type", "skipping resource", "message", err)
		log.Error(err)
		sentry.WithScope(func(scope *sentry.Scope) {
			if errC, ok := err.(interface{ SetSentryScope(*sentry.Scope) }); ok {
				errC.SetSentryScope(scope)
			}
			scope.SetTag("TrustAnchor", tal.Path)
			sentry.CaptureException(err)
		})
	}
}

func (s *OctoRPKI) generateROAList(pkiManagers []*pki.SimpleManager, span opentracing.Span) *prefixfile.ROAList {
	roalist := &prefixfile.ROAList{
		Data: make([]prefixfile.ROAJson, 0),
	}
	var counts int
	s.stats.ROAsTALsCount = make([]ROAsTAL, 0)
	for i, tal := range s.Tals {
		eSpan := s.tracer.StartSpan("extract", opentracing.ChildOf(span.Context()))
		eSpan.SetTag("tal", tal.Path)
		talname := tal.Path
		if len(s.TalNames) == len(s.Tals) {
			talname = s.TalNames[i]
		}

		var counttal int
		for _, obj := range pkiManagers[i].Validator.ValidROA {
			roa := obj.Resource.(*librpki.RPKIROA)

			for _, entry := range roa.Valids {
				oroa := prefixfile.ROAJson{
					ASN:    fmt.Sprintf("AS%v", roa.ASN),
					Prefix: entry.IPNet.String(),
					Length: uint8(entry.MaxLength),
					TA:     talname,
				}
				roalist.Data = append(roalist.Data, oroa)
				counts++
				counttal++
			}
		}
		eSpan.Finish()

		s.stats.ROAsTALsCount = append(s.stats.ROAsTALsCount, ROAsTAL{TA: talname, Count: counttal})
		MetricROAsCount.With(prometheus.Labels{"ta": talname}).Set(float64(counttal))
	}
	curTime := time.Now()
	s.LastComputed = curTime
	validTime := curTime.Add(*ValidityDuration)
	roalist.Metadata = prefixfile.MetaData{
		Counts:    counts,
		Generated: int(curTime.Unix()),
		Valid:     int(validTime.Unix()),
	}

	roalist.Data = filterDuplicates(roalist.Data)
	if *Sign {
		s.signROAList(roalist, span)
	}

	return roalist
}

func (s *OctoRPKI) signROAList(roaList *prefixfile.ROAList, span opentracing.Span) {
	sSpan := s.tracer.StartSpan("sign", opentracing.ChildOf(span.Context()))
	defer sSpan.Finish()

	signdate, sign, err := roaList.Sign(s.Key)
	if err != nil {
		log.Error(err)
		sentry.CaptureException(err)
	}
	roaList.Metadata.Signature = sign
	roaList.Metadata.SignatureDate = signdate
}

func (s *OctoRPKI) mainValidation(pSpan opentracing.Span) {
	t1 := time.Now()
	ia := make([][]SIA, len(s.Tals))
	for i := 0; i < len(ia); i++ {
		ia[i] = make([]SIA, 0)
	}
	iatmp := make(map[string]*SIA)

	span := s.tracer.StartSpan("validation", opentracing.ChildOf(pSpan.Context()))
	defer span.Finish()

	pkiManagers := make([]*pki.SimpleManager, len(s.Tals))
	for i, tal := range s.Tals {
		tSpan := s.tracer.StartSpan("explore", opentracing.ChildOf(span.Context()))
		tSpan.SetTag("tal", tal.Path)

		validator := pki.NewValidator()
		validator.DecoderConfig.ValidateStrict = *StrictCms

		sm := pki.NewSimpleManager()
		pkiManagers[i] = sm
		pkiManagers[i].ReportErrors = true
		pkiManagers[i].Validator = validator
		pkiManagers[i].FileSeeker = s.Fetcher
		pkiManagers[i].Log = log.StandardLogger()
		pkiManagers[i].StrictHash = *StrictHash
		pkiManagers[i].StrictManifests = *StrictManifests

		go logCollector(sm, tal, tSpan)

		pkiManagers[i].AddInitial([]*pki.PKIFile{tal})
		countExplore := pkiManagers[i].Explore(!*UseManifest, false)

		// Insertion of SIAs in db to allow rsync to update the repos
		var count int
		for _, obj := range pkiManagers[i].Validator.TALs {
			tal := obj.Resource.(*librpki.RPKITAL)
			if !obj.CertTALValid {
				s.TalsFetch[obj.File.Path] = tal
			}
			count++
		}

		for _, pkiResource := range pkiManagers[i].Validator.ValidObjects {
			if pkiResource.Type != pki.TYPE_CER {
				continue
			}

			cer := pkiResource.Resource.(*librpki.RPKICertificate)
			rsyncGeneralName := cer.GetRsyncGeneralName()
			rrdpGeneralName := cer.GetRRDPGeneralName()

			gnExtracted, gnExtractedDomain, err := syncpki.ExtractRsyncDomainModule(rsyncGeneralName)
			if err != nil {
				log.Errorf("Could not add cert rsync %s due to %v", rsyncGeneralName, err)
				continue
			}

			if cer.HasRRDP() {
				prev, ok := s.RRDPFetchDomain[rrdpGeneralName]
				if ok && prev != gnExtractedDomain {
					log.Errorf("rrdp %s tries to override %s with %s", rrdpGeneralName, prev, gnExtractedDomain)
					continue
				}
				s.RRDPFetchDomain[rrdpGeneralName] = gnExtractedDomain
				s.RRDPFetch[rrdpGeneralName] = gnExtracted
			}
			s.RsyncFetchJobs[gnExtracted] = rrdpGeneralName
			s.CurrentRepos[gnExtracted] = time.Now()
			count++

			// map the rrdp and rsync by TAL for info page
			sia, ok := iatmp[gnExtracted]
			if !ok {
				tmpSIA := SIA{
					gnExtracted,
					rrdpGeneralName,
				}
				ia[i] = append(ia[i], tmpSIA)
				sia = &(ia[i][len(ia[i])-1])
				iatmp[gnExtracted] = sia
			}
			sia.Rsync = gnExtracted
			sia.RRDP = rrdpGeneralName
		}
		sm.Close()
		tSpan.LogKV("count-valid", count, "count-total", countExplore)
		tSpan.Finish()
	}

	s.setInfoAuthorities(ia)
	s.setROAList(s.generateROAList(pkiManagers, span))

	t2 := time.Now()
	s.stats.ValidationDuration = t2.Sub(t1)
	MetricOperationTime.With(prometheus.Labels{"type": "validation"}).Observe(float64(s.stats.ValidationDuration.Seconds()))
	MetricLastValidation.Set(float64(s.LastComputed.Unix()))
}

func (s *OctoRPKI) setInfoAuthorities(ia [][]SIA) {
	s.InfoAuthoritiesLock.Lock()
	defer s.InfoAuthoritiesLock.Unlock()

	s.InfoAuthorities = ia
}

func (s *OctoRPKI) setROAList(roaList *prefixfile.ROAList) {
	s.ROAListMu.Lock()
	defer s.ROAListMu.Unlock()

	s.ROAList = roaList
}

func (s *OctoRPKI) getROAList() *prefixfile.ROAList {
	s.ROAListMu.RLock()
	defer s.ROAListMu.RUnlock()

	return s.ROAList
}

func (s *OctoRPKI) ServeROAs(w http.ResponseWriter, r *http.Request) {
	if !s.Stable.Load() && *WaitStable && !s.HasPreviousStable.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("File not ready yet"))
		return
	}

	upTo := s.LastComputed.Add(*ValidityDuration)
	maxAge := int(upTo.Sub(time.Now()).Seconds())

	w.Header().Set("Content-Type", "application/json")

	if maxAge > 0 && *CacheHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%v", maxAge))
	}

	roaList := s.getROAList()

	etag := sha256.New()
	etag.Write([]byte(fmt.Sprintf("%v/%v", roaList.Metadata.Generated, roaList.Metadata.Counts)))
	etagSum := etag.Sum(nil)
	etagSumHex := hex.EncodeToString(etagSum)

	if match := r.Header.Get("If-None-Match"); match != "" {
		if match == etagSumHex {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	w.Header().Set("Etag", etagSumHex)
	enc := json.NewEncoder(w)
	enc.Encode(roaList)
}

func (s *OctoRPKI) ServeHealth(w http.ResponseWriter, r *http.Request) {
	if s.Stable.Load() || s.HasPreviousStable.Load() {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte("Not ready yet"))
}

type SIA struct {
	Rsync string `json:"rsync"`
	RRDP  string `json:"rrdp,omitempty"`
}

type ROAsTAL struct {
	TA    string `json:"ta,omitempty"`
	Count int    `json:"count,omitempty"`
}

type InfoAuthorities struct {
	TA  string `json:"name"`
	Sia []SIA  `json:"sia"`
}

type InfoResult struct {
	Stable             bool              `json:"stable"`
	TAs                []InfoAuthorities `json:"tas"`
	Iteration          int               `json:"iteration"`
	LastValidation     int               `json:"validation-last"`
	ValidationDuration float64           `json:"validation-duration"`
	ROAsTALs           []ROAsTAL         `json:"roas-tal-count"`
	ROACount           int               `json:"roas-count"`
}

func (s *OctoRPKI) ServeInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.InfoAuthoritiesLock.RLock()
	ia := s.InfoAuthorities
	s.InfoAuthoritiesLock.RUnlock()

	ias := make([]InfoAuthorities, 0)
	for i, tal := range s.Tals {

		if len(ia) <= i {
			break
		}
		if ia[i] == nil {
			continue
		}

		talname := tal.Path
		if len(s.TalNames) == len(s.Tals) {
			talname = s.TalNames[i]
		}

		ias = append(ias, InfoAuthorities{
			TA:  talname,
			Sia: ia[i],
		})
	}

	ir := InfoResult{
		TAs:                ias,
		ROACount:           len(s.ROAList.Data),
		ROAsTALs:           s.stats.ROAsTALsCount,
		Stable:             s.Stable.Load(),
		LastValidation:     int(s.LastComputed.Unix()),
		ValidationDuration: s.stats.ValidationDuration.Seconds(),
		Iteration:          s.stats.Iteration,
	}
	enc := json.NewEncoder(w)
	enc.Encode(ir)
}

func (s *OctoRPKI) Serve(addr string, path string, metricsPath string, infoPath string, healthPath string, corsOrigin string, corsCreds bool) {
	// Note(Erica): fix https://github.com/cloudflare/cfrpki/issues/8
	fullPath := path
	if len(path) > 0 && string(path[0]) != "/" {
		fullPath = "/" + path
	}
	log.Infof("Serving HTTP on %v%v", addr, fullPath)

	r := http.NewServeMux()

	r.HandleFunc(fullPath, s.ServeROAs)
	r.HandleFunc(infoPath, s.ServeInfo)
	r.HandleFunc(healthPath, s.ServeHealth)
	r.Handle(metricsPath, promhttp.Handler())

	if *Pprof {
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
		r.HandleFunc("/debug/pprof/", pprof.Index)
	}

	corsReq := cors.New(cors.Options{
		AllowedOrigins:   strings.Split(corsOrigin, ","),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowCredentials: corsCreds,
	}).Handler(r)

	log.Fatal(http.ListenAndServe(addr, corsReq))
}

func init() {
	if !*AllowRoot && runningAsRoot() {
		panic("Running as root is not allowed by default")
	}

	prometheus.MustRegister(MetricSIACounts)
	prometheus.MustRegister(MetricRsyncErrors)
	prometheus.MustRegister(MetricRRDPErrors)
	prometheus.MustRegister(MetricRRDPSerial)
	prometheus.MustRegister(MetricROAsCount)
	prometheus.MustRegister(MetricState)
	prometheus.MustRegister(MetricLastStableValidation)
	prometheus.MustRegister(MetricLastValidation)
	prometheus.MustRegister(MetricOperationTime)
	prometheus.MustRegister(MetricLastFetch)
}

func runningAsRoot() bool {
	return os.Geteuid() == 0 || os.Getegid() == 0
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	sentryDsn := *SentryDSN
	if sentryDsn == "" {
		sentryDsn = os.Getenv("SENTRY_DSN")
	}
	if sentryDsn != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn: sentryDsn,
		})
		if err != nil {
			log.Fatalf("failed initializing sentry: %s", err)
		}
		defer sentry.Flush(2 * time.Second)
	}

	log.Info("Validator started")

	if *Tracer {
		cfg, err := jcfg.FromEnv()
		if err != nil {
			log.Fatal(err)
		}
		tracer, closer, err := cfg.NewTracer()
		if err != nil {
			log.Fatal(err)
		}
		defer closer.Close()
		opentracing.SetGlobalTracer(tracer)
	}

	rootTALs := strings.Split(*RootTAL, ",")
	talNames := strings.Split(*TALNames, ",")
	tals := make([]*pki.PKIFile, 0)
	for _, tal := range rootTALs {
		tals = append(tals, &pki.PKIFile{
			Path: tal,
			Type: pki.TYPE_TAL,
		})
	}

	err := os.MkdirAll(*Basepath, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directories %q: %v", *Basepath, err)
	}

	s := NewOctoRPKI(tals, talNames)

	if *Sign {
		keyFile, err := os.Open(*SignKey)
		if err != nil {
			log.Fatal(err)
		}
		keyBytes, err := ioutil.ReadAll(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		keyFile.Close()
		keyDec, err := ReadKey(keyBytes, true)
		if err != nil {
			log.Fatal(err)
		}
		s.Key = keyDec
	}

	if *Mode == "server" {
		go s.Serve(*Addr, *Output, *MetricsPath, *InfoPath, *HealthPath, *CorsOrigins, *CorsCreds)
	} else if *Mode != "oneoff" {
		log.Fatalf("Mode %v is not specified. Choose either server or oneoff", *Mode)
	}

	s.validationLoop()
}

func NewOctoRPKI(tals []*pki.PKIFile, talNames []string) *OctoRPKI {
	return &OctoRPKI{
		TalsFetch:       make(map[string]*librpki.RPKITAL),
		Tals:            tals,
		TalNames:        talNames,
		RRDPInfo:        make(map[string]RRDPInfo),
		PrevRepos:       make(map[string]time.Time),
		CurrentRepos:    make(map[string]time.Time),
		RsyncFetchJobs:  make(map[string]string),
		RRDPFetch:       make(map[string]string),
		RRDPFetchDomain: make(map[string]string),
		Fetcher:         syncpki.NewLocalFetch(*Basepath),
		HTTPFetcher:     syncpki.NewHTTPFetcher(*UserAgent),
		ROAList:         newROAList(),
		stats:           newOctoRPKIStats(),
		InfoAuthorities: make([][]SIA, 0),
		tracer:          opentracing.GlobalTracer(),
	}
}

func newROAList() *prefixfile.ROAList {
	return &prefixfile.ROAList{
		Data: make([]prefixfile.ROAJson, 0),
	}
}

func (s *OctoRPKI) validationLoop() {
	var spanActive bool
	var pSpan opentracing.Span
	var iterationsUntilStable int
	for {
		if !spanActive {
			pSpan = s.tracer.StartSpan("multoperation")
			spanActive = true
			iterationsUntilStable = 0
		}

		span := s.tracer.StartSpan("operation", opentracing.ChildOf(pSpan.Context()))

		s.stats.Iteration++
		iterationsUntilStable++
		// GHSA-g5gj-9ggf-9vmq: Prevent infinite repository traversal
		if iterationsUntilStable > *MaxIterations {
			log.Fatal("Max iterations has been reached. This number can be adjusted with -max.iterations")
		}
		span.SetTag("iteration", s.stats.Iteration)

		if *RRDP {
			s.doRRDP(span)
		}

		// HTTPs TAL
		s.mainTAL(span)
		s.TalsFetch = make(map[string]*librpki.RPKITAL) // clear decoded TAL for next iteration

		s.mainRsync(span)

		s.mainValidation(span)

		// Reduce
		changed := s.MainReduce()
		s.Stable.Store(!changed && s.stats.Iteration > 1)
		s.HasPreviousStable.Store(s.Stable.Load())

		if *Mode == "oneoff" && (s.Stable.Load() || !*WaitStable) {
			s.mustOutput()
		}

		span.SetTag("stable", s.Stable.Load())
		span.Finish()

		if *Mode == "oneoff" && s.Stable.Load() {
			log.Info("Stable, terminating")
			break
		}

		if s.Stable.Load() {
			MetricLastStableValidation.Set(float64(s.LastComputed.Unix()))
			MetricState.Set(float64(1))

			pSpan.SetTag("iterations", iterationsUntilStable)
			pSpan.Finish()
			spanActive = false

			log.Infof("Stable state. Revalidating in %v", *Refresh)
			<-time.After(*Refresh)
			s.Stable.Store(false)
			continue
		}

		MetricState.Set(float64(0))
		log.Info("Still exploring. Revalidating now")
	}
}

func (s *OctoRPKI) mustOutput() {
	err := s.output()
	if err != nil {
		log.Fatalf("Output failed: %v", err)
	}
}

func (s *OctoRPKI) output() error {
	fc, err := json.Marshal(s.ROAList)
	if err != nil {
		return fmt.Errorf("unable to marshal ROA list: %v", err)
	}

	if *Output == "" {
		fmt.Println(string(fc))
	} else {
		err := ioutil.WriteFile(*Output, fc, 0600)
		if err != nil {
			return fmt.Errorf("Unable to write ROA list to %q: %v", *Output, err)
		}
	}

	return nil
}

func (s *OctoRPKI) doRRDP(span opentracing.Span) {
	t1 := time.Now()
	defer func() {
		t2 := time.Now()
		MetricOperationTime.With(prometheus.Labels{"type": "rrdp"}).Observe(float64(t2.Sub(t1).Seconds()))
	}()

	if *RRDPFile != "" {
		err := s.LoadRRDPInfo(*RRDPFile)
		if err != nil {
			sentry.CaptureException(err)
		}
	}

	s.mainRRDP(span)

	if *RRDPFile != "" {
		err := s.saveRRDPInfo(*RRDPFile)
		if err != nil {
			sentry.CaptureException(err)
		}
	}
}
