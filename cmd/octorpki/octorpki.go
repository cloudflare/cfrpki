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
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/cfrpki/sync/lib"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"

	"github.com/rs/cors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cloudflare/gortr/prefixfile"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	RRDP_NO_MATCH = iota
	RRDP_MATCH_RSYNC
	RRDP_MATCH_STRICT
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "OctoRPKI " + version + " " + buildinfos

	// Validator Options
	RootTAL     = flag.String("tal.root", "tals/afrinic.tal,tals/apnic.tal,tals/arin.tal,tals/lacnic.tal,tals/ripe.tal", "List of TAL separated by comma")
	TALNames    = flag.String("tal.name", "AFRINIC,APNIC,ARIN,LACNIC,RIPE", "Name of the TALs")
	UseManifest = flag.Bool("manifest.use", true, "Use manifests file to explore instead of going into the repository")
	Basepath    = flag.String("cache", "cache/", "Base directory to store certificates")
	LogLevel    = flag.String("loglevel", "info", "Log level")
	Refresh     = flag.String("refresh", "20m", "Revalidation interval")

	// Rsync Options
	RsyncTimeout = flag.String("rsync.timeout", "20m", "Rsync command timeout")
	RsyncBin     = flag.String("rsync.bin", DefaultBin(), "The rsync binary to use")

	// RRDP Options
	RRDP     = flag.Bool("rrdp", true, "Enable RRDP fetching")
	RRDPFile = flag.String("rrdp.file", "cache/rrdp.json", "Save RRDP state")
	RRDPMode = flag.Int("rrdp.mode", RRDP_MATCH_RSYNC, fmt.Sprintf("RRDP security mode (%v = no check, %v = match rsync domain, %v = match path)",
		RRDP_NO_MATCH, RRDP_MATCH_RSYNC, RRDP_MATCH_STRICT))

	Mode       = flag.String("mode", "server", "Select output mode (server/oneoff)")
	WaitStable = flag.Bool("output.wait", true, "Wait until stable state to create the file (returns 503 when unstable on HTTP)")

	// Serving Options
	Addr        = flag.String("http.addr", ":8080", "Listening address")
	CacheHeader = flag.Bool("http.cache", true, "Enable cache header")
	MetricsPath = flag.String("http.metrics", "/metrics", "Prometheus metrics endpoint")
	InfoPath    = flag.String("http.info", "/infos", "Information URL")

	CorsOrigins = flag.String("cors.origins", "*", "Cors origins separated by comma")
	CorsCreds   = flag.Bool("cors.creds", false, "Cors enable credentials")

	// File option
	Output   = flag.String("output.roa", "output.json", "Output ROA file or URL")
	Sign     = flag.Bool("output.sign", true, "Sign output (GoRTR compatible)")
	SignKey  = flag.String("output.sign.key", "private.pem", "ECDSA signing key")
	Validity = flag.String("output.sign.validity", "1h", "Validity")

	Version = flag.Bool("version", false, "Print version")

	CertRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	CertRRDP       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 13}

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
	Rsync     string `json:"rsync"`
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

type state struct {
	Basepath     string
	Tals         []*pki.PKIFile
	TalNames     []string
	UseManifest  bool
	RsyncBin     string
	RsyncTimeout time.Duration

	Mode     string
	RRDPMode int

	Validity     time.Duration
	LastComputed time.Time
	WaitStable   bool
	Sign         bool
	Key          *ecdsa.PrivateKey
	EnableCache  bool

	Stable      bool // Indicates something has been added to the fetch list (rsync of rrdp)
	Fetcher     *syncpki.LocalFetch
	HTTPFetcher *syncpki.HTTPFetcher

	RsyncFetch    map[string]time.Time
	RRDPFetch     map[string][]string
	FailoverRsync []string

	FinalRsyncFetch map[string]bool
	FinalRRDPFetch  map[string][]string

	RRDPInfo map[string]RRDPInfo

	ROAList *prefixfile.ROAList

	// Various counters and statistics
	RRDPStats          map[string]Stats
	RsyncStats         map[string]Stats
	CountExplore       int
	ValidationDuration time.Duration
	Iteration          int
	ValidationMessages []string
	ROAsTALsCount      []ROAsTAL
}

func (s *state) MainReduce() bool {
	previousRsyncFetch := s.FinalRsyncFetch
	previousRRDPFetch := s.FinalRRDPFetch

	s.FinalRsyncFetch = make(map[string]bool)
	s.FinalRRDPFetch = make(map[string][]string)

	rsyncMap := make(map[string]syncpki.SubMap)
	for k, _ := range s.RsyncFetch {
		syncpki.AddInMap(k, rsyncMap)
	}
	rsyncRedMap := syncpki.ReduceMap(rsyncMap)

	for _, v := range rsyncRedMap {
		s.FinalRsyncFetch[v] = true
	}

	for k, v := range s.RRDPFetch {
		rsyncMap = make(map[string]syncpki.SubMap)
		for _, vv := range v {
			syncpki.AddInMap(vv, rsyncMap)
		}
		rsyncRedMap = syncpki.ReduceMap(rsyncMap)
		for _, vv := range rsyncRedMap {
			if _, ok := s.FinalRRDPFetch[k]; !ok {
				s.FinalRRDPFetch[vv] = make([]string, 0)
			}

			s.FinalRRDPFetch[vv] = append(s.FinalRRDPFetch[vv], k)

			if _, ok := s.FinalRsyncFetch[vv]; ok {
				log.Debugf("Deleting %v from rsync because there is an rrdp\n", vv)
				delete(s.FinalRsyncFetch, vv)
			}
		}
	}

	if len(s.FinalRRDPFetch) != len(previousRRDPFetch) ||
		len(s.FinalRsyncFetch) != len(previousRsyncFetch) {
		return true
	}
	for v, _ := range s.FinalRsyncFetch {
		if _, ok := previousRsyncFetch[v]; !ok {
			return true
		}
	}
	for v, _ := range s.FinalRRDPFetch {
		if _, ok := previousRRDPFetch[v]; !ok {
			return true
		}
	}

	return false
}

func ExtractRsyncDomain(rsync string) (string, error) {
	if len(rsync) > len("rsync://") {
		rsyncDomain := strings.Split(rsync[8:], "/")
		return "rsync://" + rsyncDomain[0], nil
	} else {
		return "", errors.New("Wrong size")
	}
}

func (s *state) ReceiveRRDPFileCallback(main string, url string, path string, data []byte, withdraw bool, snapshot bool, serial int64, args ...interface{}) error {
	rsync, _ := args[0].(string)
	if s.RRDPMode == RRDP_MATCH_STRICT && !strings.Contains(path, rsync) {
		log.Errorf("%v is outside directory %v", path, rsync)
		return nil
	}
	if s.RRDPMode == RRDP_MATCH_RSYNC {
		newDom, err := ExtractRsyncDomain(rsync)
		if err == nil && !strings.Contains(path, newDom) {
			log.Errorf("%v is outside directory %v", path, newDom)
			return nil
		}
	}

	fPath, err := syncpki.GetDownloadPath(path, true)
	if err != nil {
		log.Fatal(err)
	}
	err = os.MkdirAll(filepath.Join(s.Basepath, fPath), os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	fPath, err = syncpki.GetDownloadPath(path, false)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(filepath.Join(s.Basepath, fPath))
	if err != nil {
		return err
	}
	f.Write(data)
	f.Close()

	MetricSIACounts.With(
		prometheus.Labels{
			"address": main,
			"type":    "rrdp",
		}).Inc()
	tmpStats := s.RRDPStats[main]
	tmpStats.Count++
	tmpStats.RRDPLastFile = url
	s.RRDPStats[main] = tmpStats
	return nil
}

func (s *state) LoadRRDP(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Error(err)
		return
	}

	info := make(map[string]RRDPInfo)
	dec := json.NewDecoder(f)
	err = dec.Decode(&info)
	if err != nil && err != io.EOF {
		log.Error(err)
	} else if err == nil {
		s.RRDPInfo = info
	}
	f.Close()
}

func (s *state) SaveRRDP(file string) {
	f, err := os.Create(file)
	if err != nil {
		log.Error(err)
		return
	}

	dec := json.NewEncoder(f)
	err = dec.Encode(s.RRDPInfo)
	if err != nil {
		log.Error(err)
	}
	f.Close()
}

func (s *state) MainRRDP() {
	for rsync, v := range s.FinalRRDPFetch {
		for _, vv := range v {
			log.Infof("RRDP sync %v", vv)

			rrdpid := vv
			if s.RRDPMode == RRDP_MATCH_STRICT {
				rrdpid = fmt.Sprintf("%v|%v", rsync, vv)
			} else if s.RRDPMode == RRDP_MATCH_RSYNC {
				newDom, _ := ExtractRsyncDomain(rsync)
				rrdpid = fmt.Sprintf("%v|%v", newDom, vv)
			}

			path := vv
			info := s.RRDPInfo[rrdpid]

			MetricSIACounts.With(
				prometheus.Labels{
					"address": vv,
					"type":    "rrdp",
				}).Set(0)

			tmpStats := s.RRDPStats[vv]
			tmpStats.URI = vv
			tmpStats.Iteration++
			tmpStats.Count = 0
			s.RRDPStats[vv] = tmpStats
			t1 := time.Now().UTC()

			rrdp := &syncpki.RRDPSystem{
				Callback: s.ReceiveRRDPFileCallback,

				Path:    path,
				Fetcher: s.HTTPFetcher,

				SessionID: info.SessionID,
				Serial:    info.Serial,

				Log: log.StandardLogger(),
			}
			err := rrdp.FetchRRDP(rsync)
			t2 := time.Now().UTC()
			if err != nil {
				log.Errorf("Error when processing %v (for %v): %v. Will add to rsync.", path, rsync, err)
				s.FailoverRsync = append(s.FailoverRsync, rsync)

				MetricRRDPErrors.With(
					prometheus.Labels{
						"address": vv,
					}).Inc()

				tmpStats = s.RRDPStats[vv]
				tmpStats.Errors++
				tmpStats.LastFetchError = int(time.Now().UTC().UnixNano() / 1000000000)
				tmpStats.LastError = fmt.Sprint(err)
				tmpStats.Duration = t2.Sub(t1).Seconds()
				s.RRDPStats[vv] = tmpStats
				continue
			}
			s.Fetcher.PathAvailable = append(s.Fetcher.PathAvailable, rsync)
			MetricRRDPSerial.With(
				prometheus.Labels{
					"address": vv,
				}).Set(float64(rrdp.Serial))
			lastFetch := time.Now().UTC().UnixNano() / 1000000000
			MetricLastFetch.With(
				prometheus.Labels{
					"address": vv,
					"type":    "rrdp",
				}).Set(float64(lastFetch))
			tmpStats = s.RRDPStats[vv]
			tmpStats.LastFetch = int(lastFetch)
			tmpStats.RRDPSerial = rrdp.Serial
			tmpStats.RRDPSessionID = rrdp.SessionID
			tmpStats.Duration = t2.Sub(t1).Seconds()
			s.RRDPStats[vv] = tmpStats

			s.RRDPInfo[rrdpid] = RRDPInfo{
				Rsync:     rsync,
				Path:      path,
				SessionID: rrdp.SessionID,
				Serial:    rrdp.Serial,
			}
		}
	}
}

func (s *state) MainRsync() {
	rsync := syncpki.RsyncSystem{
		Log: log.StandardLogger(),
	}

	rsyncList := make([]string, 0)
	for v, _ := range s.FinalRsyncFetch {
		rsyncList = append(rsyncList, v)
	}
	rsyncList = append(rsyncList, s.FailoverRsync...)

	for _, v := range rsyncList {
		log.Infof("Rsync sync %v", v)
		downloadPath, err := syncpki.GetDownloadPath(v, true)
		if err != nil {
			log.Fatal(err)
		}

		tmpStats := s.RsyncStats[v]
		tmpStats.URI = v
		tmpStats.Iteration++
		tmpStats.Count = 0
		s.RsyncStats[v] = tmpStats

		path := filepath.Join(s.Basepath, downloadPath)
		ctxRsync, cancelRsync := context.WithTimeout(context.Background(), s.RsyncTimeout)
		t1 := time.Now().UTC()
		files, err := rsync.RunRsync(ctxRsync, v, s.RsyncBin, path)
		t2 := time.Now().UTC()
		if err != nil {
			log.Error(err)
			MetricRsyncErrors.With(
				prometheus.Labels{
					"address": v,
				}).Inc()

			tmpStats = s.RsyncStats[v]
			tmpStats.Errors++
			tmpStats.LastFetchError = int(time.Now().UTC().UnixNano() / 1000000000)
			tmpStats.LastError = fmt.Sprint(err)
			s.RsyncStats[v] = tmpStats
		}
		cancelRsync()
		var countFiles int
		s.Fetcher.PathAvailable = append(s.Fetcher.PathAvailable, v)
		if files != nil {
			countFiles = len(files)
		}
		MetricSIACounts.With(
			prometheus.Labels{
				"address": v,
				"type":    "rsync",
			}).Set(float64(countFiles))
		lastFetch := time.Now().UTC().UnixNano() / 1000000000
		MetricLastFetch.With(
			prometheus.Labels{
				"address": v,
				"type":    "rsync",
			}).Set(float64(lastFetch))
		tmpStats = s.RsyncStats[v]
		tmpStats.LastFetch = int(lastFetch)
		tmpStats.Count = countFiles
		tmpStats.Duration = t2.Sub(t1).Seconds()
		s.RsyncStats[v] = tmpStats
	}
}

func (s *state) Debugf(msg string, args ...interface{}) {
	log.Debugf(msg, args...)
}

func (s *state) Errorf(msg string, args ...interface{}) {
	log.Errorf(msg, args...)
	s.ValidationMessages = append(s.ValidationMessages, fmt.Sprintf(msg, args...))
}

func (s *state) Printf(msg string, args ...interface{}) {
	log.Printf(msg, args...)
	s.ValidationMessages = append(s.ValidationMessages, fmt.Sprintf(msg, args...))
}

func (s *state) Warnf(msg string, args ...interface{}) {
	log.Warnf(msg, args...)
	s.ValidationMessages = append(s.ValidationMessages, fmt.Sprintf(msg, args...))
}

func FilterDuplicates(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	roalistNodup := make([]prefixfile.ROAJson, 0)
	hmap := make(map[string]bool)
	for _, roa := range roalist {
		k := roa.String()
		_, present := hmap[k]
		if !present {
			hmap[k] = true
			roalistNodup = append(roalistNodup, roa)
		}
	}
	return roalistNodup
}

func (s *state) MainValidation() {
	manager := make([]*pki.SimpleManager, len(s.Tals))
	for i, tal := range s.Tals {
		validator := pki.NewValidator()

		manager[i] = pki.NewSimpleManager()
		manager[i].Validator = validator
		manager[i].FileSeeker = s.Fetcher
		manager[i].Log = s

		manager[i].AddInitial([]*pki.PKIFile{tal})
		s.CountExplore = manager[i].Explore(!s.UseManifest, false)

		// Insertion of SIAs in db to allow rsync to update the repos
		var count int
		for _, obj := range manager[i].Validator.TALs {
			tal := obj.Resource.(*librpki.RPKI_TAL)
			s.RsyncFetch[tal.URI] = time.Now().UTC()
			count++
		}
		for _, obj := range manager[i].Validator.ValidObjects {
			if obj.Type == pki.TYPE_CER {
				cer := obj.Resource.(*librpki.RPKI_Certificate)
				var RsyncGN string
				var RRDPGN string
				var hasRRDP bool
				for _, sia := range cer.SubjectInformationAccess {
					gn := string(sia.GeneralName)
					if sia.AccessMethod.Equal(CertRepository) {
						RsyncGN = gn
						s.RsyncFetch[gn] = time.Now().UTC()
					} else if sia.AccessMethod.Equal(CertRRDP) {
						hasRRDP = true
						RRDPGN = gn
					}
				}

				if hasRRDP {
					if _, ok := s.RRDPFetch[RRDPGN]; !ok {
						s.RRDPFetch[RRDPGN] = make([]string, 0)
					}
					s.RRDPFetch[RRDPGN] = append(s.RRDPFetch[RRDPGN], RsyncGN)
				}

				count++
			}
		}
	}

	// Generating ROAs list
	roalist := &prefixfile.ROAList{
		Data: make([]prefixfile.ROAJson, 0),
	}
	var counts int
	s.ROAsTALsCount = make([]ROAsTAL, 0)
	for i, tal := range s.Tals {
		talname := tal.Path
		if len(s.TalNames) == len(s.Tals) {
			talname = s.TalNames[i]
		}

		var counttal int
		for _, obj := range manager[i].Validator.ValidROA {
			roa := obj.Resource.(*librpki.RPKI_ROA)

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
		s.ROAsTALsCount = append(s.ROAsTALsCount, ROAsTAL{TA: talname, Count: counttal})
		MetricROAsCount.With(
			prometheus.Labels{
				"ta": talname,
			}).Set(float64(counttal))
	}
	curTime := time.Now().UTC()
	s.LastComputed = curTime
	validTime := curTime.Add(s.Validity)
	roalist.Metadata = prefixfile.MetaData{
		Counts:    counts,
		Generated: int(curTime.UnixNano()) / 1000000000,
		Valid:     int(validTime.UnixNano()) / 1000000000,
	}

	roalist.Data = FilterDuplicates(roalist.Data)
	if s.Sign {
		signdate, sign, err := roalist.Sign(s.Key)
		if err != nil {
			log.Error(err)
		}
		roalist.Metadata.Signature = sign
		roalist.Metadata.SignatureDate = signdate
	}

	s.ROAList = roalist
}

func (s *state) ServeROAs(w http.ResponseWriter, r *http.Request) {
	if s.Stable || !s.WaitStable {

		upTo := s.LastComputed.Add(s.Validity)
		maxAge := int(upTo.Sub(time.Now()).Seconds())

		w.Header().Set("Content-Type", "application/json")

		if maxAge > 0 && s.EnableCache {
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%v", maxAge))
		}

		tmp := s.ROAList

		etag := sha256.New()
		etag.Write([]byte(fmt.Sprintf("%v/%v", tmp.Metadata.Generated, tmp.Metadata.Counts)))
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
		enc.Encode(tmp)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("File not ready yet"))
	}
}

type SIA struct {
	Rsync string `json:"rsync"`
	RRDP  string `json:"rrdp,omitempty"`
}

type ROAsTAL struct {
	TA    string `json:"ta,omitempty"`
	Count int    `json:"count,omitempty"`
}

type InfoResult struct {
	Stable             bool      `json:"stable"`
	TALs               []string  `json:"tals"`
	SIAs               []SIA     `json:"sia"`
	Rsync              []Stats   `json:"sias-rsync,omitempty"`
	RRDP               []Stats   `json:"sias-rrdp,omitempty"`
	Iteration          int       `json:"iteration"`
	LastValidation     int       `json:"validation-last"`
	ValidationDuration float64   `json:"validation-duration"`
	ValidationMessages []string  `json:"validation-messages"`
	ExploredFiles      int       `json:"validation-explored"`
	ROAsTALs           []ROAsTAL `json:"roas-tal-count"`
	ROACount           int       `json:"roas-count"`
}

func (s *state) ServeInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tmproa := s.ROAList

	sia := make([]SIA, 0)
	tmprsyncfetch := s.FinalRsyncFetch
	tmprrdpfetch := s.FinalRRDPFetch
	for k, _ := range tmprsyncfetch {
		sia = append(sia, SIA{
			Rsync: k,
		})
	}
	for k, v := range tmprrdpfetch {
		for _, vv := range v {
			sia = append(sia, SIA{
				Rsync: k,
				RRDP:  vv,
			})
		}
	}
	tmprsync := s.RsyncStats
	tmprrdp := s.RRDPStats
	tmprsyncstats := make([]Stats, 0)
	tmprrdpstats := make([]Stats, 0)
	for _, v := range tmprsync {
		tmprsyncstats = append(tmprsyncstats, v)
	}
	for _, v := range tmprrdp {
		tmprrdpstats = append(tmprrdpstats, v)
	}
	vm := s.ValidationMessages

	tals := make([]string, 0)
	tmptals := s.Tals
	for _, v := range tmptals {
		tals = append(tals, v.Path)
	}

	ir := InfoResult{
		TALs:               tals,
		Stable:             s.Stable,
		SIAs:               sia,
		ROACount:           len(tmproa.Data),
		ROAsTALs:           s.ROAsTALsCount,
		Rsync:              tmprsyncstats,
		RRDP:               tmprrdpstats,
		LastValidation:     int(s.LastComputed.UnixNano() / 1000000),
		ExploredFiles:      s.CountExplore,
		ValidationDuration: s.ValidationDuration.Seconds(),
		Iteration:          s.Iteration,
		ValidationMessages: vm,
	}
	enc := json.NewEncoder(w)
	enc.Encode(ir)
}

func (s *state) Serve(addr string, path string, metricsPath string, infoPath string, corsOrigin string, corsCreds bool) {
	// Note(Erica): fix https://github.com/cloudflare/cfrpki/issues/8
	fullPath := path
	if len(path) > 0 && string(path[0]) != "/" {
		fullPath = "/" + path
	}
	log.Infof("Serving HTTP on %v%v", addr, fullPath)

	r := mux.NewRouter()

	r.HandleFunc(fullPath, s.ServeROAs)
	r.HandleFunc(infoPath, s.ServeInfo)
	r.Handle(metricsPath, promhttp.Handler())

	corsReq := cors.New(cors.Options{
		AllowedOrigins:   strings.Split(corsOrigin, ","),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowCredentials: corsCreds,
	}).Handler(r)

	http.Handle("/", corsReq)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func init() {
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

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)
	log.Infof("Validator started")

	mainRefresh, _ := time.ParseDuration(*Refresh)

	rootTALs := strings.Split(*RootTAL, ",")
	talNames := strings.Split(*TALNames, ",")
	tals := make([]*pki.PKIFile, 0)
	for _, tal := range rootTALs {
		tals = append(tals, &pki.PKIFile{
			Path: tal,
			Type: pki.TYPE_TAL,
		})
	}
	timeoutDur, _ := time.ParseDuration(*RsyncTimeout)
	timeValidity, _ := time.ParseDuration(*Validity)

	err := os.MkdirAll(*Basepath, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	s := &state{
		Basepath:     *Basepath,
		Tals:         tals,
		TalNames:     talNames,
		UseManifest:  *UseManifest,
		RsyncTimeout: timeoutDur,
		RsyncBin:     *RsyncBin,

		WaitStable: *WaitStable,
		Validity:   timeValidity,
		Sign:       *Sign,

		EnableCache: *CacheHeader,

		Mode:     *Mode,
		RRDPMode: *RRDPMode,

		RsyncFetch:      make(map[string]time.Time),
		RRDPFetch:       make(map[string][]string),
		FinalRsyncFetch: make(map[string]bool),
		FinalRRDPFetch:  make(map[string][]string),
		RRDPInfo:        make(map[string]RRDPInfo),
		FailoverRsync:   make([]string, 0),

		Fetcher: &syncpki.LocalFetch{
			MapDirectory: map[string]string{
				"rsync://": *Basepath,
			},
			Log:           log.StandardLogger(),
			PathAvailable: make([]string, 0),
		},
		HTTPFetcher: &syncpki.HTTPFetcher{
			UserAgent: "Cloudflare-RPKI-RRDP/1.0 (+https://rpki.cloudflare.com)",
			Client:    &http.Client{},
		},
		ROAList: &prefixfile.ROAList{
			Data: make([]prefixfile.ROAJson, 0),
		},

		RsyncStats:    make(map[string]Stats),
		RRDPStats:     make(map[string]Stats),
		ROAsTALsCount: make([]ROAsTAL, 0),
	}

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
		go s.Serve(*Addr, *Output, *MetricsPath, *InfoPath, *CorsOrigins, *CorsCreds)
	} else if *Mode != "oneoff" {
		log.Fatalf("Mode %v is not specified. Choose either server or oneoff", *Mode)
	}

	for {
		s.Iteration++
		s.FailoverRsync = make([]string, 0)
		s.Fetcher.PathAvailable = make([]string, 0)
		if *RRDP {
			t1 := time.Now().UTC()
			// RRDP
			if *RRDPFile != "" {
				s.LoadRRDP(*RRDPFile)
			}
			s.MainRRDP()
			if *RRDPFile != "" {
				s.SaveRRDP(*RRDPFile)
			}

			t2 := time.Now().UTC()
			MetricOperationTime.With(
				prometheus.Labels{
					"type": "rrdp",
				}).
				Observe(float64(t2.Sub(t1).Seconds()))
		}

		t1 := time.Now().UTC()

		// Rsync
		s.MainRsync()

		t2 := time.Now().UTC()
		MetricOperationTime.With(
			prometheus.Labels{
				"type": "rsync",
			}).
			Observe(float64(t2.Sub(t1).Seconds()))

		s.ValidationMessages = make([]string, 0)
		t1 = time.Now().UTC()

		// Validation
		s.MainValidation()

		t2 = time.Now().UTC()
		s.ValidationDuration = t2.Sub(t1)
		MetricOperationTime.With(
			prometheus.Labels{
				"type": "validation",
			}).
			Observe(float64(s.ValidationDuration.Seconds()))
		MetricLastValidation.Set(float64(s.LastComputed.UnixNano() / 1000000000))

		t1 = time.Now().UTC()

		// Reduce
		s.Stable = !s.MainReduce()

		t2 = time.Now().UTC()
		MetricOperationTime.With(
			prometheus.Labels{
				"type": "reduce",
			}).
			Observe(float64(t2.Sub(t1).Seconds()))

		if *Mode == "oneoff" && (s.Stable || !*WaitStable) {
			if *Output == "" {
				enc := json.NewEncoder(os.Stdout)
				enc.Encode(s.ROAList)
			} else {
				f, err := os.Create(*Output)
				if err != nil {
					log.Fatal(err)
				}
				enc := json.NewEncoder(f)
				enc.Encode(s.ROAList)
				f.Close()
			}

		}

		if *Mode == "oneoff" && s.Stable {
			log.Info("Stable, terminating")
			break
		}

		if s.Stable {
			MetricLastStableValidation.Set(float64(s.LastComputed.UnixNano() / 1000000000))
			MetricState.Set(float64(1))

			log.Infof("Stable state. Revalidating in %v", mainRefresh)
			<-time.After(mainRefresh)
			s.Stable = false
		} else {
			MetricState.Set(float64(0))

			log.Info("Still exploring. Revalidating now")
		}
	}
}
