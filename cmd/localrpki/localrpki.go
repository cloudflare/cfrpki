package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cfrpki/sync/lib"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	RootTAL     = flag.String("tal.root", "tals/apnic.tal", "List of TAL separated by comma")
	MapDir      = flag.String("map.dir", "rsync://rpki.ripe.net/repository/=./rpki.ripe.net/repository/", "Map of the paths separated by commas")
	UseManifest = flag.Bool("manifest.use", true, "Use manifests file to explore instead of going into the repository")
	ValidTime   = flag.String("valid.time", "now", "Validation time (now/timestamp/RFC3339)")
	LogLevel    = flag.String("loglevel", "info", "Log level")
	Output      = flag.String("output", "output.json", "Output file")
)

type OutputROA struct {
	ASN       string `json:"asn"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxLength"`
	Path      string `json:"path"`
}

type OutputROAs struct {
	ROAs []OutputROA `json:"roas"`
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)
	log.Infof("Validator started")

	mapDir := syncpki.ParseMapDirectory(*MapDir)

	s := syncpki.LocalFetch{
		MapDirectory: mapDir,
		Log:          log.StandardLogger(),
	}

	var vt time.Time
	if *ValidTime == "now" {
		vt = time.Now().UTC()
	} else if ts, err := strconv.ParseInt(*ValidTime, 10, 64); err == nil {
		vt = time.Unix(int64(ts), 0)
		log.Infof("Setting time to %v (timestamp)", vt)
	} else if vttmp, err := time.Parse(time.RFC3339, *ValidTime); err == nil {
		vt = vttmp
		log.Infof("Setting time to %v (RFC3339)", vt)
	}

	rootTALs := strings.Split(*RootTAL, ",")
	ors := OutputROAs{
		ROAs: make([]OutputROA, 0),
	}
	for _, tal := range rootTALs {
		validator := pki.NewValidator()
		validator.Time = vt

		manager := pki.NewSimpleManager()
		manager.Validator = validator
		manager.FileSeeker = &s
		manager.Log = log.StandardLogger()

		manager.AddInitial([]*pki.PKIFile{
			&pki.PKIFile{
				Path: tal,
				Type: pki.TYPE_TAL,
			},
		})

		manager.Explore(!*UseManifest, false)

		for _, roa := range manager.Validator.ValidROA {
			d := roa.Resource.(*librpki.RPKI_ROA)
			for _, entry := range d.Valids {
				oroa := OutputROA{
					ASN:       fmt.Sprintf("AS%v", d.ASN),
					Prefix:    entry.IPNet.String(),
					MaxLength: entry.MaxLength,
					Path:      manager.PathOfResource[roa].ComputePath(),
				}
				ors.ROAs = append(ors.ROAs, oroa)
			}
		}
	}

	var buf io.Writer
	var err error
	if *Output != "" {
		buf, err = os.Create(*Output)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		buf = os.Stdout
	}

	enc := json.NewEncoder(buf)
	enc.Encode(ors)
}
