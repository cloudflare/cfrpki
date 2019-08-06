package main

import (
	"context"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cfrpki/sync/api"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io"
	"os"
	"runtime"
	"strings"
)

var (
	//RootCertificate = flag.String("certificate.root", "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer", "Root certificates separated by comma")
	RootTAL     = flag.String("tal.root", "tals/afrinic.tal,tals/apnic.tal,tals/arin.tal,tals/lacnic.tal,tals/ripe.tal", "List of TAL separated by comma")
	APIPath     = flag.String("api", "[::1]:8080", "RPKI API")
	UseManifest = flag.Bool("manifest.use", true, "Use manifests file to explore instead of going into the repository")
	LogLevel    = flag.String("loglevel", "info", "Log level")

	Output = flag.String("output.roa", "output.json", "Output ROA file")

	CertRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	CertRRDP       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 13}
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)
	log.Infof("Validator started")

	conn, err := grpc.Dial(*APIPath, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	client := cfrpki.NewRPKIAPIClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := cfrpki.APIFetch{
		Client: client,
		Ctx:    ctx,
	}

	validator := pki.NewValidator()

	manager := pki.NewSimpleManager()
	manager.Validator = validator
	manager.FileSeeker = &s
	manager.Log = log.StandardLogger()

	rootTALs := strings.Split(*RootTAL, ",")
	tals := make([]*pki.PKIFile, 0)
	for _, tal := range rootTALs {
		tals = append(tals, &pki.PKIFile{
			Path: tal,
			Type: pki.TYPE_TAL,
		})
	}
	manager.AddInitial(tals)

	manager.Explore(!*UseManifest, false)

	var count int
	for _, obj := range manager.Validator.TALs {
		tal := obj.Resource.(*librpki.RPKI_TAL)
		postSIAQuery := &cfrpki.SIA{
			RSYNC: tal.URI,
		}

		_, err := client.PostSIA(ctx, postSIAQuery)
		if err != nil {
			log.Fatal(err)
		}
		count++
	}
	for _, obj := range manager.Validator.ValidObjects {
		if obj.Type == pki.TYPE_CER {
			cer := obj.Resource.(*librpki.RPKI_Certificate)

			postSIAQuery := &cfrpki.SIA{}
			for _, sia := range cer.SubjectInformationAccess {
				gn := string(sia.GeneralName)
				if sia.AccessMethod.Equal(CertRepository) {
					postSIAQuery.RSYNC = gn
				} else if sia.AccessMethod.Equal(CertRRDP) {
					postSIAQuery.RRDP = gn
				}
			}

			_, err := client.PostSIA(ctx, postSIAQuery)
			if err != nil {
				log.Fatal(err)
			}
			count++
		}
	}
	log.Debugf("Inserted %v SIAs", count)

	type OutputROA struct {
		ASN       string `json:"asn"`
		Prefix    string `json:"prefix"`
		MaxLength int    `json:"maxLength"`
		Path      string `json:"TA"`
	}

	type OutputROAs struct {
		ROAs []OutputROA `json:"roas"`
	}

	ors := OutputROAs{
		ROAs: make([]OutputROA, 0),
	}

	for _, obj := range manager.Validator.ValidROA {
		roa := obj.Resource.(*librpki.RPKI_ROA)

		for _, entry := range roa.Valids {
			oroa := OutputROA{
				ASN:       fmt.Sprintf("AS%v", roa.ASN),
				Prefix:    entry.IPNet.String(),
				MaxLength: entry.MaxLength,
			}
			ors.ROAs = append(ors.ROAs, oroa)

		}
	}

	// Saving ROA output
	var buf io.Writer
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
