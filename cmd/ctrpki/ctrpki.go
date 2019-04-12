package main

import (
	"context"
	"encoding/hex"
	"flag"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfrpki/sync/lib"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	log "github.com/sirupsen/logrus"
)

var (
	RootTAL                        = flag.String("tal.root", "tals/apnic.tal", "List of TAL separated by comma")
	MapDir                         = flag.String("map.dir", "rsync://rpki.ripe.net/repository/=./rpki.ripe.net/repository/", "Map of the paths separated by commas")
	UseManifest                    = flag.Bool("manifest.use", true, "Use manifests file to explore instead of going into the repository")
	ValidTime                      = flag.String("valid.time", "now", "Validation time (now/timestamp/RFC3339)")
	LogLevel                       = flag.String("loglevel", "info", "Log level")
	CertificateTransparency        = flag.String("ct", "https://ct.cloudflare.com/logs/cirrus", "Certificate Transparency Log address")
	CertificateTransparencyThreads = flag.Int("ct.threads", 50, "Number of threads to send to the CT Log")
)

func BatchCertificateTransparency(ctclient *client.LogClient, chain chan []ct.ASN1Cert, q chan bool) {
	log.Debugf("Starting BatchCertificateTransparency")
	for {
		select {
		case msg := <-chain:
			_, err := ctclient.AddChain(context.Background(), msg)
			if err != nil {
				log.Error(err)
			}
		case <-q:
			log.Debugf("Closing thread")
			return
		}
	}
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

	validator := pki.NewValidator()

	if *ValidTime == "now" {
		validator.Time = time.Now().UTC()
	} else if ts, err := strconv.ParseInt(*ValidTime, 10, 64); err == nil {
		vt := time.Unix(int64(ts), 0)
		log.Infof("Setting time to %v (timestamp)", vt)
		validator.Time = vt
	} else if vt, err := time.Parse(time.RFC3339, *ValidTime); err == nil {
		log.Infof("Setting time to %v (RFC3339)", vt)
		validator.Time = vt
	}

	ctclient, err := client.New(*CertificateTransparency, http.DefaultClient, jsonclient.Options{
		Logger:    log.StandardLogger(),
		UserAgent: "Cloudflare-RPKI-CT/1.0 (+https://github.com/cloudflare/cfrpki)",
	})
	if err != nil {
		log.Fatal(err)
	}

	threads := *CertificateTransparencyThreads

	qList := make([]chan bool, threads)
	dataChan := make(chan []ct.ASN1Cert, threads)
	if threads > 0 {
		for i := 0; i < threads; i++ {
			q := make(chan bool)
			qList[i] = q
			go BatchCertificateTransparency(ctclient, dataChan, q)
		}
	}

	defer func() {
		if threads > 0 {
			for i := 0; i < threads; i++ {
				qList[i] <- true
			}
		}
	}()

	rootTALs := strings.Split(*RootTAL, ",")
	ctData := make([][]*pki.PKIFile, 0)
	for _, tal := range rootTALs {
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

		skiToAki := make(map[string]string)
		skiToPath := make(map[string]*pki.PKIFile)
		for _, obj := range manager.Validator.ValidObjects {
			res := obj.Resource.(*librpki.RPKI_Certificate)
			ski := hex.EncodeToString(res.Certificate.SubjectKeyId)
			aki := hex.EncodeToString(res.Certificate.AuthorityKeyId)
			skiToAki[ski] = aki
			skiToPath[ski] = obj.File
		}

		pathCT := make([][]*pki.PKIFile, 0)
		for ski, aki := range skiToAki {
			skiDone := make(map[string]bool)
			skiDone[ski] = true

			curAki := aki
			curPath := skiToPath[ski]
			curPathCT := make([]*pki.PKIFile, 1)
			curPathCT[0] = curPath

			var ok bool
			for curAki != "" && !ok {
				ok = skiDone[curAki]
				skiDone[curAki] = true

				curPath = skiToPath[curAki]
				if curAki != "" {
					curPathCT = append(curPathCT, curPath)
				}
				curAki = skiToAki[curAki]
			}
			pathCT = append(pathCT, curPathCT)
		}

		ctData = append(ctData, pathCT...)
	}

	log.Infof("Sending %v certificate chains to log %v using %v threads", len(ctData), *CertificateTransparency, *CertificateTransparencyThreads)
	var itera int
	for _, certs := range ctData {
		chain := make([]ct.ASN1Cert, 0)

		for _, cert := range certs {
			var dataBytes []byte
			data, err := s.GetFile(cert)
			if cert.Type == pki.TYPE_ROA || cert.Type == pki.TYPE_MFT {
				cms, err := librpki.DecodeCMS(data.Data)
				if err != nil {
					log.Error(err)
					continue
				}
				dataBytes = cms.SignedData.Certificates.Bytes
			} else {
				dataBytes = data.Data
			}

			if err != nil {
				log.Error(err)
				continue
			}
			chain = append(chain, ct.ASN1Cert{Data: dataBytes})
		}

		if threads > 0 {
			dataChan <- chain
		} else {
			_, err := ctclient.AddChain(context.Background(), chain)
			if err != nil {
				log.Error(err)
			}
		}
		itera++
		if len(ctData) >= 20 && itera%(len(ctData)/20) == 0 {
			log.Infof("Sent %v/%v (%v%%)", itera, len(ctData), itera*100/len(ctData))
		}
	}
}
