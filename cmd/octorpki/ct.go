package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cloudflare/cfrpki/validator/pki"
	"github.com/opentracing/opentracing-go"

	librpki "github.com/cloudflare/cfrpki/validator/lib"
	ct "github.com/google/certificate-transparency-go"
	log "github.com/sirupsen/logrus"
)

var (
	// Certificate Transparency
	CertTransparency        = flag.Bool("ct", false, "Enable Certificate Transparency")
	CertTransparencyAddr    = flag.String("ct.addr", "https://ct.cloudflare.com/logs/cirrus", "Path of CT")
	CertTransparencyThreads = flag.Int("ct.threads", 50, "Threads to send to CT")
	CertTransparencyTimeout = flag.Int("ct.timeout", 50, "CT timeout in seconds")
)

func SingleSendCertificateTransparency(httpclient *http.Client, path string, msg *ct.AddChainRequest) error {
	buf := bytes.NewBuffer([]byte{})
	enc := json.NewEncoder(buf)
	enc.Encode(msg)

	resp, err := httpclient.Post(fmt.Sprintf("%v/ct/v1/add-chain", path), "application/json", buf)
	if err == nil {
		respStr, _ := io.ReadAll(resp.Body)
		log.Debugf("Sent %v certs %v %v %v", len(msg.Chain), path, string(respStr), err)
	}

	return err
}

func BatchCertificateTransparency(httpclient *http.Client, path string, d chan *ct.AddChainRequest) {
	log.Debugf("Starting BatchCertificateTransparency")

	for msg := range d {
		err := SingleSendCertificateTransparency(httpclient, path, msg)
		if err != nil {
			log.Error(err)
		}
	}
}

func (s *OctoRPKI) SendCertificateTransparency(pSpan opentracing.Span, ctData [][]*pki.PKIFile, threads int, timeout int) {
	tracer := opentracing.GlobalTracer()
	span := tracer.StartSpan(
		"ct",
		opentracing.ChildOf(pSpan.Context()),
	)
	defer span.Finish()

	log.Infof("Sending Certificate Transparency (threads=%v)", threads)

	httpclient := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	dataChan := make(chan *ct.AddChainRequest)
	defer close(dataChan)

	for i := 0; i < threads; i++ {
		go BatchCertificateTransparency(httpclient, s.CTPath, dataChan)
	}

	var iterations int
	for _, certs := range ctData {
		chain := make([][]byte, 0)

		for _, cert := range certs {
			var dataBytes []byte
			data, err := s.Fetcher.GetFile(cert)
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

			chain = append(chain, dataBytes)
		}

		dataChan <- &ct.AddChainRequest{
			Chain: chain,
		}

		iterations++
		if len(ctData) > 0 && len(ctData) >= 20 && iterations%(len(ctData)/20) == 0 {
			log.Infof("Sent %v/%v (%v percent) certificates chains to CT %v", iterations, len(ctData), iterations*100/len(ctData), s.CTPath)
		}
	}

	log.Infof("Sent %v chains to Certificate Transparency %v", len(ctData), s.CTPath)
}
