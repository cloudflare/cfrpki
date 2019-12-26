package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	cfrpki "github.com/cloudflare/cfrpki/sync/api"
	"github.com/cloudflare/cfrpki/sync/lib"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	api          = flag.String("api", "localhost:8080", "API address")
	insecurehttp = flag.Bool("tls.insecure", false, "Disable certificate verification")
	logLevel     = flag.String("loglevel", "info", "Log level")
	refresh      = flag.String("refresh", "5m", "Refresh interval (set to zero to disable)")
)

func PublishToAPI(ctx context.Context, client cfrpki.RPKIAPIClient, uri string, data []byte, withdraw bool) error {
	if !withdraw {
		log.Debugf("Publishing file: %s", uri)
		_, err := client.PublishFile(ctx, &cfrpki.ResourceData{
			Path: uri,
			Data: data,
		})
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Deleting file: %s", uri)
		_, err := client.DeleteFile(ctx, &cfrpki.ResourceData{
			Path: uri,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func InitRRDP(ctx context.Context, client cfrpki.RPKIAPIClient, path string) (string, int64, error) {
	info, err := client.GetRRDPInfo(ctx, &cfrpki.RRDPInfoQuery{
		RRDP: path,
	})

	if err != nil {
		return "", 0, err
	}

	if info == nil {
		return "", 0, errors.New(fmt.Sprintf("No RRDP info"))
	}

	return info.SessionID, info.Serial, err
}

func UpdateRRDP(ctx context.Context, client cfrpki.RPKIAPIClient, path string, sessionid string, serial int64) error {
	_, err := client.PostRRDP(ctx, &cfrpki.RRDPInfo{
		RRDP:      path,
		SessionID: sessionid,
		Serial:    serial,
	})
	return err
}

func (s *state) UploadRRDP(ctx context.Context, client cfrpki.RPKIAPIClient) (int, int, error) {
	var published int
	var withdrawn int
	for _, d := range s.ToPublish {
		err := PublishToAPI(ctx, client, d.URI, d.Data, false)
		if err != nil {
			return published, withdrawn, err
		}
		published++
	}
	for _, d := range s.ToWithdraw {
		err := PublishToAPI(ctx, client, d.URI, d.Data, true)
		if err != nil {
			return published, withdrawn, err
		}
		withdrawn++
	}
	return published, withdrawn, nil
}

type RRDPFile struct {
	URI  string
	Data []byte
}

type state struct {
	ToPublish  []*RRDPFile
	ToWithdraw []*RRDPFile
}

func (s *state) ReceiveRRDPFileCallback(main string, url string, path string, data []byte, withdraw bool, snapshot bool, curId int64, args ...interface{}) error {
	if !withdraw {
		s.ToPublish = append(s.ToPublish, &RRDPFile{
			URI:  path,
			Data: data,
		})
	} else {
		s.ToWithdraw = append(s.ToWithdraw, &RRDPFile{
			URI: path,
		})
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()

	lvl, _ := log.ParseLevel(*logLevel)
	log.SetLevel(lvl)

	conn, err := grpc.Dial(*api, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	client := cfrpki.NewRPKIAPIClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refint, err := time.ParseDuration(*refresh)
	if err != nil {
		log.Fatal(err)
	}

	httpclient := &http.Client{}
	if *insecurehttp {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpclient.Transport = transport
	}

	fetcher := &syncpki.HTTPFetcher{
		UserAgent: "Cloudflare-RPKI-RRDP/1.0 (+https://rpki.cloudflare.com)",
		Client:    httpclient,
	}

	var iteration int
	for refint > 0 || iteration == 0 {
		reply, err := client.GetFetchRRDP(ctx, &cfrpki.FetchQuery{
			Path: "rsync://",
		})
		if err != nil {
			log.Fatal(err)
		}

		var uris []*cfrpki.SIA
		for {
			sia, err := reply.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			} else if sia != nil {
				uris = append(uris, sia)
			} else {
				break
			}
		}

		if len(uris) == 0 {
			log.Infof("Nothing to fetch")
		}

		for _, uri := range uris {
			path := uri.GetRRDP()
			if err != nil {
				log.Debug(err)
			}

			sessionid, serial, err := InitRRDP(ctx, client, path)
			if err != nil {
				log.Errorf("Error when processing %v: %v. Skipping.", path, err)
				continue
			}

			fileState := &state{
				ToPublish:  make([]*RRDPFile, 0),
				ToWithdraw: make([]*RRDPFile, 0),
			}

			s := &syncpki.RRDPSystem{
				Path:    path,
				Fetcher: fetcher,

				Callback: fileState.ReceiveRRDPFileCallback,

				SessionID: sessionid,
				Serial:    serial,

				Log: log.StandardLogger(),
			}

			err = s.FetchRRDP()
			if err != nil {
				log.Errorf("Error when processing %v: %v. Skipping.", path, err)
				continue
			}
			published, withdrawn, err := fileState.UploadRRDP(ctx, client)
			if err != nil {
				log.Errorf("Error when processing %v: %v. Skipping.", path, err)
				continue
			}
			log.Debugf("Published: %v / Withdrawn: %v", published, withdrawn)

			log.Infof("Updating RRDP for path %s", path)
			err = UpdateRRDP(ctx, client, s.Path, s.SessionID, s.Serial)
			if err != nil {
				log.Errorf("Error when updating %v: %v.", path, err)
				continue
			}
		}

		if refint > 0 {
			log.Infof("Completed. Waiting until next refresh in %v", refint)
		} else {
			log.Info("Completed")
		}
		iteration++
		<-time.After(refint)
	}
}
