package main

import (
	"context"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	cfrpki "github.com/cloudflare/cfrpki/sync/api"
	"github.com/cloudflare/cfrpki/sync/lib"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	basepath = flag.String("storage", "cache", "Base directory to store certificates")
	timeout  = flag.String("timeout", "20m", "Command timeout")
	api      = flag.String("api", "localhost:8080", "API address")
	logLevel = flag.String("loglevel", "info", "Log level")
	rsyncBin = flag.String("bin", DefaultBin(), "The rsync binary to use")
	noRRDP   = flag.Bool("norrdp", false, "Do not fetch the URL that have an RRDP address")
	cold     = flag.Bool("cold", false, "Do not fetch initial data")
	refresh  = flag.String("refresh", "30m", "Refresh interval (set to zero to disable)")
)

func DefaultBin() string {
	path, _ := exec.LookPath("rsync")
	return path
}

func PublishToAPI(ctx context.Context, client cfrpki.RPKIAPIClient, publish []*syncpki.FileStat, base string) error {
	for _, curFile := range publish {
		log.Debugf("Publishing %v (deletion: %v)", curFile.Path, curFile.Deleted)
		if curFile.Deleted {
			_, err := client.DeleteFile(ctx, &cfrpki.ResourceData{
				Path: curFile.Path,
			})
			if err != nil {
				return err
			}
		} else {
			downloadPath, err := syncpki.GetDownloadPath(curFile.Path, false)
			path := filepath.Join(base, downloadPath)
			if err != nil {
				return err
			}

			b, err := ioutil.ReadFile(path)

			if err != nil {
				return err
			}

			_, err = client.PublishFile(ctx, &cfrpki.ResourceData{
				Path: curFile.Path,
				Data: b,
			})

			if err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()

	lvl, _ := log.ParseLevel(*logLevel)
	log.SetLevel(lvl)

	timeoutDur, _ := time.ParseDuration(*timeout)

	conn, err := grpc.Dial(*api, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll(*basepath, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	client := cfrpki.NewRPKIAPIClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Fetch the initial data from the API
	if !*cold {
		log.Debugf("Hot start: fetching initial data")
		reply, err := client.GetRepository(ctx, &cfrpki.ResourceQuery{
			Path: "rsync://",
		})
		if err != nil {
			log.Fatal(err)
		}
		var count uint64
		for {
			res, err := reply.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			} else if res != nil {
				dPath, err := syncpki.GetDownloadPath(res.Path, true)
				if err != nil {
					log.Fatal(err)
				}
				err = os.MkdirAll(filepath.Join(*basepath, dPath), os.ModePerm)
				if err != nil {
					log.Fatal(err)
				}
				cPath, err := syncpki.GetDownloadPath(res.Path, false)
				if err != nil {
					log.Fatal(err)
				}
				log.Debugf("Downloading from API: %v", res.Path)

				f, err := os.Create(filepath.Join(*basepath, cPath))
				if err != nil {
					log.Fatal(err)
				}
				f.Write(res.Data)
				f.Close()
			} else {
				break
			}
			count++
		}
		log.Infof("Downloaded %v files (hot-start)", count)
	}

	refint, err := time.ParseDuration(*refresh)
	if err != nil {
		log.Fatal(err)
	}
	var iteration int

	s := syncpki.RsyncSystem{
		Log: log.StandardLogger(),
	}

	for refint > 0 || iteration == 0 {
		reply, err := client.GetFetch(ctx, &cfrpki.FetchQuery{
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

		skip := make(map[string]string)
		if *noRRDP {
			reply, err = client.GetFetchRRDP(ctx, &cfrpki.FetchQuery{
				Path: "rsync://",
			})
			if err != nil {
				log.Fatal(err)
			}
			for {
				sia, err := reply.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				} else if sia != nil {
					skip[sia.RSYNC] = sia.RRDP
				} else {
					break
				}
			}
		}

		if len(uris) == 0 {
			log.Infof("Nothing to fetch")
		}
		files := make([]*syncpki.FileStat, 0)
		for _, uri := range uris {
			if rrdp, ok := skip[uri.RSYNC]; ok {
				log.Infof("Skipping %v because there is an RRDP associated: %v", uri.RSYNC, rrdp)
				continue
			}

			rsyncPath := uri.GetRSYNC()
			log.Infof("Sync %v", rsyncPath)

			downloadPath, err := syncpki.GetDownloadPath(rsyncPath, true)
			if err != nil {
				log.Fatal(err)
			}

			path := filepath.Join(*basepath, downloadPath)
			ctxRsync, cancelRsync := context.WithTimeout(context.Background(), timeoutDur)
			rsyncFiles, err := s.RunRsync(ctxRsync, rsyncPath, *rsyncBin, path)
			cancelRsync()
			if err != nil {
				log.Error(err)
			}
			files = append(files, rsyncFiles...)
		}
		log.Info("Publishing files")
		PublishToAPI(ctx, client, files, *basepath)

		if refint > 0 {
			log.Infof("Completed. Waiting until next refresh in %v", refint)
		} else {
			log.Info("Completed")
		}

		iteration++
		<-time.After(refint)
	}
}
