package cfrpki

import (
	"context"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"
	"io/ioutil"
	"os"
	"strings"
)

type APIFetch struct {
	Client RPKIAPIClient
	Ctx    context.Context
}

func FetchFile(client RPKIAPIClient, ctx context.Context, path string) ([]byte, error) {
	resource, err := client.GetResource(ctx, &ResourceQuery{
		Path: path,
	})

	if err != nil {
		return nil, err
	}
	data, err := librpki.BER2DER(resource.Data)
	if err != nil {
		return resource.Data, err
	}
	return data, err
}

func (s *APIFetch) GetFile(file *pki.PKIFile) (*pki.SeekFile, error) {
	if file.Type == pki.TYPE_TAL {
		path := file.Path
		talFile, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(talFile)
		if err != nil {
			return nil, err
		}
		return &pki.SeekFile{
			File: path,
			Data: data,
		}, err
	}

	path := file.ComputePath()

	data, err := FetchFile(s.Client, s.Ctx, path)
	return &pki.SeekFile{
		File: path,
		Data: data,
	}, err
}

func (s *APIFetch) GetRepository(file *pki.PKIFile, callback pki.CallbackExplore) error {
	resources, err := s.Client.GetRepository(s.Ctx, &ResourceQuery{
		Path: file.Repo,
	})
	if err != nil {
		return err
	}

	resource, err := resources.Recv()
	for resource != nil && err == nil {
		fullnameSplit := strings.Split(resource.Path, ".")
		extension := pki.TYPE_UNKNOWN
		if len(fullnameSplit) > 0 {
			switch fullnameSplit[len(fullnameSplit)-1] {
			case "crl":
				extension = pki.TYPE_CRL
			case "cer":
				extension = pki.TYPE_CER
			case "mft":
				extension = pki.TYPE_MFT
			case "roa":
				extension = pki.TYPE_ROA
			}
		}

		data, _ := librpki.BER2DER(resource.Data)

		callback(
			&pki.PKIFile{
				Parent: file,
				Type:   extension,
				Repo:   file.Repo,
				Path:   resource.Path,
			},
			&pki.SeekFile{
				File: resource.Path,
				Data: data,
			}, false)

		resource, err = resources.Recv()
	}
	return nil
}
