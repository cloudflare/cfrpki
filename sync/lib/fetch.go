package syncpki

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	librpki "github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"

	log "github.com/sirupsen/logrus"
)

type LocalFetch struct {
	Basepath     string
	MapDirectory map[string]string
	repositories map[string]time.Time
}

func NewLocalFetch(basepath string) *LocalFetch {
	return &LocalFetch{
		Basepath:     basepath,
		MapDirectory: map[string]string{RsyncProtoPrefix: basepath},
		repositories: make(map[string]time.Time),
	}
}

func (s *LocalFetch) SetRepositories(repositories map[string]time.Time) {
	s.repositories = repositories
}

func GetLocalPath(pathRep string, replace map[string]string) string {
	sep := fmt.Sprintf("%c", os.PathSeparator)

	for repKey, repVal := range replace {
		if !strings.HasSuffix(repVal, sep) {
			repVal += sep
		}

		pathRep = strings.Replace(pathRep, repKey, repVal, -1)
	}
	return pathRep
}

func ReplacePath(file *pki.PKIFile, replace map[string]string) string {
	pathRep := file.ComputePath()
	pathRep = GetLocalPath(pathRep, replace)
	return pathRep
}

func FetchFile(path string, derEncoding bool) ([]byte, []byte, error) {
	fc, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to read file %q: %v", path, err)
	}

	tmpSha265 := sha256.Sum256(fc)
	sha256 := tmpSha265[:]

	if !derEncoding {
		return fc, sha256, nil
	}

	fc, err = librpki.BER2DER(fc)
	if err != nil {
		return nil, nil, fmt.Errorf("librpki.BER2DER failed: %v", err)
	}

	return fc, sha256, nil
}

func ParseMapDirectory(mapdir string) map[string]string {
	mapDirectoryFinal := make(map[string]string)
	mapdirsSplit := strings.Split(mapdir, ",")
	for _, mapdirU := range mapdirsSplit {
		mapdirUSplit := strings.Split(mapdirU, "=")
		if len(mapdirUSplit) == 2 {
			mapDirectoryFinal[mapdirUSplit[0]] = mapdirUSplit[1]
		}
	}
	return mapDirectoryFinal
}

func (s *LocalFetch) GetFile(file *pki.PKIFile) (*pki.SeekFile, error) {
	return s.GetFileConv(file, file.Type != pki.TYPE_TAL)
}

func (s *LocalFetch) GetFileConv(file *pki.PKIFile, derEncoding bool) (*pki.SeekFile, error) {
	newPath := ReplacePath(file, s.MapDirectory)
	log.Debugf("Fetching %v->%v", file.Path, newPath)

	data, sha256, err := FetchFile(newPath, derEncoding)
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		rsyncBase, _, errExtract := ExtractRsyncDomainModule(file.Path)
		if errExtract != nil {
			log.Errorf("error extracting rsync of %s: %v", file.Path, errExtract)
		}

		if _, ok := s.repositories[rsyncBase]; !ok {
			log.Debugf("Got %v but repository not yet synchronized", err)
			return nil, nil
		}
	}

	return &pki.SeekFile{
		File:   file.Path,
		Data:   data,
		Sha256: sha256,
	}, err
}

func (s *LocalFetch) GetRepository(file *pki.PKIFile, callback pki.CallbackExplore) error {
	newPath := GetLocalPath(file.Repo, s.MapDirectory)
	files, err := ioutil.ReadDir(file.Repo)
	if err != nil {
		return fmt.Errorf("Unable to read dir %q: %v", file.Repo, err)
	}

	for _, fileDir := range files {
		if fileDir == nil || fileDir.IsDir() {
			continue
		}

		data, sha256, err := FetchFile(newPath+fileDir.Name(), true)
		if err != nil {
			return fmt.Errorf("FetchFile failed: %v", err)
		}

		fullnameSplit := strings.Split(fileDir.Name(), ".")

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

		callback(
			&pki.PKIFile{
				Parent: file,
				Type:   extension,
				Repo:   file.Repo,
				Path:   file.Repo + fileDir.Name(),
			},
			&pki.SeekFile{
				File:   file.Path,
				Data:   data,
				Sha256: sha256,
			}, false)

	}

	return nil
}
