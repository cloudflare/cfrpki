package syncpki

import (
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/cloudflare/cfrpki/validator/pki"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

type LocalFetch struct {
	MapDirectory map[string]string
	Log          Logger
	repositories map[string]time.Time
}

func NewLocalFetch(mapDirectory map[string]string, log Logger) *LocalFetch {
	return &LocalFetch{
		MapDirectory: mapDirectory,
		Log:          log,
		repositories: make(map[string]time.Time),
	}
}

func (s *LocalFetch) SetRepositories(repositories map[string]time.Time) {
	s.repositories = repositories
}

func ReplaceString(pathRep string, replace map[string]string) string {
	for repKey, repVal := range replace {
		pathRep = strings.Replace(pathRep, repKey, repVal, -1)
	}
	return pathRep
}

func ReplacePath(file *pki.PKIFile, replace map[string]string) string {
	pathRep := file.ComputePath()
	pathRep = ReplaceString(pathRep, replace)
	return pathRep
}

func FetchFile(path string, conv bool) ([]byte, error) {

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return data, err
	}

	if conv {
		data, err = librpki.BER2DER(data)
		if err != nil {
			return data, err
		}
	}
	return data, err
}

func ParseMapDirectory(mapdir string) map[string]string {
	mapDirectoryFinal := make(map[string]string)
	mapdirs_split := strings.Split(mapdir, ",")
	for _, mapdir_u := range mapdirs_split {
		mapdir_u_split := strings.Split(mapdir_u, "=")
		if len(mapdir_u_split) == 2 {
			mapDirectoryFinal[mapdir_u_split[0]] = mapdir_u_split[1]
		}
	}
	return mapDirectoryFinal
}

func (s *LocalFetch) GetFile(file *pki.PKIFile) (*pki.SeekFile, error) {
	return s.GetFileConv(file, file.Type != pki.TYPE_TAL)
}

func (s *LocalFetch) GetFileConv(file *pki.PKIFile, convert bool) (*pki.SeekFile, error) {
	newPath := ReplacePath(file, s.MapDirectory)
	if s.Log != nil {
		s.Log.Debugf("Fetching %v->%v", file.Path, newPath)
	}
	data, err := FetchFile(newPath, convert)
	if err != nil && os.IsNotExist(err) {

		rsyncBase, _, errExtract := ExtractRsyncDomainModule(file.Path)
		if errExtract != nil && s.Log != nil {
			s.Log.Errorf("error exracting rsync of %s: %v", file.Path, errExtract)
		}

		if _, ok := s.repositories[rsyncBase]; !ok {
			if s.Log != nil {
				s.Log.Debugf("Got %v but repository not yet synchronized", err)
			}
			return nil, nil
		}

	}
	return &pki.SeekFile{
		File: file.Path,
		Data: data,
	}, err
}

func (s *LocalFetch) GetRepository(file *pki.PKIFile, callback pki.CallbackExplore) error {
	newPath := ReplaceString(file.Repo, s.MapDirectory)
	repoFile, err := os.Open(newPath)
	if err != nil {
		return err
	}
	files, err := repoFile.Readdir(0)
	if err != nil {
		return err
	}
	for _, fileDir := range files {
		if fileDir != nil && !fileDir.IsDir() {
			data, err := FetchFile(newPath+fileDir.Name(), true)
			if err != nil {
				return err
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
					File: file.Path,
					Data: data,
				}, false)
		}
	}
	//return errors.New(fmt.Sprintf("Not implemented %v", file))
	return nil
}
