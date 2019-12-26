package syncpki

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var (
	reDeletion = regexp.MustCompile("^deleting (.*)")
	reMatch    = regexp.MustCompile("(.*\\.(cer|mft|crl|roa|gbr))$")
)

// Check if string is a file
func GetMatch(str string) bool {
	return reMatch.MatchString(str)
}

func GetDownloadPath(sync string, trimFile bool) (string, error) {
	// Trim protocol "rsync://" from path
	if len(sync) <= 8 || sync[0:8] != "rsync://" {
		return "", errors.New(fmt.Sprintf("Incorrect rsync address %v", sync))
	}

	splitSync := strings.Split(sync[8:], "/")

	if sync[len(sync)-1] != '/' && len(splitSync) > 2 && trimFile {
		splitSync = splitSync[0 : len(splitSync)-1]
	}

	joinFiles := strings.Join(splitSync, "/")

	if GetMatch(sync) == true {
		joinFiles = strings.TrimSuffix(joinFiles, "/")
	}
	return joinFiles, nil
}

// Determines if file has been deleted
func FilterMatch(line string) (string, bool, error) {
	results := reDeletion.FindAllStringSubmatch(line, -1)
	if len(results) > 0 {
		return results[0][1], true, nil
	}
	return line, false, nil
}

type FileStat struct {
	Path    string
	Deleted bool
}

type RsyncSystem struct {
	Log Logger
}

// Runs the rsync binary on a URL
func (s *RsyncSystem) RunRsync(ctx context.Context, uri string, bin string, dirPath string) ([]*FileStat, error) {
	if bin == "" {
		return nil, errors.New("rsync binary missing")
	}

	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bin, "-var", uri, dirPath)
	if s.Log != nil {
		s.Log.Debugf("Command ran: %v", cmd)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			errorStr := scanner.Text()
			if s.Log != nil {
				s.Log.Error(errorStr)
			}
			err = scanner.Err()
			if err != nil {
				if s.Log != nil {
					s.Log.Errorf("%v: %v", uri, err)
				}
				return
			}
		}
	}()

	newuri := uri
	uriSplit := strings.Split(newuri[8:], "/")
	if uri[len(uri)-1] != '/' && len(uriSplit) > 2 {
		newuri = "rsync://" + strings.Join(uriSplit[0:len(uriSplit)-1], "/")
	} else {
		newuri = strings.TrimSuffix(newuri, "/")
	}

	files := make([]*FileStat, 0)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		match := GetMatch(line)
		if s.Log != nil {
			s.Log.Debugf("Rsync received from %v: %v (match=%v)", uri, line, match)
		}
		if match {
			file, deleted, err := FilterMatch(line)
			if err != nil {
				return nil, err
			}

			files = append(files, &FileStat{
				Path:    fmt.Sprintf("%v/%v", newuri, file),
				Deleted: deleted,
			})
		}

		if err != nil {
			return files, err
		}
	}

	err = scanner.Err()
	err = cmd.Wait()
	return files, err
}
