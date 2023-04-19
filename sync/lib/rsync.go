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

	log "github.com/sirupsen/logrus"
)

const (
	RsyncProtoPrefix = "rsync://"
)

var (
	reDeletion            = regexp.MustCompile("^deleting (.*)")
	wantedFileExtensionRE = regexp.MustCompile("(.*\\.(cer|mft|crl|roa|gbr))$")
)

func ExtractFoldersPathFromRsyncURL(url string) (string, error) {
	if !isRsyncURL(url) {
		return "", fmt.Errorf("%q is not an rsync URL", url)
	}

	fp := strings.Split(strings.TrimPrefix(url, RsyncProtoPrefix), "/")
	if wantedFileExtensionRE.Match([]byte(fp[len(fp)-1])) {
		fp = fp[:len(fp)-1]
	}

	return strings.Join(fp, "/"), nil
}

func ExtractFilePathFromRsyncURL(url string) (string, error) {
	if !isRsyncURL(url) {
		return "", fmt.Errorf("%q is not an rsync URL", url)
	}

	return strings.TrimPrefix(url, RsyncProtoPrefix), nil
}

func isRsyncURL(url string) bool {
	return strings.HasPrefix(url, RsyncProtoPrefix)
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

// Runs the rsync binary on a URL
func RunRsync(ctx context.Context, uri string, bin string, dirPath string) ([]*FileStat, error) {
	if bin == "" {
		return nil, errors.New("rsync binary missing")
	}

	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bin, "-vrlt", uri, dirPath)
	log.Debugf("Command ran: %v", cmd)

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
			log.Error(errorStr)

			err := scanner.Err()
			if err != nil {
				log.Errorf("%v: %v", uri, err)
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

		match := wantedFileExtensionRE.MatchString(line)
		log.Debugf("Rsync received from %v: %v (match=%v)", uri, line, match)

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
