package syncpki

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type RRDPFetcher interface {
	GetXML(string) (string, error)
}

type HTTPFetcher struct {
	UserAgent string
	Client    *http.Client
}

func (f *HTTPFetcher) GetXML(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return "", errors.New(fmt.Sprintf("Fetching error: %v", err))
	}

	// Set recommended header
	req.Header.Set("User-Agent", f.UserAgent)

	res, err := f.Client.Do(req)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Fetching error: %v", err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("Fetching status error: %v", res.StatusCode))
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ParseRoot(data string) (Notification, error) {
	n := Notification{}

	r := bytes.NewBufferString(data)
	decoder := xml.NewDecoder(r)

	for {
		t, _ := decoder.Token()
		if t == nil {
			// EOF
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			name := se.Name.Local
			switch name {
			case "notification":
				err := decoder.DecodeElement(&n, &se)
				if err != nil {
					return n, errors.New("XML does not conform to schema")
				}
			}
		}
	}
	return n, nil
}

func ParseNode(data string) ([]Cert, []Cert, error) {
	var publish []Cert
	var withdraw []Cert
	d := Delta{}
	s := Snapshot{}

	byteStr := bytes.NewBufferString(data)
	decoder := xml.NewDecoder(byteStr)

	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			name := se.Name.Local
			switch name {
			case "delta":
				err := decoder.DecodeElement(&d, &se)

				for _, v := range d.Publish {
					publish = append(publish, v)
				}

				if (len(d.Withdraw)) > 0 {
					for _, v := range d.Withdraw {
						withdraw = append(withdraw, v)
					}
				}

				if err != nil {
					return publish, withdraw, errors.New("XML does not conform to schema")
				}
			case "snapshot":
				err := decoder.DecodeElement(&s, &se)

				for _, v := range s.Publish {
					publish = append(publish, v)
				}

				if (len(s.Withdraw)) > 0 {
					for _, v := range s.Withdraw {
						withdraw = append(withdraw, v)
					}
				}

				if err != nil {
					return publish, withdraw, errors.New("XML does not conform to schema")
				}
			}
		}
	}
	return publish, withdraw, nil
}

type RRDPFile func(main string, url string, path string, data []byte, withdraw bool, snapshot bool, curId int64, args ...interface{}) error

type RRDPSystem struct {
	Log     Logger
	Fetcher RRDPFetcher

	Callback RRDPFile

	Path      string
	SessionID string
	Serial    int64
}

func DecodeRRDPBase64(value string) ([]byte, error) {
	value = strings.Replace(value, " ", "", -1)
	value = strings.Replace(value, "\n", "", -1)
	value = strings.Replace(value, "\r", "", -1)
	return base64.StdEncoding.DecodeString(value)
}

func (s *RRDPSystem) FetchRRDP(cbArgs ...interface{}) error {
	if s.Log != nil {
		s.Log.Infof("RRDP: Downloading root notification %v", s.Path)
	}
	data, err := s.Fetcher.GetXML(s.Path)
	if err != nil {
		return err
	}
	root, err := ParseRoot(data)
	if err != nil {
		return err
	}

	curSessionID := root.SessionID
	lastSessionID := s.SessionID
	curSerial := int64(root.RootNode.Serial)
	lastSerial := s.Serial

	deltasMap := make(map[int64]ElNode)

	for _, v := range root.Deltas {
		deltasMap[int64(v.Serial)] = v
	}

	// If the last downloaded Delta is not in the map, the
	// whole notification.xml file has gone stale
	var missingFiles bool
	serial := lastSerial
	for serial = lastSerial; serial <= curSerial; serial++ {
		if _, ok := deltasMap[serial]; !ok {
			missingFiles = true
			break
		}
	}

	if lastSerial == 0 || lastSessionID != curSessionID || missingFiles {
		if s.Log != nil {
			s.Log.Infof("RRDP: %v Downloading snapshot at: %s", s.Path, root.Snapshot.URI)
		}

		data, err := s.Fetcher.GetXML(root.Snapshot.URI)
		if err != nil {
			return err
		}
		publish, withdraw, err := ParseNode(data)
		if err != nil {
			return err
		}

		if s.Callback != nil {
			for _, v := range publish {
				vdec, err := DecodeRRDPBase64(v.Value)
				if err != nil {
					return err
				}
				err = s.Callback(s.Path, root.Snapshot.URI, v.URI, vdec, false, true, curSerial, cbArgs...)
				if err != nil {
					return err
				}
			}
			for _, v := range withdraw {
				vdec, err := DecodeRRDPBase64(v.Value)
				if err != nil {
					return err
				}
				err = s.Callback(s.Path, root.Snapshot.URI, v.URI, vdec, true, true, curSerial, cbArgs...)
				if err != nil {
					return err
				}
			}
		}
	} else {
		if s.Log != nil {
			s.Log.Infof("RRDP: %v has %d deltas to parse (cur: %v, last: %v)", s.Path, curSerial-lastSerial, curSerial, lastSerial)
		}

		for serial = lastSerial; serial <= curSerial; serial++ {
			elNode, ok := deltasMap[serial]
			if !ok {
				return errors.New(fmt.Sprintf("Could not find delta with serial %v", serial))
			}
			if s.Log != nil {
				s.Log.Debugf("RRDP: Fetching serial: %v (%v) for %v", serial, elNode.URI, s.Path)
			}
			data, err := s.Fetcher.GetXML(elNode.URI)
			if err != nil {
				return err
			}
			deltaPublish, deltaWithdraw, err := ParseNode(data)
			if err != nil {
				return err
			}

			// Before inserting: check hash
			if s.Callback != nil {
				for _, v := range deltaPublish {
					vdec, err := DecodeRRDPBase64(v.Value)
					if err != nil {
						return err
					}
					err = s.Callback(s.Path, root.Snapshot.URI, v.URI, vdec, false, false, elNode.Serial, cbArgs...)
					if err != nil {
						return err
					}
				}
				for _, v := range deltaWithdraw {
					vdec, err := DecodeRRDPBase64(v.Value)
					if err != nil {
						return err
					}
					s.Callback(s.Path, root.Snapshot.URI, v.URI, vdec, true, false, elNode.Serial, cbArgs...)
					if err != nil {
						return err
					}
				}
			}
		}
		curSerial = serial
		if s.Log != nil {
			s.Log.Infof("RRDP: finished downloading %v. Last serial %v", s.Path, curSerial)
		}
	}
	s.Serial = curSerial
	s.SessionID = curSessionID
	return nil
}
