package syncpki

import (
	"encoding/xml"
)

type RootNode struct {
	Xmlns     string `xml:"xmlns,attr"`
	Version   string `xml:"version,attr"`
	SessionID string `xml:"session_id,attr"`
	Serial    int64  `xml:"serial,attr"`
}

type ElNode struct {
	Serial int64  `xml:"serial,attr"`
	URI    string `xml:"uri,attr"`
	Hash   string `xml:"hash,attr"`
}

type Cert struct {
	URI   string `xml:"uri,attr"`
	Value string `xml:",chardata"`
}

type Notification struct {
	RootNode
	XMLName  xml.Name `xml:"notification"`
	Snapshot ElNode   `xml:"snapshot"`
	Deltas   []ElNode `xml:"delta"`
}

type Delta struct {
	RootNode
	XMLName  xml.Name `xml:"delta"`
	Publish  []Cert   `xml:"publish"`
	Withdraw []Cert   `xml:"withdraw"`
}

type Snapshot struct {
	RootNode
	XMLName  xml.Name `xml:"snapshot"`
	Publish  []Cert   `xml:"publish"`
	Withdraw []Cert   `xml:"withdraw"`
}
