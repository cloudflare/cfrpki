package ca

import (
	"bytes"
	"encoding/xml"
	"io"
)

const (
	XML_VERSION_RFC8181 = 4
	XML_VERSION_RFC8183 = 1
)

type XMLMessage struct {
	XMLName xml.Name `xml:"http://www.hactrn.net/uris/rpki/publication-spec/ msg"`
	Version int      `xml:"version,attr"`
	Type    string   `xml:"type,attr"`
	Inner   string   `xml:",innerxml"`
}

type XMLMessageChildRequest struct {
	XMLName     xml.Name `xml:"http://www.hactrn.net/uris/rpki/rpki-setup/ child_request"`
	Version     int      `xml:"version,attr"`
	ChildHandle string   `xml:"child_handle,attr"`
	Tag         string   `xml:"tag,attr"`
	Inner       string   `xml:",innerxml"`
}

type XMLMessageParentResponse struct {
	XMLName      xml.Name `xml:"http://www.hactrn.net/uris/rpki/rpki-setup/ parent_response"`
	Version      int      `xml:"version,attr"`
	Tag          string   `xml:"tag,attr"`
	ServiceURI   string   `xml:"service_uri,attr"`
	ChildHandle  string   `xml:"child_handle,attr"`
	ParentHandle string   `xml:"parent_handle,attr"`
	Inner        string   `xml:",innerxml"`
}

type XMLMessagePublisherRequest struct {
	XMLName         xml.Name `xml:"http://www.hactrn.net/uris/rpki/rpki-setup/ publisher_request"`
	Version         int      `xml:"version,attr"`
	Tag             string   `xml:"tag,attr"`
	PublisherHandle string   `xml:"publisher_handle,attr"`
	Inner           string   `xml:",innerxml"`
}

type XMLMessageRepositoryResponse struct {
	XMLName             xml.Name `xml:"http://www.hactrn.net/uris/rpki/rpki-setup/ repository_response"`
	Version             int      `xml:"version,attr"`
	Tag                 string   `xml:"tag,attr"`
	ServiceURI          string   `xml:"service_uri,attr"`
	SIABase             string   `xml:"sia_base,attr"`
	RRDPNotificationURI string   `xml:"rrdp_notification_uri,attr"`
	PublisherHandle     string   `xml:"publisher_handle,attr"`
	Inner               string   `xml:",innerxml"`
}

func NewXMLList() *XMLMessage {
	return &XMLMessage{
		Version: XML_VERSION_RFC8181,
		Type:    "query",
		Inner:   "<list/>",
	}
}

type Content struct {
	XMLName   xml.Name
	Hash      string `xml:"hash,attr"`
	ErrorCode string `xml:"error_code,attr"`
	Tag       string `xml:"tag,attr"`
	URI       string `xml:"uri,attr"`
	Inner     string `xml:",innerxml"`
}

func DecodeInner(inner []byte) ([]Content, error) {
	var innerContent []Content
	var err error
	if len(inner) > 0 {
		buf := bytes.NewBuffer(inner)
		dec := xml.NewDecoder(buf)
		for err == nil {
			err = dec.Decode(&innerContent)
		}
		if err == io.EOF {
			err = nil
		}
	}
	return innerContent, err
}

func DecodeXML(message []byte) (*XMLMessage, error) {
	var msg XMLMessage
	buf := bytes.NewBuffer(message)
	dec := xml.NewDecoder(buf)
	err := dec.Decode(&msg)
	return &msg, err
}

func DecodeXMLFull(message []byte) (*XMLMessage, []Content, error) {
	var msg XMLMessage
	buf := bytes.NewBuffer(message)
	dec := xml.NewDecoder(buf)
	err := dec.Decode(&msg)
	if err != nil {
		return nil, nil, err
	}
	innerContent, err := DecodeInner([]byte(msg.Inner))
	return &msg, innerContent, err
}

func DecodeXMLCRFull(message []byte) (*XMLMessageChildRequest, []Content, error) {
	var msg XMLMessageChildRequest
	buf := bytes.NewBuffer(message)
	dec := xml.NewDecoder(buf)
	err := dec.Decode(&msg)
	if err != nil {
		return nil, nil, err
	}
	innerContent, err := DecodeInner([]byte(msg.Inner))
	return &msg, innerContent, err
}

func DecodeXMLPRFull(message []byte) (*XMLMessageParentResponse, []Content, error) {
	var msg XMLMessageParentResponse
	buf := bytes.NewBuffer(message)
	dec := xml.NewDecoder(buf)
	err := dec.Decode(&msg)
	if err != nil {
		return nil, nil, err
	}
	innerContent, err := DecodeInner([]byte(msg.Inner))
	return &msg, innerContent, err
}
