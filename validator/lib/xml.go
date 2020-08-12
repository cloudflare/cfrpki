package librpki

import (
	"bytes"
	"encoding/asn1"
	"encoding/xml"
)

var (
	XMLOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 28}
)

type XML struct {
	OID      asn1.ObjectIdentifier
	EContent asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type XMLContent struct {
	Message interface{}
}

type RPKIXML struct {
	Content     []byte
	Certificate *RPKICertificate

	InnerValid         bool
	InnerValidityError error
}

func EncodeXMLContent(content interface{}) (*XML, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := xml.NewEncoder(buf)
	err := enc.Encode(content)
	if err != nil {
		return nil, err
	}
	return EncodeXMLData(buf.Bytes())
}

func EncodeXMLData(message []byte) (*XML, error) {
	eContentEnc, err := asn1.MarshalWithParams(message, "tag:0,explicit")
	if err != nil {
		return nil, err
	}

	xmlContent := &XML{
		OID:      XMLOID,
		EContent: asn1.RawValue{FullBytes: eContentEnc},
	}
	return xmlContent, nil
}

func DecodeXML(data []byte) (*RPKIXML, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
	}

	var rawxml XML
	_, err = asn1.Unmarshal(c.SignedData.EncapContentInfo.FullBytes, &rawxml)
	if err != nil {
		return nil, err
	}

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(rawxml.EContent.Bytes, &inner)
	if err != nil {
		return nil, err
	}

	var rpki_xml RPKIXML
	rpki_xml.Content = inner.Bytes

	cert, err := c.GetRPKICertificate()
	if err != nil {
		return &rpki_xml, err
	}
	rpki_xml.Certificate = cert

	err = c.Validate(inner.Bytes, cert.Certificate)
	if err != nil {
		rpki_xml.InnerValidityError = err
	} else {
		rpki_xml.InnerValid = true
	}

	return &rpki_xml, nil
}
