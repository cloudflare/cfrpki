package librpki

import (
	"encoding/asn1"
	"math/big"
	"time"
)

type FileList struct {
	File string
	Hash asn1.BitString
}

type ManifestContent struct {
	ManifestNumber *big.Int
	ThisUpdate     time.Time
	NextUpdate     time.Time
	FileHashAlg    asn1.ObjectIdentifier
	FileList       []FileList
}

type Manifest struct {
	OID      asn1.ObjectIdentifier
	EContent asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type RPKI_Manifest struct {
	Certificate        *RPKI_Certificate
	Content            ManifestContent
	BadFormat          bool
	InnerValid         bool
	InnerValidityError error
}

func DecodeManifest(data []byte) (*RPKI_Manifest, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	_, err = asn1.Unmarshal(c.SignedData.EncapContentInfo.FullBytes, &manifest)
	if err != nil {
		return nil, err
	}

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(manifest.EContent.Bytes, &inner)
	if err != nil {
		return nil, err
	}

	fullbytes, badformat, err := BadFormatGroup(inner.Bytes)
	if err != nil {
		return nil, err
	}

	fullbytes, _ = BER2DER(fullbytes)
	var mc ManifestContent
	_, err = asn1.Unmarshal(fullbytes, &mc)
	if err != nil {
		return nil, err
	}

	rpki_manifest := &RPKI_Manifest{
		Content:   mc,
		BadFormat: badformat}

	cert, err := c.GetRPKICertificate()
	if err != nil {
		return rpki_manifest, err
	}
	rpki_manifest.Certificate = cert

	// Validate the content of the CMS
	err = c.Validate(fullbytes, cert.Certificate)
	if err != nil {
		rpki_manifest.InnerValidityError = err
	} else {
		rpki_manifest.InnerValid = true
	}

	return rpki_manifest, nil
}
