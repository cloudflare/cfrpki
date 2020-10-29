package librpki

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

var (
	SIAManifest = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 10}
	ManifestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 26}
)

type File struct {
	Name string `asn1:"ia5"`
	Hash asn1.BitString
}

func (f File) GetHash() []byte {
	return f.Hash.Bytes
}

type ManifestContent struct {
	ManifestNumber *big.Int
	ThisUpdate     time.Time `asn1:"generalized"`
	NextUpdate     time.Time `asn1:"generalized"`
	FileHashAlg    asn1.ObjectIdentifier
	FileList       []File
}

type Manifest struct {
	OID      asn1.ObjectIdentifier
	EContent asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type RPKIManifest struct {
	Certificate        *RPKICertificate
	Content            ManifestContent
	BadFormat          bool
	InnerValid         bool
	InnerValidityError error
}

func ManifestToEncap(mft *Manifest) ([]byte, error) {
	return EContentToEncap(mft.EContent.FullBytes)
}

func EncodeManifestContent(eContent ManifestContent) (*Manifest, error) {
	eContentEnc, err := asn1.Marshal(eContent)
	if err != nil {
		return nil, err
	}

	eContentEnc, err = asn1.MarshalWithParams(eContentEnc, "tag:0,explicit")
	if err != nil {
		return nil, err
	}

	mft := &Manifest{
		OID:      ManifestOID,
		EContent: asn1.RawValue{FullBytes: eContentEnc},
	}
	return mft, nil
}

func DecodeManifest(data []byte) (*RPKIManifest, error) {
	return DefaultDecoderConfig.DecodeManifest(data)
}

func (cf *DecoderConfig) DecodeManifest(data []byte) (*RPKIManifest, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
	}

	if cf.ValidateStrict {
		vs, err := c.CheckSignaturesMatch()
		if err != nil {
			return nil, err
		}
		if !vs {
			return nil, errors.New("CMS is not valid due to strict signature matching")
		}
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

	rpkiManfiest := &RPKIManifest{
		Content:   mc,
		BadFormat: badformat}

	cert, err := c.GetRPKICertificate()
	if err != nil {
		return rpkiManfiest, err
	}
	rpkiManfiest.Certificate = cert

	// Validate the content of the CMS
	err = c.Validate(fullbytes, cert.Certificate)
	if err != nil {
		rpkiManfiest.InnerValidityError = err
	} else {
		rpkiManfiest.InnerValid = true
	}

	return rpkiManfiest, nil
}
