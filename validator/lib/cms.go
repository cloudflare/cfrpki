package librpki

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	SigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type Attribute struct {
	AttrType  asn1.ObjectIdentifier
	AttrValue []asn1.RawValue `asn1:"set"`
}

type SignerInfo struct {
	Version            int
	Sid                asn1.RawValue
	DigestAlgorithms   []asn1.RawValue
	SignedAttrs        []Attribute `asn1:"optional,tag:0,implicit,set"`
	SignatureAlgorithm asn1.RawValue
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1,implicit"`
}

type CmsSignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"tag:0,optional"`
	CRLs             asn1.RawValue `asn1:"tag:1,optional"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

type CMS struct {
	OID        asn1.ObjectIdentifier
	SignedData CmsSignedData `asn1:"explicit,tag:0"`
}

// https://stackoverflow.com/questions/44852289/decrypt-with-public-key
func RSA_public_decrypt(pubKey *rsa.PublicKey, data []byte) []byte {
	c := new(big.Int)
	m := new(big.Int)
	m.SetBytes(data)
	e := big.NewInt(int64(pubKey.E))
	c.Exp(m, e, pubKey.N)
	out := c.Bytes()
	skip := 0
	for i := 2; i < len(out); i++ {
		if i+1 >= len(out) {
			break
		}
		if out[i] == 0xff && out[i+1] == 0 {
			skip = i + 2
			break
		}
	}
	return out[skip:]
}

type SignatureInner struct {
	OID asn1.ObjectIdentifier
}

type SignatureDecoded struct {
	Inner SignatureInner
	Hash  []byte
}

type SignedAttributesDigest struct {
	SignedAttrs []Attribute `asn1:"set"`
}

func DecryptSignatureRSA(signature []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	dataDecrypted := RSA_public_decrypt(pubKey, signature)
	var signDec SignatureDecoded
	_, err := asn1.Unmarshal(dataDecrypted, &signDec)
	if err != nil {
		return nil, err
	}
	return signDec.Hash, nil
}

// Won't validate if signedattributes is empty
func (cms *CMS) Validate(encap []byte, cert *x509.Certificate) error {
	signedAttributes := cms.SignedData.SignerInfos[0].SignedAttrs

	var messageDigest []byte
	for _, sAttr := range signedAttributes {

		// https://tools.ietf.org/html/rfc5652#section-5.4
		if sAttr.AttrType.Equal(MessageDigest) && len(sAttr.AttrValue) == 1 {
			messageDigest = sAttr.AttrValue[0].Bytes
		}
	}

	h := sha256.New()
	h.Write(encap)
	contentHash := h.Sum(nil)
	if !bytes.Equal(contentHash, messageDigest) {
		return errors.New(fmt.Sprintf("CMS digest (%x) and encapsulated digest (%x) are different", contentHash, messageDigest))
	}

	var sad SignedAttributesDigest
	sad.SignedAttrs = signedAttributes
	b, err := asn1.Marshal(sad)
	if err != nil {
		return err
	}
	h = sha256.New()
	if len(b) < 2 {
		return errors.New("Error with length of signed attributes")
	}
	h.Write(b[2:]) // removes the "sequence"
	signedAttributesHash := h.Sum(nil)

	// Check for public key format (ECDSA?)
	decryptedHash, err := DecryptSignatureRSA(cms.SignedData.SignerInfos[0].Signature, cert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return err
	}
	if !bytes.Equal(signedAttributesHash, decryptedHash) {
		return errors.New(fmt.Sprintf("CMS encrypted digest (%x) and calculated digest (%x) are different", decryptedHash, signedAttributesHash))
	}
	return nil
}

func BadFormatGroup(data []byte) ([]byte, bool, error) {
	var offset int
	fullbytes := make([]byte, 0)

	var err error
	var k []byte
	var iterations int

	var preTag asn1.RawValue
	_, err = asn1.Unmarshal(data, &preTag)
	if preTag.Tag == asn1.TagOctetString {
		for {
			var tmp []byte
			k, err = asn1.Unmarshal(data[offset:], &tmp)

			offset = len(data) - len(k)
			fullbytes = append(fullbytes, tmp...)
			iterations++
			if len(k) == 0 || err != nil {
				break
			}
		}
	} else {
		fullbytes = preTag.FullBytes
	}

	return fullbytes, iterations > 1, err
}

func (cms *CMS) GetRPKICertificate() (*RPKI_Certificate, error) {
	rpki_cert, err := DecodeCertificate(cms.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	return rpki_cert, nil
}

func (cms *CMS) GetSigningTime() (time.Time, error) {
	var signingTime time.Time
	signedAttributes := cms.SignedData.SignerInfos[0].SignedAttrs
	for _, sAttr := range signedAttributes {
		if sAttr.AttrType.Equal(SigningTime) && len(sAttr.AttrValue) > 0 {
			_, err := asn1.Unmarshal(sAttr.AttrValue[0].FullBytes, &signingTime)
			return signingTime, err
		}
	}
	return signingTime, nil
}

func DecodeCMS(data []byte) (*CMS, error) {
	var c CMS
	_, err := asn1.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
