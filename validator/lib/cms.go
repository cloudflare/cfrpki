package librpki

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
	//"encoding/hex"
)

var (
	ContentTypeOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	MessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	SigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	SignedDataOID  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	SHA256OID      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	RSAOID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type Attribute struct {
	AttrType  asn1.ObjectIdentifier
	AttrValue []asn1.RawValue `asn1:"set"`
}

type SignerInfo struct {
	Version int
	Sid     asn1.RawValue // `asn1:"tag:0,implicit"`
	//Sid                asn1.RawValue `asn1:"tag:0,implicit"`
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
func RSAPublicDecrypt(pubKey *rsa.PublicKey, data []byte) []byte {
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

func PrivateEncrypt(priv *rsa.PrivateKey, data []byte) (enc []byte, err error) {
	k := (priv.N.BitLen() + 7) / 8
	tLen := len(data)
	// rfc2313, section 8:
	// The length of the data D shall not be more than k-11 octets
	if tLen > k-11 {
		err = errors.New("Input error")
		return
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], data)
	c := new(big.Int).SetBytes(em)
	if c.Cmp(priv.N) > 0 {
		err = errors.New("Encryption error")
		return
	}
	var m *big.Int
	var ir *big.Int
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}
	enc = m.Bytes()
	return
}

type SignatureInner struct {
	OID  asn1.ObjectIdentifier
	Null asn1.RawValue
}

type SignatureDecoded struct {
	Inner SignatureInner
	Hash  []byte
}

type SignedAttributesDigest struct {
	SignedAttrs []Attribute `asn1:"set"`
}

func DecryptSignatureRSA(signature []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	dataDecrypted := RSAPublicDecrypt(pubKey, signature)
	var signDec SignatureDecoded
	_, err := asn1.Unmarshal(dataDecrypted, &signDec)
	if err != nil {
		return nil, err
	}
	return signDec.Hash, nil
}

func EncryptSignatureRSA(rand io.Reader, signature []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	signDec := SignatureDecoded{
		Inner: SignatureInner{
			OID:  SHA256OID,
			Null: asn1.NullRawValue,
		},
		Hash: signature,
	}
	signEnc, err := asn1.Marshal(signDec)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("TEST 1 %v\n", hex.EncodeToString(signEnc))

	signatureM, err := rsa.SignPKCS1v15(rand, privKey, crypto.Hash(0), signEnc)
	//signatureM, err := PrivateEncrypt(privKey, signEnc)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("TEST 2 %v\n", hex.EncodeToString(signatureM))
	//dec, err := DecryptSignatureRSA(signatureM, privKey.Public().(*rsa.PublicKey))
	//fmt.Printf("TEST 2 %v %v\n", hex.EncodeToString(dec), err)

	return signatureM, nil
}

// Pass fullbytes of any EContent
// Do one for ROA and MFT
func EContentToEncap(econtent []byte) ([]byte, error) {
	return EContentToEncapBF(econtent, false)
}

func EContentToEncapBF(econtent []byte, skipbf bool) ([]byte, error) {
	var inner asn1.RawValue
	_, err := asn1.Unmarshal(econtent, &inner)
	if err != nil {
		return inner.Bytes, err
	}
	var inner2 asn1.RawValue
	_, err = asn1.Unmarshal(inner.Bytes, &inner2)
	if err != nil {
		return inner2.Bytes, err
	}
	fullbytes := inner2.Bytes
	if !skipbf {
		fullbytes, _, err = BadFormatGroup(inner2.Bytes)
	}
	return fullbytes, err
}

// https://stackoverflow.com/questions/18011708/encrypt-message-with-rsa-private-key-as-in-openssls-rsa-private-encrypt
func (cms *CMS) Sign(rand io.Reader, ski []byte, encap []byte, priv interface{}, cert []byte) error {
	privKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return errors.New("Private key is not RSA")
	}

	h := sha256.New()
	h.Write(encap)
	messageDigest := h.Sum(nil)
	messageDigestEnc, err := asn1.Marshal(messageDigest)

	digestAttribute := Attribute{
		AttrType:  MessageDigest,
		AttrValue: []asn1.RawValue{asn1.RawValue{FullBytes: messageDigestEnc}},
	}
	cms.SignedData.SignerInfos[0].SignedAttrs = append(cms.SignedData.SignerInfos[0].SignedAttrs, digestAttribute)

	var sad SignedAttributesDigest
	sad.SignedAttrs = cms.SignedData.SignerInfos[0].SignedAttrs
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

	//signature, err := privKey.Sign(rand, signedAttributesHash, nil)
	signature, err := EncryptSignatureRSA(rand, signedAttributesHash, privKey)
	if err != nil {
		return err
	}
	cms.SignedData.SignerInfos[0].Signature = signature

	skiM, err := asn1.MarshalWithParams(ski, "tag:0,optional")
	if err != nil {
		return err
	}
	cms.SignedData.SignerInfos[0].Sid = asn1.RawValue{FullBytes: skiM}

	// Causes the byte slice to be encapsulated in a RawValue instead of an OctetString
	var inner asn1.RawValue
	_, err = asn1.Unmarshal(cert, &inner)
	if err != nil {
		return err
	}
	certM, err := asn1.MarshalWithParams([]asn1.RawValue{inner}, "tag:0,optional")
	if err != nil {
		return err
	}
	cms.SignedData.Certificates = asn1.RawValue{FullBytes: certM}
	return nil
}

func (cms *CMS) AddCRLs(crls []byte) error {
	crlsM, err := asn1.MarshalWithParams([]asn1.RawValue{asn1.RawValue{FullBytes: crls}}, "tag:1,optional")
	if err != nil {
		return err
	}
	cms.SignedData.CRLs = asn1.RawValue{FullBytes: crlsM}
	return nil
}

// Checks for an explicit NULL object in AlgorithmIdentifier
// for both CMS and EE certificate.
func (cms *CMS) CheckSignaturesMatch() (bool, error) {

	type tbsCertificate struct {
		Raw                asn1.RawContent
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       asn1.RawValue
		SignatureAlgorithm asn1.RawValue
	}

	type certificate struct {
		Raw                asn1.RawContent
		TBSCertificate     tbsCertificate
		SignatureAlgorithm asn1.RawValue
	}

	var cert certificate

	_, err := asn1.Unmarshal(cms.SignedData.Certificates.Bytes, &cert)
	if err != nil {
		return false, err
	}
	if len(cms.SignedData.SignerInfos) > 0 {

		var signatureCert []asn1.RawValue
		_, err = asn1.Unmarshal(cert.TBSCertificate.SignatureAlgorithm.FullBytes, &signatureCert)
		if err != nil {
			return false, err
		}
		if len(signatureCert) == 0 {
			return false, nil
		}

		last := signatureCert[len(signatureCert)-1]
		if last.Tag != asn1.TagNull {
			return false, nil
		}

		var signatureCms []asn1.RawValue
		_, err = asn1.Unmarshal(cms.SignedData.SignerInfos[0].SignatureAlgorithm.FullBytes, &signatureCms)
		if err != nil {
			return false, err
		}

		return bytes.Equal(cert.TBSCertificate.SignatureAlgorithm.FullBytes, cms.SignedData.SignerInfos[0].SignatureAlgorithm.FullBytes), nil
	} else {
		return false, nil
	}
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
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("Public key is not RSA")
	}

	decryptedHash, err := DecryptSignatureRSA(cms.SignedData.SignerInfos[0].Signature, pubKey)
	if err != nil {
		return errors.New(fmt.Sprintf("CMS signature decoding error: %v", err))
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

func (cms *CMS) GetRPKICertificate() (*RPKICertificate, error) {
	rpkiCert, err := DecodeCertificate(cms.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	return rpkiCert, nil
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

func EncodeCMS(certificate []byte, encapContent interface{}, signingTime time.Time) (*CMS, error) {
	val := asn1.RawValue{}
	var signOid asn1.ObjectIdentifier
	switch ec := encapContent.(type) {
	case *ROA:
		roaBytes, err := asn1.Marshal(*ec)
		if err != nil {
			return nil, err
		}
		val.FullBytes = roaBytes
		signOid = RoaOID
	case *Manifest:
		mftBytes, err := asn1.Marshal(*ec)
		if err != nil {
			return nil, err
		}
		val.FullBytes = mftBytes
		signOid = ManifestOID
	case *XML:
		xmlBytes, err := asn1.Marshal(*ec)
		if err != nil {
			return nil, err
		}
		val.FullBytes = xmlBytes
		signOid = XMLOID
	default:
		return nil, errors.New("Unknown type of content (not ROA, Manifest or XML)")
	}

	certificateBytes, err := asn1.MarshalWithParams(certificate, "tag:0,implicit")
	if err != nil {
		return nil, err
	}

	type DigestAlg struct {
		OID  asn1.ObjectIdentifier
		Null asn1.RawValue
	}

	type DigestAlgNoNull struct {
		OID asn1.ObjectIdentifier
	}

	dgstBytes, err := asn1.Marshal(DigestAlgNoNull{
		OID: SHA256OID,
		//Null: asn1.NullRawValue,
	})
	if err != nil {
		return nil, err
	}

	/*hash := []byte("abcdeabcdeabcdeabcde")
	sidBytes, err := asn1.MarshalWithParams(hash, "tag:0,implicit")
	if err != nil {
		return nil, err
	}
	sid := asn1.RawValue{FullBytes: sidBytes,}*/

	oidBytes, err := asn1.Marshal(SHA256OID)
	if err != nil {
		return nil, err
	}
	/*nullBytes, err := asn1.Marshal(asn1.NullRawValue)
	if err != nil {
		return nil, err
	}*/
	ctOidBytes, err := asn1.Marshal(signOid)
	if err != nil {
		return nil, err
	}
	signingTimeBytes, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	/*messageDgstBytes, err := asn1.Marshal([]byte("abcdef"))
	if err != nil {
		return nil, err
	}*/
	rsaAlg := DigestAlg{
		OID:  RSAOID,
		Null: asn1.NullRawValue,
	}
	rsaOidBytes, err := asn1.Marshal(rsaAlg)
	if err != nil {
		return nil, err
	}

	attrs := []Attribute{
		Attribute{
			AttrType: ContentTypeOID,
			AttrValue: []asn1.RawValue{
				asn1.RawValue{FullBytes: ctOidBytes},
			},
		},
		Attribute{
			AttrType: SigningTime,
			AttrValue: []asn1.RawValue{
				asn1.RawValue{FullBytes: signingTimeBytes},
			},
		},
		/*Attribute{
			AttrType: MessageDigest,
			AttrValue: []asn1.RawValue{
				asn1.RawValue{FullBytes: messageDgstBytes,},
			},
		},*/
	}

	si := []SignerInfo{
		SignerInfo{
			Version: 3,
			DigestAlgorithms: []asn1.RawValue{
				asn1.RawValue{FullBytes: oidBytes},
				//asn1.RawValue{FullBytes: nullBytes,},
			},
			SignedAttrs:        attrs,
			SignatureAlgorithm: asn1.RawValue{FullBytes: rsaOidBytes},
			//Signature: []byte("abcdeabcdeabcdeabcde"),
		},
	}

	return &CMS{
		OID: SignedDataOID,
		SignedData: CmsSignedData{
			Version: 3,
			DigestAlgorithms: []asn1.RawValue{
				asn1.RawValue{FullBytes: dgstBytes},
			},
			Certificates:     asn1.RawValue{FullBytes: certificateBytes},
			EncapContentInfo: val,
			SignerInfos:      si,
		},
	}, nil
}

func DecodeCMS(data []byte) (*CMS, error) {
	var c CMS
	_, err := asn1.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
