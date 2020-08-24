package librpki

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type RPKITAL struct {
	URI       []string
	Algorithm x509.PublicKeyAlgorithm
	OID       asn1.ObjectIdentifier
	PublicKey interface{}
}

func (tal *RPKITAL) HasRsync() bool {
	for _, url := range tal.URI {
		if strings.HasPrefix(url, "rsync://") {
			return true
		}
	}
	return false
}

// Returns the rsync URL associated with the TAL certificate.
// If it does not exist (http only), return a made up URI
func (tal *RPKITAL) GetRsyncURI() string {
	var rsync string
	var other string
	for _, url := range tal.URI {
		if strings.HasPrefix(url, "rsync://") {
			rsync = url
			break
		}
		other = url
	}
	if rsync == "" {
		rsync = fmt.Sprintf("rsync://rfc8630/certs/%x.cer", sha1.Sum([]byte(other)))
	}
	return rsync
}

func (tal *RPKITAL) GetURI() string {
	uri := "unknown"
	if len(tal.URI) > 0 {
		uri = tal.URI[0]
	}
	return uri
}

func (tal *RPKITAL) CheckCertificate(cert *x509.Certificate) bool {
	if tal.Algorithm == cert.PublicKeyAlgorithm {
		switch tal.Algorithm {
		case x509.RSA:
			a := tal.PublicKey.(*rsa.PublicKey)
			b := cert.PublicKey.(*rsa.PublicKey)
			if a.N.Cmp(b.N) == 0 && a.E == b.E {
				return true
			}
		}
	}
	return false
}

func DeleteLineEnd(line string) string {
	if len(line) > 1 && line[len(line)-2] == 0xd {
		line = line[0 : len(line)-2]
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[0 : len(line)-1]
	}
	return line
}

func CreateTAL(uri []string, pubkey interface{}) (*RPKITAL, error) {
	var pubkeyc interface{}
	switch pubkeyt := pubkey.(type) {
	case *rsa.PublicKey:
		pubkeyc = *pubkeyt
	case rsa.PublicKey:
		pubkeyc = pubkeyt
	default:
		return nil, errors.New("Public key is not RSA")
	}
	return &RPKITAL{
		URI:       uri,
		Algorithm: x509.RSA,
		OID:       RSA,
		PublicKey: pubkeyc,
	}, nil
}

func EncodeTAL(tal *RPKITAL) ([]byte, error) {
	return EncodeTALSize(tal, 64)
}

func HashPublicKey(key interface{}) ([]byte, error) {
	switch keyc := key.(type) {
	case *rsa.PublicKey:
		return HashRSAPublicKey(*keyc)
	case rsa.PublicKey:
		return HashRSAPublicKey(keyc)
	default:
		return nil, errors.New("Public key is not RSA")
	}
}

func HashRSAPublicKey(key rsa.PublicKey) ([]byte, error) {
	keyBytesHash, err := asn1.Marshal(key)
	if err != nil {
		return nil, err
	}

	hash := sha1.Sum(keyBytesHash)
	return hash[:], nil
}

func BundleRSAPublicKey(key rsa.PublicKey) (asn1.BitString, error) {
	keyBytes, err := asn1.Marshal(key)
	if err != nil {
		return asn1.BitString{}, err
	}
	return asn1.BitString{Bytes: keyBytes}, nil

}

func EncodeTALSize(tal *RPKITAL, split int) ([]byte, error) {
	var bs asn1.BitString
	var err error
	if tal.OID.Equal(RSA) {
		keyRaw := tal.PublicKey.(rsa.PublicKey)
		bs, err = BundleRSAPublicKey(keyRaw)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("TAL does not contain a RSA key")
	}

	type subjectPublicKeyInfo struct {
		Type struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}
		BS asn1.BitString
	}

	spki := subjectPublicKeyInfo{
		Type: struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}{
			OID:  tal.OID,
			Null: asn1.NullRawValue,
		},
		BS: bs,
	}
	keyBytesData, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}
	key := base64.RawStdEncoding.EncodeToString(keyBytesData)
	if split > 0 {
		keySplit := make([]string, len(key)/split+1)
		for i := 0; i < len(key)/split+1; i++ {
			max := (i + 1) * split
			if len(key) < max {
				max = len(key)
			}
			keySplit[i] = key[i*split : max]
		}
		key = strings.Join(keySplit, "\n")
	}

	return []byte(fmt.Sprintf("%s\n\n%s", strings.Join(tal.URI, "\n"), key)), nil
}

func DecodeTAL(data []byte) (*RPKITAL, error) {
	buf := bytes.NewBufferString(string(data))

	var passedUrl bool
	var b64 string
	urls := make([]string, 0)
	for {
		line, err := buf.ReadString('\n')
		if err != nil && err == io.EOF {
			if line != "" {
				b64 += line
			}
			break
		}
		if err != nil {
			return nil, err
		}
		line = DeleteLineEnd(line)

		if len(line) > 0 && line[0] == 0xd {
			line = line[1:]
		}

		if len(line) > 0 && line[0] != '#' && !passedUrl {
			urls = append(urls, line)
		}

		if len(line) == 0 {
			passedUrl = true
		}

		if len(line) > 0 && passedUrl {
			b64 += line
		}

	}

	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	type subjectPublicKeyInfo struct {
		Type struct {
			OID asn1.ObjectIdentifier
		}
		BS asn1.BitString
	}

	var inner subjectPublicKeyInfo
	_, err = asn1.Unmarshal(d, &inner)
	if err != nil {
		return nil, err
	}

	tal := &RPKITAL{
		URI: urls,
		OID: inner.Type.OID,
	}

	if tal.OID.Equal(RSA) {
		tal.Algorithm = x509.RSA

		var inner2 rsa.PublicKey
		_, err = asn1.Unmarshal(inner.BS.Bytes, &inner2)

		if err != nil {
			return nil, err
		}
		tal.PublicKey = &inner2
	} else {
		tal.PublicKey = inner.BS.Bytes
	}
	return tal, nil
}
