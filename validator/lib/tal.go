package librpki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"io"
)

var (
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type RPKI_TAL struct {
	URI       string
	Algorithm x509.PublicKeyAlgorithm
	OID       asn1.ObjectIdentifier
	PublicKey interface{}
}

func (tal *RPKI_TAL) CheckCertificate(cert *x509.Certificate) bool {
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

func DecodeTAL(data []byte) (*RPKI_TAL, error) {
	buf := bytes.NewBufferString(string(data))
	url, err := buf.ReadString('\n')
	url = DeleteLineEnd(url)
	if err != nil {
		return nil, err
	}
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	if b == 0xd {
		b, err = buf.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	b64, err := buf.ReadString('\n')
	b64 = DeleteLineEnd(b64)
	for err == nil {
		var b64tmp string
		b64tmp, err = buf.ReadString('\n')
		b64tmp = DeleteLineEnd(b64tmp)
		b64 += b64tmp
	}
	if err != io.EOF {
		return nil, err
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

	tal := &RPKI_TAL{
		URI: url,
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
