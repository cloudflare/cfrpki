package librpki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"
)

var (
	OidSignatureSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OidSerialNumber           = asn1.ObjectIdentifier{2, 5, 29, 20}
)

type CRLAuthKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// https://tools.ietf.org/html/rfc6487#section-5
func CreateCRL(c *x509.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time, sn *big.Int) (crlBytes []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	hashFunc := crypto.SHA256
	signatureAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  OidSignatureSHA256WithRSA,
		Parameters: asn1.NullRawValue,
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:             1,
		Signature:           signatureAlgorithm,
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCertsUTC,
	}

	// Authority Key Id
	if len(c.SubjectKeyId) > 0 {
		var aki pkix.Extension
		aki.Id = AuthorityKeyIdentifier
		aki.Value, err = asn1.Marshal(CRLAuthKeyId{Id: c.SubjectKeyId})
		if err != nil {
			return
		}
		tbsCertList.Extensions = append(tbsCertList.Extensions, aki)
	}

	// Serial Number
	var snExt pkix.Extension
	snExt.Id = OidSerialNumber
	snExt.Value, err = asn1.Marshal(sn)
	if err != nil {
		return
	}
	tbsCertList.Extensions = append(tbsCertList.Extensions, snExt)

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	h := hashFunc.New()
	h.Write(tbsCertListContents)
	digest := h.Sum(nil)

	var signature []byte
	signature, err = key.Sign(rand, digest, hashFunc)
	if err != nil {
		return
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
