package librpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net"
	"testing"
	"time"
)

func MakeROAEntries() []*ROA_Entry {
	_, prefix, _ := net.ParseCIDR("10.0.0.0/20")
	return []*ROA_Entry{
		&ROA_Entry{
			IPNet:     prefix,
			MaxLength: 20,
		},
	}
}

func TestEncodeROAEntries(t *testing.T) {
	entries := MakeROAEntries()
	entriesEnc, err := EncodeROAEntries(65001, entries)
	assert.Nil(t, err)

	_, err = asn1.Marshal(*entriesEnc)
	assert.Nil(t, err)
}

func TestEncodeROA(t *testing.T) {
	entries := MakeROAEntries()
	entriesEnc, err := EncodeROAEntries(65001, entries)
	assert.Nil(t, err)

	cms, err := EncodeCMS(nil, entriesEnc, time.Now().UTC())
	assert.Nil(t, err)

	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	ski := []byte{1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5}

	cert := &x509.Certificate{
		Version:      1,
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			Country:      []string{"USA"},
			Organization: []string{"OctoRPKI"},
		},
		SubjectKeyId:          ski,
		CRLDistributionPoints: []string{"https://www.example.com/crl"},
	}
	pubkey := privkey.Public()
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pubkey, privkey)

	encap, _ := EContentToEncap(entriesEnc.EContent.FullBytes)
	err = cms.Sign(rand.Reader, ski, encap, privkey, certBytes)
	assert.Nil(t, err)

	entriesBytes, err := asn1.Marshal(*cms)
	assert.Nil(t, err)

	_, err = DecodeROA(entriesBytes)
	assert.Nil(t, err)
}
