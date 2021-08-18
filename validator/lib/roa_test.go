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

func MakeROAEntries() []*ROAEntry {
	_, prefix, _ := net.ParseCIDR("10.0.0.0/20")
	return []*ROAEntry{
		&ROAEntry{
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

	dc := &DecoderConfig{
		ValidateStrict: false,
	}
	// At the moment, certificate encoding relying on Golang's library
	// does not produce the NULL-ended signature algorithm field.
	// Must disable strict validation for test to go through.
	_, err = dc.DecodeROA(entriesBytes)
	assert.Nil(t, err)
}

func TestValidateROAEntry(t *testing.T) {
	// Valid
	_, ipnet, _ := net.ParseCIDR("192.0.2.0/24")
	roaEntryValid := ROAEntry{
		IPNet:     ipnet,
		MaxLength: 24,
	}

	// Invalid (max length too small)
	_, ipnet, _ = net.ParseCIDR("192.0.2.0/24")
	roaEntryInvalidSmallMaxLength := ROAEntry{
		IPNet:     ipnet,
		MaxLength: 8,
	}

	// Invalid IPv4 (max length out of bounds)
	_, ipnet, _ = net.ParseCIDR("192.0.2.0/24")
	roaEntryInvalidLargeMaxLength := ROAEntry{
		IPNet:     ipnet,
		MaxLength: 128,
	}

	// Invalid IPv6 (max length out of bounds)
	_, ipnet, _ = net.ParseCIDR("2001:db8::/128")
	roaEntryInvalidv6LargeMaxLength := ROAEntry{
		IPNet:     ipnet,
		MaxLength: 130,
	}

	// Invalid (max length negative)
	_, ipnet, _ = net.ParseCIDR("0.0.0.0/0")
	roaEntryInvalidNegativeMaxLength := ROAEntry{
		IPNet:     ipnet,
		MaxLength: -1,
	}

	for _, tc := range []struct {
		ROAEntry    ROAEntry
		ShouldError bool
	}{
		{roaEntryValid, false},
		{roaEntryInvalidSmallMaxLength, true},
		{roaEntryInvalidLargeMaxLength, true},
		{roaEntryInvalidv6LargeMaxLength, true},
		{roaEntryInvalidNegativeMaxLength, true},
	} {
		err := tc.ROAEntry.Validate()
		if !tc.ShouldError {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}
