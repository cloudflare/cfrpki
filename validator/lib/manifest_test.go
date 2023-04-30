package librpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func MakeMFTContent() ManifestContent {
	roahash := sha256.Sum256([]byte("roahash"))
	crlhash := sha256.Sum256([]byte("crlhash"))
	manifestContent := ManifestContent{
		ManifestNumber: big.NewInt(7845),
		ThisUpdate:     time.Now().UTC(),
		NextUpdate:     time.Now().UTC(),
		FileHashAlg:    SHA256OID,
		FileList: []File{
			File{
				Name: "test.roa",
				Hash: asn1.BitString{
					Bytes:     roahash[:],
					BitLength: 256,
				},
			},
			File{
				Name: "test.crl",
				Hash: asn1.BitString{
					Bytes:     crlhash[:],
					BitLength: 256,
				},
			},
		},
	}
	return manifestContent
}

func TestEncodeMFTContent(t *testing.T) {
	content := MakeMFTContent()
	contentEnc, err := EncodeManifestContent(content)
	assert.Nil(t, err)

	cms, err := EncodeCMS(nil, contentEnc, time.Now().UTC())
	assert.Nil(t, err)

	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
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
	require.NoError(t, err)

	encap, _ := EContentToEncap(contentEnc.EContent.FullBytes)
	err = cms.Sign(rand.Reader, ski, encap, privkey, certBytes)
	assert.Nil(t, err)

	entriesBytes, err := asn1.Marshal(*cms)
	assert.Nil(t, err)

	dc := &DecoderConfig{
		ValidateStrict: false,
	}
	_, err = dc.DecodeManifest(entriesBytes)
	assert.Nil(t, err)
}
