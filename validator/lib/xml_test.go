package librpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestEncodeXMLContent(t *testing.T) {
	msg := []byte(`<msg xmlns="http://www.hactrn.net/uris/rpki/publication-spec/" version="4" type="query"><list /></msg>`)
	contentEnc, err := EncodeXMLData(msg)
	assert.Nil(t, err)

	now := time.Now().UTC()
	cms, err := EncodeCMS(nil, contentEnc, now)
	assert.Nil(t, err)

	privkeyParent, err := rsa.GenerateKey(rand.Reader, 2048)
	skiParent, _ := HashRSAPublicKey(*privkeyParent.Public().(*rsa.PublicKey))

	parentCert := &x509.Certificate{
		Version:      1,
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: strings.ToUpper(hex.EncodeToString(skiParent)),
		},
		NotBefore:    now.Add(-time.Minute * 5),
		NotAfter:     now.Add(time.Hour * 24 * (365*100 + 24)),
		SubjectKeyId: skiParent,
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	ski, _ := HashRSAPublicKey(*privkey.Public().(*rsa.PublicKey))

	cert := &x509.Certificate{
		Version:      1,
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: strings.ToUpper(hex.EncodeToString(ski)),
		},
		NotBefore:    now.Add(-time.Minute * 5),
		NotAfter:     now.Add(time.Hour * 24 * (365*100 + 24)),
		SubjectKeyId: ski,
	}
	pubkey := privkey.Public()
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCert, pubkey, privkeyParent)

	crls, err := parentCert.CreateCRL(rand.Reader, privkeyParent, []pkix.RevokedCertificate{}, now.Add(-time.Minute*5), now.Add(time.Minute*5))
	assert.Nil(t, err)
	cms.AddCRLs(crls)

	encap, _ := EContentToEncapBF(contentEnc.EContent.FullBytes, true)
	err = cms.Sign(rand.Reader, ski, encap, privkey, certBytes)
	assert.Nil(t, err)

	entriesBytes, err := asn1.Marshal(*cms)
	assert.Nil(t, err)

	data, err := DecodeXML(entriesBytes)
	assert.Nil(t, err)
	assert.Equal(t, data.Content, msg)
	assert.Equal(t, data.InnerValid, true)
}
