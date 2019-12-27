package librpki

import (
	"net"
	"testing"
	//"encoding/asn1"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
)

func MakeSIA() []*SIA {
	return []*SIA{
		&SIA{
			AccessMethod: SIAManifest,
			GeneralName:  []byte("rsync://example.com/root.cer"),
		},
		&SIA{
			AccessMethod: CertRRDP,
			GeneralName:  []byte("https://example.com/notification.xml"),
		},
		&SIA{
			AccessMethod: CertRepository,
			GeneralName:  []byte("rsync://example.com/repository/"),
		},
	}
}

func MakeIPs(null bool) []IPCertificateInformation {
	if null {
		return []IPCertificateInformation{
			&IPAddressNull{
				Family: 1,
			},
		}
	}

	_, net1, _ := net.ParseCIDR("0.0.0.0/0")
	_, net2, _ := net.ParseCIDR("::/0")
	ip1 := net.ParseIP("192.168.0.1")
	ip2 := net.ParseIP("192.168.0.3")

	return []IPCertificateInformation{
		&IPNet{
			IPNet: net1,
		},
		&IPNet{
			IPNet: net2,
		},
		&IPAddressRange{
			Min: ip1,
			Max: ip2,
		},
		//&IPAddressNull{Family: 1,},
	}
}

func MakeASN(null bool) []ASNCertificateInformation {
	if null {
		return []ASNCertificateInformation{
			&ASNull{},
		}
	}
	return []ASNCertificateInformation{
		&ASNRange{
			Min: 0,
			Max: 4294967295,
		},
		&ASNRange{
			Min: 0,
			Max: 4294967295,
		},
		&ASN{
			ASN: 65001,
		},
		&ASN{
			ASN: 65002,
		},
	}
}

func TestEncodeSIA(t *testing.T) {
	sias := MakeSIA()
	siaExtension, err := EncodeSIA(sias)
	assert.Nil(t, err)

	_, err = DecodeSubjectInformationAccess(siaExtension.Value)
	assert.Nil(t, err)
}

func TestEncodeIPBlocks(t *testing.T) {
	ipBlocks := MakeIPs(true)
	ipblocksExtension, err := EncodeIPAddressBlock(ipBlocks)
	assert.Nil(t, err)
	ipblocksDec, err := DecodeIPAddressBlock(ipblocksExtension.Value)
	assert.Nil(t, err)
	assert.NotNil(t, ipblocksDec)

	ipBlocks = MakeIPs(false)
	ipblocksExtension, err = EncodeIPAddressBlock(ipBlocks)
	assert.Nil(t, err)
	ipblocksDec, err = DecodeIPAddressBlock(ipblocksExtension.Value)
	assert.Nil(t, err)
	assert.NotNil(t, ipblocksDec)
}

func TestEncodeASN(t *testing.T) {
	asns := MakeASN(true)
	asnExtension, err := EncodeASN(asns, nil)
	assert.Nil(t, err)

	asnDec, rdiDec, err := DecodeASN(asnExtension.Value)
	assert.Nil(t, err)
	assert.NotNil(t, asnDec)
	assert.NotNil(t, rdiDec)

	asns = MakeASN(false)
	asnExtension, err = EncodeASN(asns, nil)
	assert.Nil(t, err)
	asnDec, rdiDec, err = DecodeASN(asnExtension.Value)
	assert.Nil(t, err)
	assert.NotNil(t, asnDec)
	assert.NotNil(t, rdiDec)
}

func TestMakeCertificate(t *testing.T) {
	ipBlocks := MakeIPs(false)
	ipblocksExtension, err := EncodeIPAddressBlock(ipBlocks)
	assert.Nil(t, err)

	asns := MakeASN(false)
	asnExtension, err := EncodeASN(asns, nil)
	assert.Nil(t, err)

	sias := MakeSIA()
	siaExtension, err := EncodeSIA(sias)
	assert.Nil(t, err)

	cert := &x509.Certificate{
		Version:      1,
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			Country:      []string{"USA"},
			Organization: []string{"OctoRPKI"},
		},
		ExtraExtensions: []pkix.Extension{
			*siaExtension,
			*ipblocksExtension,
			*asnExtension,
		},
		SubjectKeyId:          []byte{1, 2, 3, 4},
		CRLDistributionPoints: []string{"https://www.example.com/crl"},
	}

	// KeyUsage!

	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)
	pubkey := privkey.Public()
	_, err = x509.CreateCertificate(rand.Reader, cert, cert, pubkey, privkey)
	assert.Nil(t, err)
}
