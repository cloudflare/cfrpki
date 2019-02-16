package librpki

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// https://tools.ietf.org/html/rfc6487
// https://tools.ietf.org/html/rfc3779

var (
	IpAddrBlock      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
	AutonomousSysIds = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 8}

	IpAddrBlockV2      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 28}
	AutonomousSysIdsV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 29}
	IpAddrAndASIdent   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30}

	SubjectInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}

	SubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	AuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
)

type IPNet struct {
	IPNet *net.IPNet
}

func (ipn *IPNet) String() string {
	return ipn.IPNet.String()
}

func (ipn *IPNet) IsIPInRange(ip net.IP) (bool, bool) {
	return ipn.IPNet.Contains(ip), false
}

func (ipn *IPNet) GetAfi() uint8 {
	if ipn.IPNet.IP.To4() != nil {
		return 1
	} else if ipn.IPNet.IP.To16() != nil {
		return 2
	}
	return 0
}

func (ipn *IPNet) GetRange() (net.IP, net.IP, bool) {
	min, max := GetRangeIP(ipn.IPNet)
	return min, max, false
}

type IPAddressRange struct {
	Min net.IP
	Max net.IP
}

func (ipr *IPAddressRange) String() string {
	return fmt.Sprintf("Min: %v max: %v", ipr.Min.String(), ipr.Max.String())
}

func (ipr *IPAddressRange) IsIPInRange(ip net.IP) (bool, bool) {
	if len(ip) != len(ipr.Min) || len(ip) != len(ipr.Max) {
		return false, false
	}
	r1 := bytes.Compare(ip, ipr.Min)
	r2 := bytes.Compare(ip, ipr.Max)
	return (r1 == 0 || r1 == 1) && (r2 == 0 || r2 == -1), false
}

func (ipr *IPAddressRange) GetAfi() uint8 {
	if ipr.Min.To4() != nil {
		return 1
	} else if ipr.Min.To16() != nil {
		return 2
	}
	return 0
}

func (ipr *IPAddressRange) GetRange() (net.IP, net.IP, bool) {
	return ipr.Min, ipr.Max, false
}

type IPAddressNull struct {
	Family uint8
}

func (ipan *IPAddressNull) String() string {
	return fmt.Sprintf("Null IP %v", ipan.Family)
}

func (ipan *IPAddressNull) IsIPInRange(ip net.IP) (bool, bool) {
	if ipan.GetAfi() == 1 && ip.To4() != nil {
		return false, true
	} else if ipan.GetAfi() == 2 && ip.To4() == nil && ip.To16() != nil {
		return false, true
	}
	return false, false
}

func (ipan *IPAddressNull) GetAfi() uint8 {
	return ipan.Family
}

func (ipan *IPAddressNull) GetRange() (net.IP, net.IP, bool) {
	return nil, nil, true
}

type IPCertificateInformation interface {
	GetRange() (net.IP, net.IP, bool)
	IsIPInRange(net.IP) (bool, bool)
	String() string
	GetAfi() uint8
}

type ASNCertificateInformation interface {
	GetRange() (int, int, bool)
	IsASNInRange(int) (bool, bool)
	String() string
}

type ASNRange struct {
	Min int
	Max int
}

func (ar *ASNRange) String() string {
	return fmt.Sprintf("Min: %v max: %v", ar.Min, ar.Max)
}

func (ar *ASNRange) IsASNInRange(asn int) (bool, bool) {
	return asn >= ar.Min && asn <= ar.Max, false
}

func (ar *ASNRange) GetRange() (int, int, bool) {
	return ar.Min, ar.Max, false
}

type ASN struct {
	ASN int
}

func (a *ASN) String() string {
	return fmt.Sprintf("%v", a.ASN)
}

func (a *ASN) IsASNInRange(asn int) (bool, bool) {
	return asn == a.ASN, false
}

func (a *ASN) GetRange() (int, int, bool) {
	return a.ASN, a.ASN, false
}

type ASNull struct {
}

func (an *ASNull) String() string {
	return "Null ASN"
}

func (an *ASNull) IsASNInRange(asn int) (bool, bool) {
	return false, true
}

func (an *ASNull) GetRange() (int, int, bool) {
	return 0, 0, true
}

func DecodeIP(addrfamily []byte, addr asn1.BitString) (*net.IPNet, error) {
	if len(addrfamily) >= 2 && (addrfamily[1] == 1 || addrfamily[1] == 2) {
		size := 4
		if addrfamily[1] == 2 {
			size = 16
		}
		ipaddr := make([]byte, size)
		copy(ipaddr, addr.Bytes)
		mask := net.CIDRMask(addr.BitLength, size*8)

		return &net.IPNet{
			IP:   net.IP(ipaddr),
			Mask: mask,
		}, nil
	} else {
		return nil, errors.New("Not an IP address")
	}
}

func DecodeIPMinMax(addrfamily []byte, addr asn1.BitString, max bool) (net.IP, error) {
	if len(addrfamily) >= 2 && (addrfamily[1] == 1 || addrfamily[1] == 2) {
		size := 4
		if addrfamily[1] == 2 {
			size = 16
		}
		ipaddr := make([]byte, size)
		copy(ipaddr, addr.Bytes)
		if max {
			for i := addr.BitLength/8 + 1; i < len(ipaddr); i++ {
				ipaddr[i] = 0xFF
			}
			if addr.BitLength/8 > len(ipaddr) {
				return nil, errors.New(fmt.Sprintf("Error converting ip address %v %v", addr.BitLength, len(ipaddr)))
			}
			if addr.BitLength/8 < len(ipaddr) {
				ipaddr[addr.BitLength/8] |= 0xFF >> uint(8-(8*(addr.BitLength/8+1)-addr.BitLength))
			}
		}
		return net.IP(ipaddr), nil
	} else {
		return nil, errors.New("Not an IP address")
	}
}

func DecodeIPAddressBlock(data []byte) ([]IPCertificateInformation, error) {
	type IPAddressFamily struct {
		AddressFamily   []byte
		IPAddressChoice asn1.RawValue
	}
	var blk []IPAddressFamily
	ipaddresses := make([]IPCertificateInformation, 0)

	_, err := asn1.Unmarshal(data, &blk)
	if err != nil {
		return ipaddresses, err
	}

	for _, ipaddrfam := range blk {
		if ipaddrfam.IPAddressChoice.Tag == asn1.TagNull {
			var family uint8
			if len(ipaddrfam.AddressFamily) == 2 && ipaddrfam.AddressFamily[1] == 1 {
				family = 1
			}
			if len(ipaddrfam.AddressFamily) == 2 && ipaddrfam.AddressFamily[1] == 2 {
				family = 2
			}
			ipaddresses = append(ipaddresses, &IPAddressNull{Family: family})
		} else if ipaddrfam.IPAddressChoice.Tag == asn1.TagSequence {
			var ipaddrranges []asn1.RawValue
			_, err = asn1.Unmarshal(ipaddrfam.IPAddressChoice.FullBytes, &ipaddrranges)
			if err != nil {
				return ipaddresses, err
			}

			for _, ipaddrrange := range ipaddrranges {
				if ipaddrrange.Tag == asn1.TagBitString {
					var addrRange asn1.BitString
					_, err := asn1.Unmarshal(ipaddrrange.FullBytes, &addrRange)
					if err != nil {
						return ipaddresses, err
					}

					a, _ := DecodeIP(ipaddrfam.AddressFamily, addrRange)
					ipaddresses = append(ipaddresses, &IPNet{
						IPNet: a,
					})
				} else if ipaddrrange.Tag == asn1.TagSequence {
					type AddrRange struct {
						Min asn1.BitString
						Max asn1.BitString
					}

					var addrRange AddrRange
					_, err := asn1.Unmarshal(ipaddrrange.FullBytes, &addrRange)
					if err != nil {
						return ipaddresses, err
					}

					a, _ := DecodeIPMinMax(ipaddrfam.AddressFamily, addrRange.Min, false)
					b, err := DecodeIPMinMax(ipaddrfam.AddressFamily, addrRange.Max, true)
					ipaddresses = append(ipaddresses, &IPAddressRange{
						Min: a,
						Max: b,
					})
				}
			}
		}
	}
	return ipaddresses, nil
}

func DecodeASIdentifier(data asn1.RawValue) ([]ASNCertificateInformation, error) {
	var asitmp asn1.RawValue
	asns := make([]ASNCertificateInformation, 0)

	_, err := asn1.Unmarshal(data.Bytes, &asitmp)
	if err != nil {
		return asns, err
	}

	if asitmp.Tag == asn1.TagNull {
		asns = append(asns, &ASNull{})
	} else if asitmp.Tag == asn1.TagSequence {
		var asidors []asn1.RawValue

		_, err := asn1.Unmarshal(data.Bytes, &asidors)
		if err != nil {
			return asns, err
		}

		for _, asidor := range asidors {
			if asidor.Tag == asn1.TagSequence {
				var asrange ASNRange
				_, err := asn1.Unmarshal(asidor.FullBytes, &asrange)
				if err != nil {
					return asns, err
				}
				asns = append(asns, &asrange)
			} else if asidor.Tag == asn1.TagInteger {
				var asid int
				_, err := asn1.Unmarshal(asidor.FullBytes, &asid)
				if err != nil {
					return asns, err
				}
				asns = append(asns, &ASN{ASN: asid})
			}

		}
	}
	return asns, nil
}

func DecodeASN(data []byte) ([]ASNCertificateInformation, []ASNCertificateInformation, error) {
	type ASIdentifiers struct {
		ASNum asn1.RawValue `asn1:"tag:0,optional"`
		RDI   asn1.RawValue `asn1:"tag:1,optional"`
	}
	var asi ASIdentifiers
	asnsnum := make([]ASNCertificateInformation, 0)
	asnsrdi := make([]ASNCertificateInformation, 0)
	_, err := asn1.Unmarshal(data, &asi)
	if err != nil {
		return asnsnum, asnsrdi, err
	}
	if asi.ASNum.Class != 0 {
		asnsnum, err = DecodeASIdentifier(asi.ASNum)
		if err != nil {
			return asnsnum, asnsrdi, err
		}
	}
	if asi.RDI.Class != 0 {
		asnsrdi, err = DecodeASIdentifier(asi.RDI)
		if err != nil {
			return asnsnum, asnsrdi, err
		}
	}
	return asnsnum, asnsrdi, nil
}

type RPKI_Certificate struct {
	SubjectInformationAccess []SIA
	IPAddresses              []IPCertificateInformation
	ASNums                   []ASNCertificateInformation
	ASNRDI                   []ASNCertificateInformation

	Certificate *x509.Certificate

	//SubjectKeyIdentifier []byte // Replace by certificate content
	//AuthorityKeyIdentifier []byte
}

func (cert *RPKI_Certificate) IsIPRangeInCertificate(min net.IP, max net.IP) (bool, bool) {
	for _, ip := range cert.IPAddresses {
		minIn, checkParentMin := ip.IsIPInRange(min)
		maxIn, checkParentMax := ip.IsIPInRange(max)

		if minIn && maxIn {
			return true, false
		}
		if checkParentMin || checkParentMax {
			return false, true
		}
	}
	return false, false
}

func (cert *RPKI_Certificate) IsASRangeInCertificate(min int, max int) (bool, bool) {
	for _, asn := range cert.ASNums {
		minIn, checkParentMin := asn.IsASNInRange(min)
		maxIn, checkParentMax := asn.IsASNInRange(max)
		if minIn && maxIn {
			return true, false
		}
		if checkParentMin || checkParentMax {
			return false, true
		}
	}
	return false, false
}

// https://tools.ietf.org/html/rfc6487#section-7.2
func ValidateIPCertificateList(list []IPCertificateInformation, parent *RPKI_Certificate) ([]IPCertificateInformation, []IPCertificateInformation, []IPCertificateInformation) {
	valids := make([]IPCertificateInformation, 0)
	invalids := make([]IPCertificateInformation, 0)
	checkParents := make([]IPCertificateInformation, 0)
	for _, ip := range list {
		min, max, checkParent := ip.GetRange()
		if checkParent {
			valids = append(valids, ip)
			continue
		}
		valid, checkParent := parent.IsIPRangeInCertificate(min, max)
		if valid {
			valids = append(valids, ip)
		} else if checkParent {
			checkParents = append(checkParents, ip)
		} else {
			invalids = append(invalids, ip)
		}
	}
	return valids, invalids, checkParents
}

func (cert *RPKI_Certificate) ValidateIPCertificate(parent *RPKI_Certificate) ([]IPCertificateInformation, []IPCertificateInformation, []IPCertificateInformation) {
	return ValidateIPCertificateList(cert.IPAddresses, parent)
}

func ValidateASNCertificateList(list []ASNCertificateInformation, parent *RPKI_Certificate) ([]ASNCertificateInformation, []ASNCertificateInformation, []ASNCertificateInformation) {
	valids := make([]ASNCertificateInformation, 0)
	invalids := make([]ASNCertificateInformation, 0)
	checkParents := make([]ASNCertificateInformation, 0)
	for _, asn := range list {
		min, max, checkParent := asn.GetRange()
		if checkParent {
			valids = append(valids, asn)
			continue
		}
		valid, checkParent := parent.IsASRangeInCertificate(min, max)
		if valid {
			valids = append(valids, asn)
		} else if checkParent {
			checkParents = append(checkParents, asn)
		} else {
			invalids = append(invalids, asn)
		}
	}
	return valids, invalids, checkParents
}

func (cert *RPKI_Certificate) ValidateASNCertificate(parent *RPKI_Certificate) ([]ASNCertificateInformation, []ASNCertificateInformation, []ASNCertificateInformation) {
	return ValidateASNCertificateList(cert.ASNums, parent)
}

func (cert *RPKI_Certificate) Validate(parent *RPKI_Certificate) error {
	if cert.Certificate == nil {
		return errors.New("No certificate found")
	}
	if parent.Certificate == nil {
		return errors.New("No certificate found in parent")
	}
	err := cert.Certificate.CheckSignatureFrom(parent.Certificate)
	if err != nil {
		return err
	}
	return nil
}

func (cert *RPKI_Certificate) ValidateTime(comp time.Time) error {
	if cert.Certificate == nil {
		return errors.New("No certificate found")
	}
	if cert.Certificate.NotBefore.After(comp) {
		return errors.New(fmt.Sprintf("Certificate beginning of validity: %v is after: %v", cert.Certificate.NotBefore, comp))
	}
	if comp.After(cert.Certificate.NotAfter) {
		return errors.New(fmt.Sprintf("Certificate end of validity: %v is before: %v", cert.Certificate.NotBefore, comp))
	}
	return nil
}

func (cert *RPKI_Certificate) String() string {
	s := "RPKI Certificate: "

	s += fmt.Sprintf("KeyIdentifier: %v / Emitter: %v",
		hex.EncodeToString(cert.Certificate.SubjectKeyId),
		hex.EncodeToString(cert.Certificate.AuthorityKeyId))

	sias := ""
	for _, i := range cert.SubjectInformationAccess {
		sias += fmt.Sprintf("%v, ", i.String())
	}
	s += fmt.Sprintf(" SIA: [ %v]", sias)

	ipaddresses := ""
	for _, i := range cert.IPAddresses {
		ipaddresses += fmt.Sprintf("%v, ", i.String())
	}
	s += fmt.Sprintf(" IP Addresses: [ %v]", ipaddresses)

	asns := ""
	for _, i := range cert.ASNums {
		asns += fmt.Sprintf("%v, ", i.String())
	}
	s += fmt.Sprintf(" ASNs: [ %v]", asns)

	asns = ""
	for _, i := range cert.ASNums {
		asns += fmt.Sprintf("%v, ", i.String())
	}
	s += fmt.Sprintf(" ASNs RDI: [ %v]", asns)
	return s
}

type SIA struct {
	AccessMethod asn1.ObjectIdentifier
	GeneralName  []byte `asn1:"tag:6"`
}

func (sia *SIA) String() string {
	return fmt.Sprintf("SIA %v %v", sia.AccessMethod, string(sia.GeneralName))
}

func DecodeSubjectInformationAccess(data []byte) ([]SIA, error) {
	var sias []SIA
	_, err := asn1.Unmarshal(data, &sias)
	if err != nil {
		return sias, err
	}
	return sias, nil
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
func DecodeKeyAuthority(data []byte) ([]byte, error) {
	type KeyAuthority struct {
		Key []byte `asn1:"tag:0"`
	}
	var key KeyAuthority
	_, err := asn1.Unmarshal(data, &key)
	if err != nil {
		return key.Key, err
	}
	return key.Key, nil
}

func DecodeKeyIdentifier(data []byte) ([]byte, error) {
	var key []byte
	_, err := asn1.Unmarshal(data, &key)
	if err != nil {
		return key, err
	}
	return key, nil
}

func DecodeCertificate(data []byte) (*RPKI_Certificate, error) {
	cert, err := x509.ParseCertificate(data)

	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	rpki_cert := RPKI_Certificate{
		Certificate: cert,
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(IpAddrBlock) {
			addresses, err := DecodeIPAddressBlock(extension.Value)
			rpki_cert.IPAddresses = addresses
			if err != nil {
				return &rpki_cert, err
			}
		} else if extension.Id.Equal(AutonomousSysIds) {
			asnsnum, asnsrdi, err := DecodeASN(extension.Value)
			rpki_cert.ASNums = asnsnum
			rpki_cert.ASNRDI = asnsrdi
			if err != nil {
				return &rpki_cert, err
			}
		} else if extension.Id.Equal(SubjectInfoAccess) {
			sias, err := DecodeSubjectInformationAccess(extension.Value)
			rpki_cert.SubjectInformationAccess = sias
			if err != nil {
				return &rpki_cert, err
			}
		}
	}

	return &rpki_cert, nil
}
