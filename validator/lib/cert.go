package librpki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
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

	CertPolicy         = asn1.ObjectIdentifier{2, 5, 29, 32}
	ResourceCertPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 14, 2}
	CPS                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}

	SubjectInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	AuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	CAIssuer            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	SignedObject        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 11}

	SubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	AuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}

	CertRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	CertRRDP       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 13}
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
	err, min, max := GetRangeIP(ipn.IPNet)
	if err != nil {
		return nil, nil, false
	}
	return min, max, false
}

func (ipn *IPNet) ASN1() ([]byte, error) {
	return asn1.Marshal(IPNetToBitString(*ipn.IPNet))
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

func IPToBitString(ip net.IP) asn1.BitString {
	blen := 32
	bitsplit := 12
	if ip.To4() == nil {
		blen = 128
		bitsplit = 0
	}
	return asn1.BitString{
		Bytes:     []byte(ip)[bitsplit:],
		BitLength: blen,
	}
}

func IPNetToBitString(ipnet net.IPNet) asn1.BitString {
	size, _ := ipnet.Mask.Size()
	sizeBytes := size / 8
	if size%8 > 0 {
		sizeBytes++
	}
	prefixBytes := make([]byte, sizeBytes)
	for i := 0; i < len(ipnet.IP) && i < sizeBytes; i++ {
		prefixBytes[i] = ipnet.IP[i] & ipnet.Mask[i]
	}

	return asn1.BitString{
		Bytes:     prefixBytes,
		BitLength: size,
	}
}

func (ipr *IPAddressRange) ASN1() ([]byte, error) {
	return asn1.Marshal([]asn1.BitString{IPToBitString(ipr.Min), IPToBitString(ipr.Max)})
}

// Add IP address type (just bit string)

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

func (ipan *IPAddressNull) ASN1() ([]byte, error) {
	return asn1.Marshal(asn1.NullRawValue)
}

type IPCertificateInformation interface {
	GetRange() (net.IP, net.IP, bool)
	IsIPInRange(net.IP) (bool, bool)
	String() string
	GetAfi() uint8

	ASN1() ([]byte, error)
}

type ASNCertificateInformation interface {
	GetRange() (int, int, bool)
	IsASNInRange(int) (bool, bool)
	String() string

	ASN1() ([]byte, error)
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

func (ar *ASNRange) ASN1() ([]byte, error) {
	return asn1.Marshal([]int{ar.Min, ar.Max})
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

func (a *ASN) ASN1() ([]byte, error) {
	return asn1.Marshal(a.ASN)
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

func (an *ASNull) ASN1() ([]byte, error) {
	return asn1.Marshal(asn1.NullRawValue)
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

type RPKICertificate struct {
	SubjectInformationAccess []SIA
	IPAddresses              []IPCertificateInformation
	ASNums                   []ASNCertificateInformation
	ASNRDI                   []ASNCertificateInformation

	Certificate *x509.Certificate

	//SubjectKeyIdentifier []byte // Replace by certificate content
	//AuthorityKeyIdentifier []byte
}

func (cert *RPKICertificate) IsIPRangeInCertificate(min net.IP, max net.IP) (bool, bool) {
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

func (cert *RPKICertificate) IsASRangeInCertificate(min int, max int) (bool, bool) {
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
func ValidateIPCertificateList(list []IPCertificateInformation, parent *RPKICertificate) ([]IPCertificateInformation, []IPCertificateInformation, []IPCertificateInformation) {
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

func (cert *RPKICertificate) ValidateIPCertificate(parent *RPKICertificate) ([]IPCertificateInformation, []IPCertificateInformation, []IPCertificateInformation) {
	return ValidateIPCertificateList(cert.IPAddresses, parent)
}

func ValidateASNCertificateList(list []ASNCertificateInformation, parent *RPKICertificate) ([]ASNCertificateInformation, []ASNCertificateInformation, []ASNCertificateInformation) {
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

func (cert *RPKICertificate) ValidateASNCertificate(parent *RPKICertificate) ([]ASNCertificateInformation, []ASNCertificateInformation, []ASNCertificateInformation) {
	return ValidateASNCertificateList(cert.ASNums, parent)
}

func (cert *RPKICertificate) Validate(parent *RPKICertificate) error {
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

func (cert *RPKICertificate) ValidateTime(comp time.Time) error {
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

func (cert *RPKICertificate) String() string {
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

// Put in ExtraExtensions
// https://tools.ietf.org/html/rfc3779
func GroupIPAddressBlock(ips []IPCertificateInformation) map[byte][]IPCertificateInformation {
	mapIps := make(map[byte][]IPCertificateInformation)
	for _, ip := range ips {
		afi := ip.GetAfi()
		ipsList, ok := mapIps[afi]
		if !ok {
			ipsList = make([]IPCertificateInformation, 0)
		}
		ipsList = append(ipsList, ip)

		mapIps[afi] = ipsList
	}
	return mapIps
}

func EncodeInfoAccess(authority bool, path string) (*pkix.Extension, error) {
	type SubStruct struct {
		OID  asn1.ObjectIdentifier
		Path string `asn1:"implicit,tag:6"`
	}

	oid1 := SubjectInfoAccess
	oid2 := SignedObject
	if authority {
		oid1 = AuthorityInfoAccess
		oid2 = CAIssuer
	}

	substruct := SubStruct{
		OID:  oid2,
		Path: path,
	}

	iasBytes, err := asn1.Marshal([]interface{}{substruct})
	if err != nil {
		return nil, err
	}
	ext := &pkix.Extension{
		Id:    oid1,
		Value: iasBytes,
	}
	return ext, nil
}

// https://tools.ietf.org/html/rfc7318
func EncodePolicyInformation(cps string) (*pkix.Extension, error) {
	type CertificatePolicy struct {
		OID    asn1.ObjectIdentifier
		Policy []interface{}
	}
	type CPSStruct struct {
		OID asn1.ObjectIdentifier
		CPS string `asn1:"ia5"`
	}
	certPolicy := CertificatePolicy{
		OID: ResourceCertPolicy,
	}
	if cps != "" {
		cpss := CPSStruct{
			OID: CPS,
			CPS: cps,
		}

		certPolicy.Policy = []interface{}{
			cpss,
		}
	}

	policyGroupBytes, err := asn1.Marshal([]CertificatePolicy{certPolicy})
	if err != nil {
		return nil, err
	}
	ext := &pkix.Extension{
		Id:       CertPolicy,
		Critical: true,
		Value:    policyGroupBytes,
	}
	return ext, nil
}

func EncodeIPAddressBlock(ips []IPCertificateInformation) (*pkix.Extension, error) {
	groups := GroupIPAddressBlock(ips)

	versionList := make([]int, 0)
	for version, _ := range groups {
		versionList = append(versionList, int(version))
	}
	sort.Ints(versionList)

	groupAsn1 := make([]asn1.RawValue, 0)
	for _, cversion := range versionList {
		version := byte(cversion)
		ipBytes, err := EncodeIPAddressBlockVersion(version, groups[version], 0, false)
		if err != nil {
			return nil, err
		}
		groupAsn1 = append(groupAsn1, asn1.RawValue{FullBytes: ipBytes})
	}

	ipGroupBytes, err := asn1.Marshal(groupAsn1)
	if err != nil {
		return nil, err
	}
	ext := &pkix.Extension{
		Id:       IpAddrBlock,
		Critical: true,
		Value:    ipGroupBytes,
	}
	return ext, nil
}

func EncodeIPAddressBlockVersion(version byte, ips []IPCertificateInformation, safi byte, addSafi bool) ([]byte, error) {
	type Ip struct {
		Version []byte
		Ips     []asn1.RawValue
	}
	type IpNull struct {
		Version []byte
		Ips     asn1.RawValue
	}

	ver := []byte{0, version}
	if addSafi {
		ver = append(ver, safi)
	}

	ipSeq := Ip{
		Version: ver,
		Ips:     make([]asn1.RawValue, 0),
	}
	for _, ip := range ips {
		ipBytes, err := ip.ASN1()
		if err != nil {
			return nil, err
		}

		switch ip.(type) {
		case *IPAddressNull:
			return asn1.Marshal(IpNull{
				Version: ver,
				Ips:     asn1.RawValue{FullBytes: ipBytes},
			})
		}

		ipSeq.Ips = append(ipSeq.Ips, asn1.RawValue{FullBytes: ipBytes})
	}

	return asn1.Marshal(ipSeq)
}

// https://tools.ietf.org/html/rfc6487
func EncodeASNSeq(asns []ASNCertificateInformation) ([]asn1.RawValue, error) {
	if len(asns) == 0 {
		return nil, nil
	}

	asnSeq := make([]asn1.RawValue, 0)
	for _, asn := range asns {
		asnBytes, err := asn.ASN1()
		if err != nil {
			return nil, err
		}
		asnStruct := asn1.RawValue{
			FullBytes: asnBytes,
		}
		asnSeq = append(asnSeq, asnStruct)

		switch asn.(type) {
		case *ASNull:
			return asnSeq, nil
		}
	}

	m, err := asn1.Marshal(asnSeq)
	if err != nil {
		return nil, err
	}

	return []asn1.RawValue{asn1.RawValue{FullBytes: m}}, nil
}

func EncodeASN(nums []ASNCertificateInformation, rdi []ASNCertificateInformation) (*pkix.Extension, error) {
	asnSeq, err := EncodeASNSeq(nums)
	if err != nil {
		return nil, err
	}
	rdiSeq, err := EncodeASNSeq(rdi)
	if err != nil {
		return nil, err
	}

	type AsnStruct struct {
		ASN []asn1.RawValue `asn1:"tag:0,omitempty"`
		RDI []asn1.RawValue `asn1:"tag:1,omitempty"`
	}
	asnTotalStruct := AsnStruct{
		ASN: asnSeq,
		RDI: rdiSeq,
	}

	asnSeqBytes, err := asn1.Marshal(asnTotalStruct)
	if err != nil {
		return nil, err
	}

	ext := &pkix.Extension{
		Id:       AutonomousSysIds,
		Critical: true,
		Value:    asnSeqBytes,
	}
	return ext, nil
}

func EncodeSIA(sias []*SIA) (*pkix.Extension, error) {
	siaSeq := make([]asn1.RawValue, 0)
	for _, sia := range sias {
		siaBytes, err := asn1.Marshal(*sia)
		if err != nil {
			return nil, err
		}
		siaStruct := asn1.RawValue{
			FullBytes: siaBytes,
		}
		siaSeq = append(siaSeq, siaStruct)
	}

	siaSeqBytes, err := asn1.Marshal(siaSeq)
	if err != nil {
		return nil, err
	}

	ext := &pkix.Extension{
		Id:    SubjectInfoAccess,
		Value: siaSeqBytes,
	}
	return ext, nil
}

func DecodeCertificate(data []byte) (*RPKICertificate, error) {
	cert, err := x509.ParseCertificate(data)

	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	rpkiCert := RPKICertificate{
		Certificate: cert,
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(IpAddrBlock) {
			addresses, err := DecodeIPAddressBlock(extension.Value)
			rpkiCert.IPAddresses = addresses
			if err != nil {
				return &rpkiCert, err
			}
		} else if extension.Id.Equal(AutonomousSysIds) {
			asnsnum, asnsrdi, err := DecodeASN(extension.Value)
			rpkiCert.ASNums = asnsnum
			rpkiCert.ASNRDI = asnsrdi
			if err != nil {
				return &rpkiCert, err
			}
		} else if extension.Id.Equal(SubjectInfoAccess) {
			sias, err := DecodeSubjectInformationAccess(extension.Value)
			rpkiCert.SubjectInformationAccess = sias
			if err != nil {
				return &rpkiCert, err
			}
		}
	}

	return &rpkiCert, nil
}
