package librpki

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"
)

var (
	RoaOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 24}
)

type ROAIPAddresses struct {
	Address   asn1.BitString
	MaxLength int `asn1:"optional,default:-1"`
}

type ROAAddressFamily struct {
	AddressFamily []byte
	Addresses     []ROAIPAddresses
}

type ROAContent struct {
	ASID         int
	IpAddrBlocks []ROAAddressFamily
}

type ROA struct {
	OID      asn1.ObjectIdentifier
	EContent asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type ROAEntry struct {
	IPNet     *net.IPNet
	MaxLength int
}

type RPKIROA struct {
	ASN         int
	Entries     []*ROAEntry
	Certificate *RPKICertificate
	BadFormat   bool
	SigningTime time.Time

	InnerValid         bool
	InnerValidityError error

	Valids      []*ROAEntry
	Invalids    []*ROAEntry
	CheckParent []*ROAEntry
}

func ROAToEncap(roa *ROA) ([]byte, error) {
	return EContentToEncap(roa.EContent.FullBytes)
}

func GroupEntries(entries []*ROAEntry) map[byte][]*ROAEntry {
	mapIps := make(map[byte][]*ROAEntry)
	for _, entry := range entries {
		afi := byte(2)
		if entry.IPNet.IP.To4() != nil {
			afi = 1
		}

		ipsList, ok := mapIps[afi]
		if !ok {
			ipsList = make([]*ROAEntry, 0)
		}
		ipsList = append(ipsList, entry)

		mapIps[afi] = ipsList
	}
	return mapIps
}

func EncodeROAEntries(asn int, entries []*ROAEntry) (*ROA, error) {
	groups := GroupEntries(entries)

	versionList := make([]int, 0)
	for version, _ := range groups {
		versionList = append(versionList, int(version))
	}
	sort.Ints(versionList)

	roaFam := make([]ROAAddressFamily, 0)
	for _, cversion := range versionList {
		version := byte(cversion)

		listAddresses := make([]ROAIPAddresses, 0)
		for _, v := range groups[version] {
			ipnetbs := IPNetToBitString(*v.IPNet)
			listAddresses = append(listAddresses, ROAIPAddresses{
				Address:   ipnetbs,
				MaxLength: v.MaxLength,
			})
		}

		roa := ROAAddressFamily{
			AddressFamily: []byte{0, version},
			Addresses:     listAddresses,
		}
		roaFam = append(roaFam, roa)
	}

	eContent := ROAContent{
		ASID:         asn,
		IpAddrBlocks: roaFam,
	}
	eContentEnc, err := asn1.Marshal(eContent)
	if err != nil {
		return nil, err
	}

	// Present in ARIN ROAs
	/*
		eContentEnc, err = asn1.Marshal(eContentEnc)
		if err != nil {
			return nil, err
		}*/

	eContentEnc, err = asn1.MarshalWithParams(eContentEnc, "tag:0,explicit")
	if err != nil {
		return nil, err
	}

	roa := &ROA{
		OID:      RoaOID,
		EContent: asn1.RawValue{FullBytes: eContentEnc},
	}
	return roa, nil
}

func GetRangeIP(ipnet *net.IPNet) (error, net.IP, net.IP) {
	ip := ipnet.IP
	mask := ipnet.Mask

	beginIP := make([]byte, len(ip))
	endIP := make([]byte, len(ip))
	for i := range []byte(ip) {
		// GHSA-w6ww-fmfx-2x22: Prevent oob read
		if i >= len(mask) {
			return errors.New("Invalid IP address mask"), nil, nil
		}
		beginIP[i] = ip[i] & mask[i]
		endIP[i] = ip[i] | ^mask[i]
	}
	return nil, net.IP(beginIP), net.IP(endIP)
}

// https://tools.ietf.org/html/rfc6480#section-2.3
// https://tools.ietf.org/html/rfc6482#section-4

func (entry *ROAEntry) Validate() error {
	s, _ := entry.IPNet.Mask.Size()
	if entry.MaxLength < s {
		return errors.New(fmt.Sprintf("Max length (%v) is smaller than prefix length (%v)", entry.MaxLength, s))
	}

	if entry.MaxLength < 0 {
		return fmt.Errorf("max length (%d) is less than 0", entry.MaxLength)
	}

	if entry.IPNet.IP.To4() != nil && entry.MaxLength > 32 { // If IPv4
		return fmt.Errorf("max length (%d) too small for IPv4 prefix", entry.MaxLength)
	} else if entry.MaxLength > 128 { // If IPv6
		return fmt.Errorf("max length (%d) too small for IPv6 prefix", entry.MaxLength)
	}

	return nil
}

func (roa *RPKIROA) ValidateTime(comp time.Time) error {
	err := roa.Certificate.ValidateTime(comp)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to expiration date: %v", err))
	}
	return nil
}

func (roa *RPKIROA) ValidateEntries() error {
	for _, entry := range roa.Entries {
		err := entry.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidateIPRoaCertificateList(entries []*ROAEntry, cert *RPKICertificate) ([]*ROAEntry, []*ROAEntry, []*ROAEntry) {
	valids := make([]*ROAEntry, 0)
	invalids := make([]*ROAEntry, 0)
	checkParents := make([]*ROAEntry, 0)
	for _, entry := range entries {
		err, min, max := GetRangeIP(entry.IPNet)
		if err != nil {
			invalids = append(invalids, entry)
		}
		valid, checkParent := cert.IsIPRangeInCertificate(min, max)
		if valid {
			valids = append(valids, entry)
		} else if checkParent {
			checkParents = append(checkParents, entry)
		} else {
			invalids = append(invalids, entry)
		}
	}
	return valids, invalids, checkParents
}

func (roa *RPKIROA) ValidateIPRoaCertificate(cert *RPKICertificate) ([]*ROAEntry, []*ROAEntry, []*ROAEntry) {
	return ValidateIPRoaCertificateList(roa.Entries, cert)
}

func ConvertROAEntries(roacontent ROAContent) ([]*ROAEntry, int, error) {
	entries := make([]*ROAEntry, 0)
	asn := roacontent.ASID
	//fmt.Printf("ROAContent %v %v AS: %v\n", len(fullbytes), err, roacontent.ASID)
	for _, addrblock := range roacontent.IpAddrBlocks {
		for _, addr := range addrblock.Addresses {
			ip, err := DecodeIP(addrblock.AddressFamily, addr.Address)
			if err != nil {
				return entries, asn, err
			}

			maxlength := addr.MaxLength
			if maxlength < 0 {
				maxlength, _ = ip.Mask.Size()
			}
			//fmt.Printf(" - %v %v\n", ip, err)
			re := &ROAEntry{
				IPNet:     ip,
				MaxLength: maxlength,
			}
			entries = append(entries, re)
		}
	}
	return entries, asn, nil
}

type DecoderConfig struct {
	ValidateStrict bool
}

var (
	DefaultDecoderConfig = &DecoderConfig{
		ValidateStrict: true,
	}
)

func DecodeROA(data []byte) (*RPKIROA, error) {
	return DefaultDecoderConfig.DecodeROA(data)
}

func (cf *DecoderConfig) DecodeROA(data []byte) (*RPKIROA, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
	}

	if cf.ValidateStrict {
		vs, err := c.CheckSignaturesMatch()
		if err != nil {
			return nil, err
		}
		if !vs {
			return nil, errors.New("CMS is not valid due to strict signature matching")
		}
	}

	var rawroa ROA
	_, err = asn1.Unmarshal(c.SignedData.EncapContentInfo.FullBytes, &rawroa)

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(rawroa.EContent.Bytes, &inner)
	if err != nil {
		return nil, err
	}
	fullbytes, badformat, err := BadFormatGroup(inner.Bytes)
	if err != nil {
		return nil, err
	}

	var roacontent ROAContent
	_, err = asn1.Unmarshal(fullbytes, &roacontent)
	if err != nil {
		return nil, err
	}

	entries, asn, err := ConvertROAEntries(roacontent)
	if err != nil {
		return nil, err
	}
	// Check for the correct Max Length

	rpkiROA := RPKIROA{
		BadFormat: badformat,
		Entries:   entries,
		ASN:       asn,
	}

	rpkiROA.SigningTime, _ = c.GetSigningTime()

	cert, err := c.GetRPKICertificate()
	if err != nil {
		return &rpkiROA, err
	}
	rpkiROA.Certificate = cert

	// Validate the content of the CMS
	err = c.Validate(fullbytes, cert.Certificate)
	if err != nil {
		rpkiROA.InnerValidityError = err
	} else {
		rpkiROA.InnerValid = true
	}

	// Validates the actual IP addresses
	validEntries, invalidEntries, checkParentEntries := rpkiROA.ValidateIPRoaCertificate(cert)
	rpkiROA.Valids = validEntries
	rpkiROA.Invalids = invalidEntries
	rpkiROA.CheckParent = checkParentEntries

	return &rpkiROA, nil
}
