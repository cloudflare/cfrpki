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

type ROA_Entry struct {
	IPNet     *net.IPNet
	MaxLength int
}

type RPKI_ROA struct {
	ASN         int
	Entries     []*ROA_Entry
	Certificate *RPKI_Certificate
	BadFormat   bool
	SigningTime time.Time

	InnerValid         bool
	InnerValidityError error

	Valids      []*ROA_Entry
	Invalids    []*ROA_Entry
	CheckParent []*ROA_Entry
}

func ROAToEncap(roa *ROA) ([]byte, error) {
	return EContentToEncap(roa.EContent.FullBytes)
}

func GroupEntries(entries []*ROA_Entry) map[byte][]*ROA_Entry {
	mapIps := make(map[byte][]*ROA_Entry)
	for _, entry := range entries {
		afi := byte(2)
		if entry.IPNet.IP.To4() != nil {
			afi = 1
		}

		ipsList, ok := mapIps[afi]
		if !ok {
			ipsList = make([]*ROA_Entry, 0)
		}
		ipsList = append(ipsList, entry)

		mapIps[afi] = ipsList
	}
	return mapIps
}

func EncodeROAEntries(asn int, entries []*ROA_Entry) (*ROA, error) {
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

func GetRangeIP(ipnet *net.IPNet) (net.IP, net.IP) {
	ip := ipnet.IP
	mask := ipnet.Mask

	begin_ip := make([]byte, len(ip))
	end_ip := make([]byte, len(ip))
	for i := range []byte(ip) {
		begin_ip[i] = ip[i] & mask[i]
		end_ip[i] = ip[i] | ^mask[i]
	}
	return net.IP(begin_ip), net.IP(end_ip)
}

// https://tools.ietf.org/html/rfc6480#section-2.3
// https://tools.ietf.org/html/rfc6482#section-4

func (entry *ROA_Entry) Validate() error {
	s, _ := entry.IPNet.Mask.Size()
	if entry.MaxLength < s {
		return errors.New(fmt.Sprintf("Max length (%v) is smaller than prefix length (%v)", entry.MaxLength, s))
	}
	return nil
}

func (roa *RPKI_ROA) ValidateTime(comp time.Time) error {
	err := roa.Certificate.ValidateTime(comp)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to expiration date: %v", err))
	}
	return nil
}

func (roa *RPKI_ROA) ValidateEntries() error {
	for _, entry := range roa.Entries {
		err := entry.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidateIPRoaCertificateList(entries []*ROA_Entry, cert *RPKI_Certificate) ([]*ROA_Entry, []*ROA_Entry, []*ROA_Entry) {
	valids := make([]*ROA_Entry, 0)
	invalids := make([]*ROA_Entry, 0)
	checkParents := make([]*ROA_Entry, 0)
	for _, entry := range entries {
		min, max := GetRangeIP(entry.IPNet)
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

func (roa *RPKI_ROA) ValidateIPRoaCertificate(cert *RPKI_Certificate) ([]*ROA_Entry, []*ROA_Entry, []*ROA_Entry) {
	return ValidateIPRoaCertificateList(roa.Entries, cert)
}

func ConvertROAEntries(roacontent ROAContent) ([]*ROA_Entry, int, error) {
	entries := make([]*ROA_Entry, 0)
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
			re := &ROA_Entry{
				IPNet:     ip,
				MaxLength: maxlength,
			}
			entries = append(entries, re)
		}
	}
	return entries, asn, nil
}

func DecodeROA(data []byte) (*RPKI_ROA, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
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

	rpki_roa := RPKI_ROA{
		BadFormat: badformat,
		Entries:   entries,
		ASN:       asn,
	}

	rpki_roa.SigningTime, _ = c.GetSigningTime()

	cert, err := c.GetRPKICertificate()
	if err != nil {
		return &rpki_roa, err
	}
	rpki_roa.Certificate = cert

	// Validate the content of the CMS
	err = c.Validate(fullbytes, cert.Certificate)
	if err != nil {
		rpki_roa.InnerValidityError = err
	} else {
		rpki_roa.InnerValid = true
	}

	// Validates the actual IP addresses
	validEntries, invalidEntries, checkParentEntries := rpki_roa.ValidateIPRoaCertificate(cert)
	rpki_roa.Valids = validEntries
	rpki_roa.Invalids = invalidEntries
	rpki_roa.CheckParent = checkParentEntries

	return &rpki_roa, nil
}
