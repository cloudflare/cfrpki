package main

import "github.com/cloudflare/gortr/prefixfile"

func FilterInvalidPrefixLen(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	validROAs := make([]prefixfile.ROAJson, 0)
	for _, roa := range roalist {
		prefix := roa.GetPrefix()
		ones, _ := prefix.Mask.Size()
		if prefix.IP.To4() != nil && ones <= 24 {
			validROAs = append(validROAs, roa)
			continue
		}

		if prefix.IP.To16() != nil && ones <= 48 {
			validROAs = append(validROAs, roa)
		}
	}

	return validROAs
}

func FilterDuplicates(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	roalistNodup := make([]prefixfile.ROAJson, 0)
	existingsROAs := make(map[string]struct{})
	for _, roa := range roalist {
		k := roa.String()
		_, present := existingsROAs[k]
		if !present {
			roalistNodup = append(roalistNodup, roa)
			existingsROAs[k] = struct{}{}
		}
	}

	return roalistNodup
}
