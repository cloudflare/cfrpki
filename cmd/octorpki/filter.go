package main

import "github.com/cloudflare/gortr/prefixfile"

func FilterInvalidPrefixLen(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	validROAs := make([]prefixfile.ROAJson, 0, len(roalist))
	for _, roa := range roalist {
		prefix := roa.GetPrefix()
		prefixLen, _ := prefix.Mask.Size()
		if prefix.IP.To4() != nil {
			if prefixLen <= 24 {
				validROAs = append(validROAs, roa)
			}

			continue
		}

		if prefixLen <= 48 {
			validROAs = append(validROAs, roa)
		}
	}

	return validROAs
}

func FilterDuplicates(roalist []prefixfile.ROAJson) []prefixfile.ROAJson {
	roalistNodup := make([]prefixfile.ROAJson, 0, len(roalist))
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
