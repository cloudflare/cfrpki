package pki

import (
	"fmt"
	"github.com/cloudflare/cfrpki/validator/lib"
	"strings"
)

const (
	ERROR_CERTIFICATE_VALIDITY = iota
	ERROR_CERTIFICATE_PARENT
	ERROR_CERTIFICATE_REVOCATION
	ERROR_CERTIFICATE_RESOURCE
)

type CertificateError struct {
	EType int

	InnerErr error
	Message  string

	Certificate *librpki.RPKI_Certificate
	Parent      *librpki.RPKI_Certificate

	IPs  []librpki.IPCertificateInformation
	ASNs []librpki.ASNCertificateInformation
}

func (e *CertificateError) Error() string {
	certinfo := "for certificate"
	if e.Certificate != nil {
		ski := e.Certificate.Certificate.SubjectKeyId
		aki := e.Certificate.Certificate.AuthorityKeyId

		certinfo = fmt.Sprintf("for certificate ski:%x aki:%x", ski, aki)
	}

	var err string
	if e.InnerErr != nil {
		err = fmt.Sprintf(": %s", e.InnerErr.Error())
	}

	var ips, asns string
	if len(e.IPs) > 0 {
		toMerge := make([]string, len(e.IPs))
		for i, v := range e.IPs {
			toMerge[i] = v.String()
		}
		merged := strings.Join(toMerge, ", ")
		ips = fmt.Sprintf(" invalid IP resources (%d): [%v]", len(e.IPs), merged)
	}
	if len(e.ASNs) > 0 {
		toMerge := make([]string, len(e.ASNs))
		for i, v := range e.ASNs {
			toMerge[i] = v.String()
		}
		merged := strings.Join(toMerge, ", ")
		asns = fmt.Sprintf(" invalid ASN resources (%d): [%v]", len(e.ASNs), merged)
	}

	return fmt.Sprintf("%s %s%v%s%s", e.Message, certinfo, err, ips, asns)

}

func NewCertificateErrorValidity(cert *librpki.RPKI_Certificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_VALIDITY,
		Certificate: cert,
		InnerErr:    err,
		Message:     "expiration issue",
	}
}

func NewCertificateErrorParent(cert, parent *librpki.RPKI_Certificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_PARENT,
		Certificate: cert,
		Parent:      parent,
		InnerErr:    err,
		Message:     "parent issue",
	}
}

func NewCertificateErrorRevocation(cert *librpki.RPKI_Certificate) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_REVOCATION,
		Certificate: cert,
		Message:     "revocation by issuer",
	}
}

func NewCertificateErrorResource(cert *librpki.RPKI_Certificate, ips []librpki.IPCertificateInformation, asns []librpki.ASNCertificateInformation) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_RESOURCE,
		Certificate: cert,
		Message:     "resource issue",
		IPs:         ips,
		ASNs:        asns,
	}
}
