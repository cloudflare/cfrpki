package pki

import (
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/cfrpki/validator/lib"
	"github.com/getsentry/sentry-go"
	"runtime"
	"strings"
)

const (
	ERROR_CERTIFICATE_VALIDITY = iota
	ERROR_CERTIFICATE_PARENT
	ERROR_CERTIFICATE_REVOCATION
	ERROR_CERTIFICATE_RESOURCE
	ERROR_CERTIFICATE_CONFLICT
)

type stack []uintptr
type Frame uintptr

var (
	ErrorTypeToName = map[int]string{
		ERROR_CERTIFICATE_VALIDITY:   "validity",
		ERROR_CERTIFICATE_PARENT:     "parent",
		ERROR_CERTIFICATE_REVOCATION: "revocation",
		ERROR_CERTIFICATE_RESOURCE:   "resource",
		ERROR_CERTIFICATE_CONFLICT:   "conflict",
	}
)

type CertificateError struct {
	EType int

	InnerErr error
	Message  string

	Certificate *librpki.RPKI_Certificate
	Parent      *librpki.RPKI_Certificate

	IPs  []librpki.IPCertificateInformation
	ASNs []librpki.ASNCertificateInformation

	Stack *stack

	File     *PKIFile
	SeekFile *SeekFile
}

func callers() *stack {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	var st stack = pcs[0:n]
	return &st
}

// This function returns the Stacktrace of the error.
// The naming scheme corresponds to what Sentry fetches
// https://github.com/getsentry/sentry-go/blob/master/stacktrace.go#L49
func StackTrace(s *stack) []Frame {
	f := make([]Frame, len(*s))
	for i := 0; i < len(f); i++ {
		f[i] = Frame((*s)[i])
	}
	return f
}

func (e *CertificateError) StackTrace() []Frame {
	return StackTrace(e.Stack)
}

func (e *CertificateError) AddFileErrorInfo(file *PKIFile, seek *SeekFile) {
	e.File = file
	e.SeekFile = seek
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

func (e *CertificateError) SetSentryScope(scope *sentry.Scope) {
	scope.SetTag("Type", ErrorTypeToName[e.EType])

	if e.Certificate != nil {
		ski := e.Certificate.Certificate.SubjectKeyId
		aki := e.Certificate.Certificate.AuthorityKeyId
		scope.SetTag("Certificate.SubjectKeyId", hex.EncodeToString(ski))
		scope.SetTag("Certificate.AuthorityKeyId", hex.EncodeToString(aki))

		scope.SetExtra("Certificate.NotBefore", e.Certificate.Certificate.NotBefore)
		scope.SetExtra("Certificate.NotAfter", e.Certificate.Certificate.NotAfter)
		scope.SetTag("Certificate.SerialNumber", e.Certificate.Certificate.SerialNumber.String())

		// Might be worth to convert into proper strings later
		scope.SetExtra("Certificate.SIAs", e.Certificate.SubjectInformationAccess)
		scope.SetExtra("Certificate.IP", e.Certificate.IPAddresses)
		scope.SetExtra("Certificate.ASN", e.Certificate.ASNums)
		scope.SetExtra("Certificate.ASNRDI", e.Certificate.ASNRDI)
	}
	if e.File != nil {
		scope.SetTag("File.Repository", e.File.Repo)
		scope.SetTag("File.Path", e.File.Path)
		scope.SetTag("File.Type", TypeToName[e.File.Type])
		scope.SetExtra("File.Trust", e.File.Trust)
	}
	if e.SeekFile != nil {
		// disabling as most of certificates are above the 200KB Sentry limit
		//scope.SetExtra("File.Data", e.SeekFile.Data)
		scope.SetExtra("File.Length", len(e.SeekFile.Data))
	}
	if len(e.IPs) > 0 {
		scope.SetExtra("IPs", e.IPs)
	}
	if len(e.ASNs) > 0 {
		scope.SetExtra("ASNs", e.ASNs)
	}
}

func NewCertificateErrorValidity(cert *librpki.RPKI_Certificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_VALIDITY,
		Certificate: cert,
		InnerErr:    err,
		Message:     "expiration issue",
		Stack:       callers(),
	}
}

func NewCertificateErrorParent(cert, parent *librpki.RPKI_Certificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_PARENT,
		Certificate: cert,
		Parent:      parent,
		InnerErr:    err,
		Message:     "parent issue",
		Stack:       callers(),
	}
}

func NewCertificateErrorRevocation(cert *librpki.RPKI_Certificate) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_REVOCATION,
		Certificate: cert,
		Message:     "revocation by issuer",
		Stack:       callers(),
	}
}

func NewCertificateErrorResource(cert *librpki.RPKI_Certificate, ips []librpki.IPCertificateInformation, asns []librpki.ASNCertificateInformation) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_RESOURCE,
		Certificate: cert,
		Message:     "resource issue",
		IPs:         ips,
		ASNs:        asns,
		Stack:       callers(),
	}
}

func NewCertificateErrorConflict(cert *librpki.RPKI_Certificate) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_CONFLICT,
		Certificate: cert,
		Message:     "certificate conflict",
		Stack:       callers(),
	}
}
