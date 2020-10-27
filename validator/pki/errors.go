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
	ERROR_CERTIFICATE_UNKNOWN = iota
	ERROR_CERTIFICATE_EXPIRATION
	ERROR_CERTIFICATE_PARENT
	ERROR_CERTIFICATE_REVOCATION
	ERROR_CERTIFICATE_RESOURCE
	ERROR_CERTIFICATE_CONFLICT
	ERROR_FILE
	ERROR_CERTIFICATE_MANIFEST
	ERROR_CERTIFICATE_HASH
	ERROR_CERTIFICATE_CRL
)

type stack []uintptr
type Frame uintptr

var (
	ErrorTypeToName = map[int]string{
		ERROR_CERTIFICATE_UNKNOWN:    "unknown",
		ERROR_CERTIFICATE_EXPIRATION: "expiration",
		ERROR_CERTIFICATE_PARENT:     "parent",
		ERROR_CERTIFICATE_REVOCATION: "revocation",
		ERROR_CERTIFICATE_RESOURCE:   "resource",
		ERROR_CERTIFICATE_CONFLICT:   "conflict",
		ERROR_FILE:                   "file",
		ERROR_CERTIFICATE_MANIFEST:   "manifest",
		ERROR_CERTIFICATE_HASH:       "hash",
		ERROR_CERTIFICATE_CRL:        "crl",
	}
)

type CertificateError struct {
	EType int

	InnerErr error
	Message  string

	Certificate *librpki.RPKICertificate
	Conflict    *librpki.RPKICertificate
	Parent      *librpki.RPKICertificate

	IPs  []librpki.IPCertificateInformation
	ASNs []librpki.ASNCertificateInformation

	Stack *stack

	File     *PKIFile
	SeekFile *SeekFile

	InnerFile *PKIFile
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
	if e.Conflict != nil {
		ski := e.Conflict.Certificate.SubjectKeyId
		aki := e.Conflict.Certificate.AuthorityKeyId
		scope.SetTag("Conflict.SubjectKeyId", hex.EncodeToString(ski))
		scope.SetTag("Conflict.AuthorityKeyId", hex.EncodeToString(aki))

		scope.SetExtra("Conflict.NotBefore", e.Conflict.Certificate.NotBefore)
		scope.SetExtra("Conflict.NotAfter", e.Conflict.Certificate.NotAfter)
		scope.SetTag("Conflict.SerialNumber", e.Conflict.Certificate.SerialNumber.String())

		// Might be worth to convert into proper strings later
		scope.SetExtra("Conflict.SIAs", e.Conflict.SubjectInformationAccess)
		scope.SetExtra("Conflict.IP", e.Conflict.IPAddresses)
		scope.SetExtra("Conflict.ASN", e.Conflict.ASNums)
		scope.SetExtra("Conflict.ASNRDI", e.Conflict.ASNRDI)
	}
	if e.File != nil {
		if e.File.Repo != "" {
			scope.SetTag("File.Repository", e.File.Repo)
		} else {
			if e.File.Parent != nil && e.File.Parent.Repo != "" {
				scope.SetTag("File.Repository", e.File.Parent.Repo)
			}
		}
		scope.SetTag("File.Path", e.File.Path)
		scope.SetTag("File.Type", TypeToName[e.File.Type])
		scope.SetExtra("File.Trust", e.File.Trust)
	}
	if e.InnerFile != nil {
		if e.InnerFile.Repo != "" {
			scope.SetTag("InnerFile.Repository", e.InnerFile.Repo)
		} else {
			if e.InnerFile.Parent != nil && e.InnerFile.Parent.Repo != "" {
				scope.SetTag("InnerFile.Repository", e.InnerFile.Parent.Repo)
			}
		}
		scope.SetTag("InnerFile.Path", e.InnerFile.Path)
		scope.SetTag("InnerFile.Type", TypeToName[e.InnerFile.Type])
		scope.SetExtra("InnerFile.Trust", e.InnerFile.Trust)
	}
	if e.SeekFile != nil {
		// disabling as most of certificates are above the 200KB Sentry limit
		//scope.SetExtra("File.Data", e.SeekFile.Data)
		scope.SetExtra("File.Length", len(e.SeekFile.Data))
		scope.SetExtra("File.Sha256", hex.EncodeToString(e.SeekFile.Sha256))
	}
	if len(e.IPs) > 0 {
		scope.SetExtra("IPs", e.IPs)
	}
	if len(e.ASNs) > 0 {
		scope.SetExtra("ASNs", e.ASNs)
	}
}

func NewCertificateErrorValidity(cert *librpki.RPKICertificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_EXPIRATION,
		Certificate: cert,
		InnerErr:    err,
		Message:     "expiration issue",
		Stack:       callers(),
	}
}

func NewCertificateErrorParent(cert, parent *librpki.RPKICertificate, err error) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_PARENT,
		Certificate: cert,
		Parent:      parent,
		InnerErr:    err,
		Message:     "parent issue",
		Stack:       callers(),
	}
}

func NewCertificateErrorRevocation(cert *librpki.RPKICertificate) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_REVOCATION,
		Certificate: cert,
		Message:     "revocation by issuer",
		Stack:       callers(),
	}
}

func NewCertificateErrorResource(cert *librpki.RPKICertificate, ips []librpki.IPCertificateInformation, asns []librpki.ASNCertificateInformation) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_RESOURCE,
		Certificate: cert,
		Message:     "resource issue",
		IPs:         ips,
		ASNs:        asns,
		Stack:       callers(),
	}
}

func NewCertificateErrorConflict(cert *librpki.RPKICertificate, conflict *librpki.RPKICertificate) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_CONFLICT,
		Certificate: cert,
		Conflict:    conflict,
		Message:     "certificate conflict",
		Stack:       callers(),
	}
}

func NewCertificateErrorManifestRevocation(cert *librpki.RPKICertificate, err error, fileMft *PKIFile, fileAffected *PKIFile) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_MANIFEST,
		Certificate: cert,
		InnerErr:    err,
		InnerFile:   fileAffected,
		Message:     "revocation due to manifest issue",
		Stack:       callers(),
	}
}

func NewCertificateErrorCRLRevocation(cert *librpki.RPKICertificate, err error, fileCrl *PKIFile, fileAffected *PKIFile) *CertificateError {
	return &CertificateError{
		EType:       ERROR_CERTIFICATE_CRL,
		Certificate: cert,
		InnerErr:    err,
		InnerFile:   fileAffected,
		Message:     "revocation due to crl issue",
		Stack:       callers(),
	}
}

type FileError CertificateError

func (e *FileError) Error() string {
	return (*CertificateError)(e).Error()
}
func (e *FileError) StackTrace() []Frame {
	return (*CertificateError)(e).StackTrace()
}
func (e *FileError) SetSentryScope(scope *sentry.Scope) {
	(*CertificateError)(e).SetSentryScope(scope)
}
func (e *FileError) AddFileErrorInfo(file *PKIFile, seek *SeekFile) {
	(*CertificateError)(e).AddFileErrorInfo(file, seek)
}

func NewFileError(err error) *FileError {
	return &FileError{
		EType:    ERROR_FILE,
		Message:  "file error",
		InnerErr: err,
		Stack:    callers(),
	}
}

type ResourceError struct {
	EType         int
	InnerValidity bool
	InnerErr      error
	Message       string

	Wrapper interface{}

	Stack *stack

	File     *PKIFile
	SeekFile *SeekFile
}

func (e *ResourceError) StackTrace() []Frame {
	if e.InnerErr != nil {
		if errC, ok := e.InnerErr.(interface{ StackTrace() []Frame }); ok {
			return errC.StackTrace()
		}
	}
	return StackTrace(e.Stack)
}

func (e *ResourceError) Error() string {
	return e.InnerErr.Error()
}

func (e *ResourceError) SetSentryScope(scope *sentry.Scope) {
	if e.InnerErr != nil {
		if errC, ok := e.InnerErr.(interface{ SetSentryScope(scope *sentry.Scope) }); ok {
			errC.SetSentryScope(scope)
		}
	}
	scope.SetTag("Type", ErrorTypeToName[e.EType])
	if e.File != nil {
		if e.File.Repo != "" {
			scope.SetTag("File.Repository", e.File.Repo)
		} else {
			if e.File.Parent != nil && e.File.Parent.Repo != "" {
				scope.SetTag("File.Repository", e.File.Parent.Repo)
			}
		}
		scope.SetTag("File.Path", e.File.Path)
		scope.SetTag("File.Type", TypeToName[e.File.Type])
		scope.SetExtra("File.Trust", e.File.Trust)
	}
	if e.SeekFile != nil {
		// disabling as most of certificates are above the 200KB Sentry limit
		//scope.SetExtra("File.Data", e.SeekFile.Data)
		scope.SetExtra("File.Length", len(e.SeekFile.Data))
		scope.SetExtra("File.Sha256", hex.EncodeToString(e.SeekFile.Sha256))
	}
}

func (e *ResourceError) AddFileErrorInfo(file *PKIFile, seek *SeekFile) {
	e.File = file
	e.SeekFile = seek
}

func NewResourceErrorWrap(wrapper interface{}, err error) *ResourceError {
	rw := &ResourceError{
		EType:    ERROR_CERTIFICATE_UNKNOWN,
		InnerErr: err,
		Wrapper:  wrapper,
		Stack:    callers(),
	}
	if err != nil {
		if errC, ok := err.(*CertificateError); ok {
			rw.EType = errC.EType
		}
	}

	return rw
}

func NewResourceErrorHash(hashFile, hashExpected []byte) *ResourceError {
	return &ResourceError{
		EType:    ERROR_CERTIFICATE_HASH,
		InnerErr: fmt.Errorf("file hash is %s, expected %s from manifest", hex.EncodeToString(hashFile), hex.EncodeToString(hashExpected)),
		Message:  "hash issue",
		Stack:    callers(),
	}
}
