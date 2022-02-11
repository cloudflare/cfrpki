package pki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	librpki "github.com/cloudflare/cfrpki/validator/lib"
)

const (
	TYPE_UNKNOWN = iota
	TYPE_CER
	TYPE_MFT
	TYPE_ROA
	TYPE_CRL
	TYPE_ROACER
	TYPE_MFTCER
	TYPE_CAREPO
	TYPE_TAL
)

var (
	CARepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	Manifest     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 10}

	TypeToName = map[int]string{
		TYPE_UNKNOWN: "unknown",
		TYPE_CER:     "certificate",
		TYPE_MFT:     "manifest",
		TYPE_ROA:     "roa",
		TYPE_CRL:     "crl",
		TYPE_ROACER:  "roa-ee",
		TYPE_MFTCER:  "manifest-ee",
		TYPE_CAREPO:  "ca-repo",
		TYPE_TAL:     "tal",
	}
)

type Resource struct {
	Type     int
	Parent   *Resource
	File     *PKIFile
	Resource interface{}
	Childs   []*Resource

	CertTALValid bool // currently used for TALs: indicates the child is valid and does not need to be fetched again
}

func (res *Resource) GetIdentifier() (bool, []byte) {
	switch res := res.Resource.(type) {
	case *librpki.RPKICertificate:
		return true, res.Certificate.SubjectKeyId
	case *librpki.RPKIROA:
		return true, res.Certificate.Certificate.SubjectKeyId
	case *librpki.RPKIManifest:
		return true, res.Certificate.Certificate.SubjectKeyId
	}
	return false, nil
}

type SeekFile struct {
	Repo   string
	File   string
	Data   []byte
	Sha256 []byte
}

type FileSeeker interface {
	GetFile(*PKIFile) (*SeekFile, error)
	GetRepository(*PKIFile, CallbackExplore) error
}

type Log interface {
	Debugf(string, ...interface{})
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
}

type SimpleManager struct {
	PathOfResource  map[*Resource]*PKIFile
	ResourceOfPath  map[*PKIFile]*Resource
	ToExplore       []*PKIFile
	FileSeeker      FileSeeker
	Validator       *Validator
	Explored        map[string]bool
	ToExploreUnique map[string]bool
	Log             Log

	ReportErrors bool
	Errors       chan error

	StrictManifests bool
	StrictHash      bool
}

func NewSimpleManager() *SimpleManager {
	return &SimpleManager{
		PathOfResource:  make(map[*Resource]*PKIFile),
		ResourceOfPath:  make(map[*PKIFile]*Resource),
		Explored:        make(map[string]bool),
		ToExploreUnique: make(map[string]bool),
		Errors:          make(chan error, 50),
		StrictManifests: true,
		StrictHash:      true,
	}
}

func (sm *SimpleManager) Close() {
	close(sm.Errors)
}

func (sm *SimpleManager) reportError(err error) {
	if sm.ReportErrors {
		sm.Errors <- err
	}
}
func (sm *SimpleManager) reportErrorFile(err error, file *PKIFile, seek *SeekFile) {
	if errC, ok := err.(interface{ AddFileErrorInfo(*PKIFile, *SeekFile) }); file != nil && ok {
		errC.AddFileErrorInfo(file, seek)
	}
	sm.reportError(err)
}

func (sm *SimpleManager) PutFiles(fileList []*PKIFile) {
	for _, file := range fileList {
		path := file.ComputePath()
		_, ok1 := sm.Explored[path]
		_, ok2 := sm.ToExploreUnique[path]
		if ok1 || ok2 {
			if sm.Log != nil {
				sm.Log.Debugf("Skipping %v, already been explored", path)
			}
		} else {
			sm.ToExploreUnique[path] = true
			sm.ToExplore = append(sm.ToExplore, file)
		}
	}
}

func (sm *SimpleManager) HasMore() bool {
	return len(sm.ToExplore) > 0
}

func (sm *SimpleManager) GetNextExplore() (*PKIFile, bool, error) {
	if len(sm.ToExplore) == 0 {
		return nil, false, errors.New("EOF")
	}
	curExplore := sm.ToExplore[0]
	sm.ToExplore = sm.ToExplore[1:]
	return curExplore, len(sm.ToExplore) > 0, nil
}

func (sm *SimpleManager) GetNextFile(curExplore *PKIFile) (*SeekFile, error) {
	path := curExplore.ComputePath()
	if _, ok := sm.Explored[path]; ok {
		return nil, errors.New(fmt.Sprintf("File %v already explored", path))
	}

	if sm.FileSeeker != nil {
		data, err := sm.FileSeeker.GetFile(curExplore)
		if err != nil {
			err = NewFileError(err)
		}
		return data, err
	}
	return nil, errors.New("No interface to fetch file, check FileSeeker")
}

type CallbackExplore func(*PKIFile, *SeekFile, bool)

func (sm *SimpleManager) GetNextRepository(curExplore *PKIFile, callback CallbackExplore) error {
	if _, ok := sm.Explored[curExplore.Repo]; ok {
		return errors.New(fmt.Sprintf("Path %v already explored", curExplore.Repo))
	}

	if sm.FileSeeker != nil {
		err := sm.FileSeeker.GetRepository(curExplore, callback)
		return err
	}
	return errors.New("No interface to fetch file, check FileSeeker")
}

type Validator struct {
	TALs map[string]*Resource

	// Key by SubjectKeyIdentifier
	ValidObjects map[string]*Resource
	Objects      map[string]*Resource

	// Key by path
	ObjectsPath map[string]*Resource

	CertsSerial map[string]*Resource
	Revoked     map[string]bool

	// Key by parent certificate
	ValidCRL map[string]*Resource
	CRL      map[string]*Resource

	// Key by parent certificate
	ValidROA map[string]*Resource // Make sure EE certificates are unique for a ROA
	ROA      map[string]*Resource

	// Key by parent certificate
	ValidManifest map[string]*Resource // Make sure EE certificates are unique for a ROA
	Manifest      map[string]*Resource

	DecoderConfig *librpki.DecoderConfig

	Time time.Time
}

func NewValidator() *Validator {
	return &Validator{
		TALs: make(map[string]*Resource),

		ValidObjects: make(map[string]*Resource),
		Objects:      make(map[string]*Resource),

		ObjectsPath: make(map[string]*Resource),

		CertsSerial: make(map[string]*Resource),
		Revoked:     make(map[string]bool),

		ValidCRL: make(map[string]*Resource),
		CRL:      make(map[string]*Resource),

		ValidROA: make(map[string]*Resource),
		ROA:      make(map[string]*Resource),

		ValidManifest: make(map[string]*Resource),
		Manifest:      make(map[string]*Resource),

		DecoderConfig: librpki.DefaultDecoderConfig,

		Time: time.Now().UTC(),
	}
}

type PKIFile struct {
	Parent *PKIFile
	Repo   string
	Path   string
	Type   int
	Trust  bool

	ManifestHash []byte
}

func (f *PKIFile) ComputePath() string {
	pathRep := f.Path
	if f.Parent != nil && f.Parent.Type == TYPE_MFT {
		if len(f.Parent.Repo) > 0 && f.Parent.Repo[len(f.Parent.Repo)-1] == '/' {
			pathRep = f.Parent.Repo + pathRep
		} else {
			pathRep = f.Parent.Repo + "/" + pathRep
		}
	}
	return pathRep
}

func ObjectToResource(data interface{}) *Resource {
	res := &Resource{
		Resource: data,
		Childs:   make([]*Resource, 0),
	}
	return res
}

func (v *Validator) AddResource(pkifile *PKIFile, data []byte) (bool, []*PKIFile, *Resource, error) {
	resType := pkifile.Type
	switch resType {
	case TYPE_TAL:
		tal, err := librpki.DecodeTAL(data)
		if err != nil {
			return false, nil, nil, err
		}
		pathCert, res, err := v.AddTAL(tal)
		if res == nil {
			return true, pathCert, res, errors.New("Resource is empty")
		}
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return true, pathCert, res, err
	case TYPE_CER:
		cert, err := librpki.DecodeCertificate(data)
		if err != nil {
			return false, nil, nil, err
		}
		if pkifile != nil && pkifile.Parent != nil && pkifile.Parent.Type == TYPE_TAL {
			talComp, ok := v.TALs[pkifile.Path]
			if ok {
				talValidation := talComp.Resource.(*librpki.RPKITAL).CheckCertificate(cert.Certificate)
				if !talValidation {
					return false, nil, nil, errors.New("Certificate was not validated against TAL")
				}
				v.TALs[pkifile.Path].CertTALValid = true // indicates that we can skip downloading
			}
		}

		valid, pathCert, res, err := v.AddCert(cert, pkifile.Trust)
		if res == nil {
			return valid, pathCert, res, fmt.Errorf("Resource is empty: %v", err)
		}
		res.Type = TYPE_CER
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}

		v.ObjectsPath[pkifile.Path] = res
		return valid, pathCert, res, err
	case TYPE_ROA:
		roa, err := v.DecoderConfig.DecodeROA(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddROA(pkifile, roa)
		if res == nil {
			return valid, nil, res, fmt.Errorf("Resource is empty: %v", err)
		}
		res.File = pkifile

		v.ObjectsPath[pkifile.Path] = res
		return valid, nil, res, err
	case TYPE_MFT:
		mft, err := v.DecoderConfig.DecodeManifest(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, pathCert, res, err := v.AddManifest(pkifile, mft)
		if res == nil {
			return valid, nil, res, fmt.Errorf("Resource is empty: %v", err)
		}
		res.File = pkifile
		// add the parent information to invalidate the Manifest in case of an issue
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}

		v.ObjectsPath[pkifile.Path] = res
		return valid, pathCert, res, err
	case TYPE_CRL:
		// https://tools.ietf.org/html/rfc5280
		crl, err := x509.ParseDERCRL(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddCRL(crl)
		if pkifile.Parent.Parent.Path != res.Parent.File.Path {
			return false, nil, nil, fmt.Errorf("CRL %s does not match with the parent %s", pkifile.Path, pkifile.Parent.Parent.Path)
		}
		if res == nil {
			return valid, nil, res, fmt.Errorf("Resource is empty: %v", err)
		}
		res.File = pkifile

		v.ObjectsPath[pkifile.Path] = res
		return valid, nil, res, err
	}
	return false, nil, nil, errors.New("Unknown file type")
}

func (v *Validator) InvalidateObject(keyid []byte) {
	invalidated := make(map[string]bool)
	invalidateList := make([][]byte, 1)
	invalidateList[0] = keyid

	for len(invalidateList) > 0 {
		currentKeyId := invalidateList[0]
		invalidateList = invalidateList[1:]

		ski := string(currentKeyId)

		if _, ok := invalidated[ski]; ok {
			continue
		}

		res, hasCert := v.Objects[ski]
		delete(v.ValidObjects, ski)
		delete(v.ValidROA, ski)
		delete(v.ValidCRL, ski)
		invalidated[ski] = true

		if hasCert {
			for _, child := range res.Childs {
				hasId, id := child.GetIdentifier()
				if hasId {
					//v.InvalidateObject(id)
					invalidateList = append(invalidateList, id)
				}
			}
		}
	}

}

func (v *Validator) AddTAL(tal *librpki.RPKITAL) ([]*PKIFile, *Resource, error) {
	uri := tal.GetRsyncURI()
	files := []*PKIFile{
		&PKIFile{
			Type:  TYPE_CER,
			Path:  uri,
			Trust: true,
		},
	}
	res := ObjectToResource(tal)
	res.Type = TYPE_TAL

	v.TALs[uri] = res

	return files, res, nil
}

func (v *Validator) AddCert(cert *librpki.RPKICertificate, trust bool) (bool, []*PKIFile, *Resource, error) {
	pathCert := ExtractPathCert(cert)

	ski := string(cert.Certificate.SubjectKeyId)
	aki := string(cert.Certificate.AuthorityKeyId)

	res := ObjectToResource(cert)

	conflict, exists := v.Objects[ski]
	if exists {
		conflictCert, _ := conflict.Resource.(*librpki.RPKICertificate)
		return false, nil, res, NewCertificateErrorConflict(cert, conflictCert)
	}

	_, hasParentValid := v.ValidObjects[aki]
	parent, hasParent := v.Objects[aki]
	res.Parent = parent

	var valid bool
	if hasParentValid || trust {
		valid = true
	}

	err := v.ValidateCertificate(cert, trust)
	if err != nil {
		valid = false
	}

	if hasParent && parent != nil && valid {
		parent.Childs = append(parent.Childs, res)

		v.CertsSerial[aki+cert.Certificate.SerialNumber.String()] = res
	}

	if valid {
		v.ValidObjects[ski] = res
	}
	v.Objects[ski] = res

	return valid, pathCert, res, err
}

func (v *Validator) ValidateCertificate(cert *librpki.RPKICertificate, trust bool) error {
	// Check time validity
	err := cert.ValidateTime(v.Time)
	if err != nil {
		return NewCertificateErrorValidity(cert, err)
	}

	if trust {
		return nil
	}

	// Check against parent
	aki := cert.Certificate.AuthorityKeyId
	parent, hasParent := v.ValidObjects[string(aki)]
	if !hasParent {
		return NewCertificateErrorParent(cert, nil, errors.New("missing parent"))
	}

	parentCert, ok := parent.Resource.(*librpki.RPKICertificate)
	if !ok {
		return NewCertificateErrorParent(cert, parentCert, errors.New("parent is not a rpki certificate"))
	}
	err = cert.Validate(parentCert)
	if err != nil {
		return NewCertificateErrorParent(cert, parentCert, err)
	}

	// Check presence in revocation lists
	_, revoked := v.Revoked[string(aki)+cert.Certificate.SerialNumber.String()]
	if revoked {
		return NewCertificateErrorRevocation(cert)
	}

	// Check IPs
	validIPs, invalidIPs, checkParent := cert.ValidateIPCertificate(parentCert)
	chain := parent.Parent
	for chain != nil && len(checkParent) > 0 {
		key := parentCert.Certificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			//return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not valid", key, ski))
			return NewCertificateErrorParent(cert, parentCert, errors.New(fmt.Sprintf("ancestor %x is missing", key)))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKICertificate)
		if !ok {
			//return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not a RPKI Certificate", key, ski))
			return NewCertificateErrorParent(cert, parentCert, errors.New(fmt.Sprintf("ancestor %x is not a rpki certificate", key)))
		}
		validTmp, invalidTmp, checkParentTmp := librpki.ValidateIPCertificateList(checkParent, chainCert)
		validIPs = append(validIPs, validTmp...)
		invalidIPs = append(invalidIPs, invalidTmp...)
		checkParent = checkParentTmp
		chain = chain.Parent
	}

	// Check ASNs
	validASNs, invalidASNs, checkParentASN := cert.ValidateASNCertificate(parentCert)
	chain = parent.Parent
	for chain != nil && len(checkParentASN) > 0 {
		key := parentCert.Certificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			return NewCertificateErrorParent(cert, parentCert, errors.New(fmt.Sprintf("ancestor %x is not valid", key)))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKICertificate)
		if !ok {
			return NewCertificateErrorParent(cert, parentCert, errors.New(fmt.Sprintf("ancestor %x is not a rpki certificate", key)))
		}
		validTmp, invalidTmp, checkParentTmp := librpki.ValidateASNCertificateList(checkParentASN, chainCert)
		validASNs = append(validASNs, validTmp...)
		invalidASNs = append(invalidASNs, invalidTmp...)
		checkParentASN = checkParentTmp
		chain = chain.Parent
	}

	if len(invalidIPs) > 0 || len(invalidASNs) > 0 {
		//return errors.New(fmt.Sprintf("%x contains invalid ASNs: %v", ski, invalidsASN))
		//return errors.New(fmt.Sprintf("%x contains invalid IP addresses: %v", ski, invalids))
		return NewCertificateErrorResource(cert, invalidIPs, invalidASNs)
	}

	return nil
}

func (v *Validator) AddROA(pkifile *PKIFile, roa *librpki.RPKIROA) (bool, *Resource, error) {
	valid, _, res, err := v.AddCert(roa.Certificate, false)
	if res == nil {
		return valid, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
	}
	res.File = pkifile
	res.Type = TYPE_ROACER

	errValidity := v.ValidateROA(roa)
	if errValidity != nil {
		valid = false
		err = errValidity
	}

	if !roa.InnerValid {
		valid = false
		err = errors.New(fmt.Sprintf("ROA inner validity error: %v", roa.InnerValidityError))
	}

	res_roa := ObjectToResource(roa)
	res_roa.Type = TYPE_ROA
	res_roa.File = pkifile
	res.Childs = append(res.Childs, res_roa)
	res_roa.Parent = res
	key := roa.Certificate.Certificate.SubjectKeyId

	if valid {
		v.ValidROA[string(key)] = res_roa
	}
	v.ROA[string(key)] = res_roa

	if err != nil {
		errRes := NewResourceErrorWrap(roa, err)
		errRes.InnerValidity = valid
		err = errRes
	}

	return valid, res_roa, err
}

func (v *Validator) ValidateROA(roa *librpki.RPKIROA) error {
	err := roa.ValidateEntries()
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to wrong entry: %v", err))
	}
	return nil
}

func (v *Validator) AddManifest(pkifile *PKIFile, mft *librpki.RPKIManifest) (bool, []*PKIFile, *Resource, error) {
	pathCert, err := ExtractPathManifest(mft)
	if err != nil {
		return false, nil, nil, fmt.Errorf("ExtractPathManifest failed: %v", err)
	}

	valid, _, res, err := v.AddCert(mft.Certificate, false)
	if res == nil {
		return valid, pathCert, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
	}
	res.File = pkifile
	res.Type = TYPE_MFTCER

	if !mft.InnerValid {
		valid = false
		err = errors.New(fmt.Sprintf("Manifest inner validity error: %v", mft.InnerValidityError))
	}

	res_mft := ObjectToResource(mft)
	res_mft.Type = TYPE_MFT
	res_mft.File = pkifile
	res.Childs = append(res.Childs, res_mft)
	res_mft.Parent = res
	key := mft.Certificate.Certificate.SubjectKeyId
	if valid {
		v.ValidManifest[string(key)] = res_mft
	}
	v.Manifest[string(key)] = res_mft

	if err != nil {
		errRes := NewResourceErrorWrap(mft, err)
		errRes.InnerValidity = valid
		err = errRes
	}

	return valid, pathCert, res_mft, err
}

func (v *Validator) AddCRL(crl *pkix.CertificateList) (bool, *Resource, error) {
	var aki []byte
	for _, ext := range crl.TBSCertList.Extensions {
		if ext.Id.Equal(librpki.AuthorityKeyIdentifier) {
			if len(ext.Value) > 4 {
				aki = ext.Value[4:]
			}
		}
	}

	_, hasParentValid := v.ValidObjects[string(aki)]
	parent, hasParent := v.Objects[string(aki)]
	res := ObjectToResource(crl)
	res.Type = TYPE_CRL
	res.Parent = parent

	var valid bool
	if hasParentValid {
		valid = true
	}

	var parentCert *librpki.RPKICertificate
	if hasParent && valid {
		var ok bool
		parentCert, ok = parent.Resource.(*librpki.RPKICertificate)
		if !ok {
			valid = false
		}
	}
	if valid {
		err := parentCert.Certificate.CheckCRLSignature(crl)
		if err != nil {
			valid = false
		} else {
			v.ValidCRL[string(aki)] = res
			for _, revoked := range crl.TBSCertList.RevokedCertificates {
				/*for _, child := range parent.Childs {
					switch child := child.Resource.(type) {
					case *librpki.RPKI_Certificate:
						if child.Certificate.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
							err = v.InvalidateObject(child.Certificate.SubjectKeyId)
							// Handle error?
						}
					}
				}*/
				key := string(aki) + revoked.SerialNumber.String()
				child, found := v.CertsSerial[key]
				if found {
					childConv := child.Resource.(*librpki.RPKICertificate)
					if childConv.Certificate.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						v.InvalidateObject(childConv.Certificate.SubjectKeyId)
					}
				}

				v.Revoked[key] = true
			}
			parent.Childs = append(parent.Childs, res)
		}
	}
	v.CRL[string(aki)] = res

	return valid, res, nil
}

func (v *Validator) GetRepositories() {

}

func (v *Validator) GetValidROAs() {

}

func DetermineType(path string) int {
	if len(path) > 4 {
		if path[len(path)-4:] == ".cer" {
			return TYPE_CER
		} else if path[len(path)-4:] == ".mft" {
			return TYPE_MFT
		} else if path[len(path)-4:] == ".crl" {
			return TYPE_CRL
		} else if path[len(path)-4:] == ".roa" {
			return TYPE_ROA
		}
	}
	return TYPE_UNKNOWN
}

func ExtractPathCert(cert *librpki.RPKICertificate) []*PKIFile {
	fileList := make([]*PKIFile, 0)

	var repo string
	item := &PKIFile{
		Type: TYPE_MFT,
	}
	var add bool
	for _, sia := range cert.SubjectInformationAccess {
		if sia.AccessMethod.Equal(Manifest) {
			item.Path = string(sia.GeneralName)
			add = true
		} else if sia.AccessMethod.Equal(CARepository) {
			repo = string(sia.GeneralName)
			item.Repo = repo
		}
	}

	for _, crl := range cert.Certificate.CRLDistributionPoints {
		item := &PKIFile{
			Type: TYPE_CRL,
			Repo: repo,
			Path: crl,
		}
		fileList = append(fileList, item)
	}

	if add {
		fileList = append(fileList, item)
	}
	return fileList
}

// Returns the list of files from the Manifest
func ExtractPathManifest(mft *librpki.RPKIManifest) ([]*PKIFile, error) {
	fileList := make([]*PKIFile, 0)
	for _, file := range mft.Content.FileList {
		curFile := file.Name
		path := string(curFile)
		// GHSA-8459-6rc9-8vf8: Prevent file path references to parent
		// directories.
		if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
			return nil, fmt.Errorf("Path %q contains illegal path element", path)
		}
		item := PKIFile{
			Type:         DetermineType(path),
			Path:         path,
			ManifestHash: file.GetHash(),
		}
		fileList = append(fileList, &item)
	}
	return fileList, nil
}

func (sm *SimpleManager) AddInitial(fileList []*PKIFile) {
	sm.PutFiles(fileList)
}

// Given a file, invalidates the certificate parent of the Manifest in which the file is listed in
func (sm *SimpleManager) InvalidateManifestParent(file *PKIFile, mftError error) {
	if file != nil && file.Parent != nil && file.Parent.Type == TYPE_MFT && file.Parent.Parent != nil && file.Parent.Parent.Type == TYPE_CER {
		res, ok := sm.ResourceOfPath[file.Parent.Parent]

		if ok && res != nil && res.Resource != nil {
			cert, ok := res.Resource.(*librpki.RPKICertificate)
			if ok {
				sm.Validator.InvalidateObject(cert.Certificate.SubjectKeyId)

				err := NewCertificateErrorManifestRevocation(cert, mftError, file.Parent, file)
				sm.reportErrorFile(err, file.Parent.Parent, nil)

			} else {
				sm.Log.Debugf("Could not invalidate certificate because incorrect resource")
			}
		} else {
			sm.Log.Debugf("Could not invalidate certificate because not found in list")
		}
	}
}

func (sm *SimpleManager) InvalidateCRLParent(file *PKIFile, crlError error) {
	if file != nil && file.Parent != nil && file.Parent.Type == TYPE_CRL && file.Parent.Parent != nil && file.Parent.Parent.Type == TYPE_CER {
		res, ok := sm.Validator.ObjectsPath[file.Parent.Parent.Path]

		if ok && res != nil && res.Resource != nil {
			cert, ok := res.Resource.(*librpki.RPKICertificate)
			if ok {
				sm.Validator.InvalidateObject(cert.Certificate.SubjectKeyId)

				err := NewCertificateErrorCRLRevocation(cert, crlError, file.Parent, file)
				sm.reportErrorFile(err, file.Parent.Parent, nil)

			} else {
				sm.Log.Debugf("Could not invalidate certificate because incorrect resource")
			}
		} else {
			sm.Log.Debugf("Could not invalidate certificate because not found in list")
		}
	}
}

func (sm *SimpleManager) ExploreAdd(file *PKIFile, data *SeekFile, addInvalidChilds bool) {
	sm.Explored[file.ComputePath()] = true
	valid, subFiles, res, err := sm.Validator.AddResource(file, data.Data)

	/*if !valid || err != nil {
		if sm.StrictManifests {
			// will also invalidate when ROA is expired
			sm.InvalidateManifestParent(file, err)
		}
	}*/

	if err != nil {
		//sm.InvalidateCRLParent(file, err)

		switch err.(type) {
		case *FileError:
		case *ResourceError:
		case *CertificateError:
		default:
			fe := NewFileError(err)
			fe.AddFileErrorInfo(file, data)
			err = fe
		}

		if sm.Log != nil {
			sm.reportErrorFile(err, file, data)
		}
	}
	if !valid && err == nil {
		sm.reportErrorFile(err, file, data)
	}
	for _, subFile := range subFiles {
		subFile.Parent = file
	}
	if addInvalidChilds || valid {
		sm.PutFiles(subFiles)
		sm.PathOfResource[res] = file
		sm.ResourceOfPath[file] = res
	}
}

// addInvalidChilds is a strict mode: visible at LACNIC with
// manifests with short expiration date.
// The certificate can still be valid while its discovery path will not
func (sm *SimpleManager) Explore(notMFT bool, addInvalidChilds bool) int {
	hasMore := sm.HasMore()
	var count int
	for hasMore {
		// Log errors
		var err error
		var file *PKIFile

		file, hasMore, err = sm.GetNextExplore()
		if err != nil {
			sm.reportError(err)
		} else {
			count++
		}
		if !notMFT || file.Type != TYPE_MFT {
			data, err := sm.GetNextFile(file)

			if err == nil && data != nil && sm.StrictHash && data.Sha256 != nil && file.ManifestHash != nil {
				// Invalidates the Manifests' CA when the manifest is expired
				if file.Parent != nil && file.Parent.Type == TYPE_MFT {
					res, ok := sm.ResourceOfPath[file.Parent]
					if ok && res != nil && res.Resource != nil {
						cert, ok := res.Resource.(*librpki.RPKIManifest)
						if ok {
							if time.Now().After(cert.Content.NextUpdate) || time.Now().Before(cert.Content.ThisUpdate) {
								sm.InvalidateManifestParent(file, nil)
							}
						} else {
							sm.Log.Debugf("Resource is not a manifest, not invalidating")
						}
					} else {
						sm.Log.Debugf("Could not fetch Parent Resource, not invalidating")
					}
				}
				if bytes.Compare(data.Sha256, file.ManifestHash) != 0 {
					errHash := NewResourceErrorHash(data.Sha256, file.ManifestHash)
					errHash.AddFileErrorInfo(file, data)
					err = errHash
				}
			}

			if err != nil || data == nil {

				// This invalidates the Manifests' CA when a file is not found
				if sm.StrictManifests {
					sm.InvalidateManifestParent(file, nil)
					//sm.reportErrorFile(err, file, data)
				}

			}
			if err != nil {
				sm.reportErrorFile(err, file, data)

				sm.InvalidateCRLParent(file, err)
			} else if data != nil {
				sm.ExploreAdd(file, data, addInvalidChilds)
				hasMore = sm.HasMore()
			} else { // data == nil && err == nil -> file was not found
				if sm.Log != nil {
					sm.Log.Debugf("GetNextFile returned nothing")
				}
			}
		} else {
			err = sm.GetNextRepository(file, sm.ExploreAdd)
			sm.Explored[file.Repo] = true
			if err != nil {
				sm.reportErrorFile(err, file, nil)
			}
		}
		hasMore = sm.HasMore()
	}
	return count
}
