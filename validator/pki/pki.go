package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cloudflare/cfrpki/validator/lib"
	"time"
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
)

type Resource struct {
	Type     int
	Parent   *Resource
	File     *PKIFile
	Resource interface{}
	Childs   []*Resource
}

func (res *Resource) GetIdentifier() (bool, []byte) {
	switch res := res.Resource.(type) {
	case *librpki.RPKI_Certificate:
		return true, res.Certificate.SubjectKeyId
	case *librpki.RPKI_ROA:
		return true, res.Certificate.Certificate.SubjectKeyId
	case *librpki.RPKI_Manifest:
		return true, res.Certificate.Certificate.SubjectKeyId
	}
	return false, nil
}

type SeekFile struct {
	Repo string
	File string
	Data []byte
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
	ToExplore       []*PKIFile
	FileSeeker      FileSeeker
	Validator       *Validator
	Explored        map[string]bool
	ToExploreUnique map[string]bool
	Log             Log
}

func NewSimpleManager() *SimpleManager {
	return &SimpleManager{
		PathOfResource:  make(map[*Resource]*PKIFile),
		Explored:        make(map[string]bool),
		ToExploreUnique: make(map[string]bool),
	}
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

	Time time.Time
}

func NewValidator() *Validator {
	return &Validator{
		TALs: make(map[string]*Resource),

		ValidObjects: make(map[string]*Resource),
		Objects:      make(map[string]*Resource),

		CertsSerial: make(map[string]*Resource),
		Revoked:     make(map[string]bool),

		ValidCRL: make(map[string]*Resource),
		CRL:      make(map[string]*Resource),

		ValidROA: make(map[string]*Resource),
		ROA:      make(map[string]*Resource),

		ValidManifest: make(map[string]*Resource),
		Manifest:      make(map[string]*Resource),

		Time: time.Now().UTC(),
	}
}

type PKIFile struct {
	Parent *PKIFile
	Repo   string
	Path   string
	Type   int
	Trust  bool
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
				talValidation := talComp.Resource.(*librpki.RPKI_TAL).CheckCertificate(cert.Certificate)
				if !talValidation {
					return false, nil, nil, errors.New("Certificate was not validated against TAL")
				}
			}
		}

		valid, pathCert, res, err := v.AddCert(cert, pkifile.Trust)
		res.Type = TYPE_CER
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return valid, pathCert, res, err
	case TYPE_ROA:
		roa, err := librpki.DecodeROA(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddROA(pkifile, roa)
		res.File = pkifile
		return valid, nil, res, err
	case TYPE_MFT:
		mft, err := librpki.DecodeManifest(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, pathCert, res, err := v.AddManifest(pkifile, mft)
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return valid, pathCert, res, err
	case TYPE_CRL:
		// https://tools.ietf.org/html/rfc5280
		crl, err := x509.ParseDERCRL(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddCRL(crl)
		res.File = pkifile
		return valid, nil, res, err
	}
	return false, nil, nil, nil
}

func (v *Validator) InvalidateObject(keyid []byte) {
	invalidateList := make([][]byte, 1)
	invalidateList[0] = keyid

	for len(invalidateList) > 0 {
		currentKeyId := invalidateList[0]
		invalidateList = invalidateList[1:]

		ski := string(currentKeyId)
		res, hasCert := v.Objects[ski]
		delete(v.ValidObjects, ski)
		delete(v.ValidROA, ski)
		delete(v.ValidCRL, ski)

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

func (v *Validator) AddTAL(tal *librpki.RPKI_TAL) ([]*PKIFile, *Resource, error) {
	uri := tal.URI
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

func (v *Validator) AddCert(cert *librpki.RPKI_Certificate, trust bool) (bool, []*PKIFile, *Resource, error) {
	pathCert := ExtractPathCert(cert)

	ski := string(cert.Certificate.SubjectKeyId)
	aki := string(cert.Certificate.AuthorityKeyId)

	_, exists := v.Objects[ski]
	if exists {
		return false, nil, nil, errors.New(fmt.Sprintf("A certificate with Subject Key Id: %v already exists", hex.EncodeToString))
	}

	_, hasParentValid := v.ValidObjects[aki]
	parent, hasParent := v.Objects[aki]
	res := ObjectToResource(cert)
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

func (v *Validator) ValidateCertificate(cert *librpki.RPKI_Certificate, trust bool) error {
	ski := cert.Certificate.SubjectKeyId

	// Check time validity
	err := cert.ValidateTime(v.Time)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to expiration date %x: %v", ski, err))
	}

	if trust {
		return nil
	}

	// Check against parent
	aki := cert.Certificate.AuthorityKeyId
	parent, hasParent := v.ValidObjects[string(aki)]
	if !hasParent {
		return errors.New(fmt.Sprintf("Could not find parent %x for certificate %x", aki, ski))
	}

	parentCert, ok := parent.Resource.(*librpki.RPKI_Certificate)
	if !ok {
		return errors.New(fmt.Sprintf("Parent %x of %x is not a RPKI Certificate", ski, aki))
	}
	err = cert.Validate(parentCert)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate %x against parent %x: %v", ski, aki, err))
	}

	// Check presence in revokation lists
	_, revoked := v.Revoked[string(aki)+cert.Certificate.SerialNumber.String()]
	if revoked {
		return errors.New(fmt.Sprintf("Certificate was revoked by issuer %x", ski))
	}

	// Check IPs
	valids, invalids, checkParent := cert.ValidateIPCertificate(parentCert)
	chain := parent.Parent
	for chain != nil && len(checkParent) > 0 {
		key := parentCert.Certificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not valid", key, ski))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKI_Certificate)
		if !ok {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not a RPKI Certificate", key, ski))
		}
		validsTmp, invalidsTmp, checkParentTmp := librpki.ValidateIPCertificateList(checkParent, chainCert)
		valids = append(valids, validsTmp...)
		invalids = append(invalids, invalidsTmp...)
		checkParent = checkParentTmp
		chain = chain.Parent
	}
	if len(invalids) > 0 {
		return errors.New(fmt.Sprintf("%x contains invalid IP addresses: %v", ski, invalids))
	}

	// Check ASNs
	validsASN, invalidsASN, checkParentASN := cert.ValidateASNCertificate(parentCert)
	chain = parent.Parent
	for chain != nil && len(checkParentASN) > 0 {
		key := parentCert.Certificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not valid", key, ski))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKI_Certificate)
		if !ok {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not a RPKI Certificate", key, ski))
		}
		validsTmp, invalidsTmp, checkParentTmp := librpki.ValidateASNCertificateList(checkParentASN, chainCert)
		validsASN = append(validsASN, validsTmp...)
		invalidsASN = append(invalidsASN, invalidsTmp...)
		checkParentASN = checkParentTmp
		chain = chain.Parent
	}
	if len(invalidsASN) > 0 {
		return errors.New(fmt.Sprintf("%x contains invalid ASNs: %v", ski, invalidsASN))
	}

	return nil
}

func (v *Validator) AddROA(pkifile *PKIFile, roa *librpki.RPKI_ROA) (bool, *Resource, error) {
	valid, _, res, err := v.AddCert(roa.Certificate, false)
	res.File = pkifile
	res.Type = TYPE_ROACER

	err = v.ValidateROA(roa)
	if err != nil {
		valid = false
	}

	if !roa.InnerValid {
		valid = false
		err = roa.InnerValidityError
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

	return valid, res_roa, err
}

func (v *Validator) ValidateROA(roa *librpki.RPKI_ROA) error {
	err := roa.ValidateEntries()
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to wrong entry: %v", err))
	}
	return nil
}

func (v *Validator) AddManifest(pkifile *PKIFile, mft *librpki.RPKI_Manifest) (bool, []*PKIFile, *Resource, error) {
	pathCert := ExtractPathManifest(mft)

	valid, _, res, err := v.AddCert(mft.Certificate, false)
	res.File = pkifile
	res.Type = TYPE_MFTCER

	if !mft.InnerValid {
		valid = false
		err = mft.InnerValidityError
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

	var parentCert *librpki.RPKI_Certificate
	if hasParent && valid {
		var ok bool
		parentCert, ok = parent.Resource.(*librpki.RPKI_Certificate)
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
					childConv := child.Resource.(*librpki.RPKI_Certificate)
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

func ExtractPathCert(cert *librpki.RPKI_Certificate) []*PKIFile {
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

func ExtractPathManifest(mft *librpki.RPKI_Manifest) []*PKIFile {
	fileList := make([]*PKIFile, 0)
	for _, file := range mft.Content.FileList {
		curFile := file.File
		path := string(curFile)
		item := PKIFile{
			Type: DetermineType(path),
			Path: path,
		}
		fileList = append(fileList, &item)
	}
	return fileList
}

func (sm *SimpleManager) AddInitial(fileList []*PKIFile) {
	sm.PutFiles(fileList)
}

func (sm *SimpleManager) ExploreAdd(file *PKIFile, data *SeekFile, addInvalidChilds bool) {
	sm.Explored[file.ComputePath()] = true
	valid, subFiles, res, err := sm.Validator.AddResource(file, data.Data)
	if err != nil {
		if sm.Log != nil {
			sm.Log.Errorf("Error adding Resource %v: %v", file.Path, err)
		}
	}
	if !valid && err == nil {
		if sm.Log != nil {
			sm.Log.Warnf("Resource %v is invalid: %v", file.Path, err)
		}
	}
	for _, subFile := range subFiles {
		subFile.Parent = file
	}
	if addInvalidChilds || valid {
		sm.PutFiles(subFiles)
		sm.PathOfResource[res] = file
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
			if sm.Log != nil {
				sm.Log.Errorf("Error getting file: %v", err)
			}
		} else {
			count++
		}
		if !notMFT || file.Type != TYPE_MFT {
			data, err := sm.GetNextFile(file)

			if err != nil {
				if sm.Log != nil {
					sm.Log.Errorf("Error exploring file: %v", err)
				}
			} else if data != nil {
				sm.ExploreAdd(file, data, addInvalidChilds)
				hasMore = sm.HasMore()
			} else {
				if sm.Log != nil {
					sm.Log.Debugf("GetNextFile returned nothing")
				}
			}
		} else {
			err = sm.GetNextRepository(file, sm.ExploreAdd)
			sm.Explored[file.Repo] = true
			if err != nil {
				if sm.Log != nil {
					sm.Log.Errorf("Error exploring repository: %v", err)
				}
			}
		}
		hasMore = sm.HasMore()
	}
	return count
}
