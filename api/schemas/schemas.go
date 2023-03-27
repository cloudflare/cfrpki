package schemas

type OutputROA struct {
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max-length"`
}

type OutputASN struct {
	ASN     uint32   `json:"asn,omitempty"`
	Range   []uint32 `json:"asn-range,omitempty"`
	Inherit bool     `json:"inherit,omitempty"`
}

type OutputIP struct {
	Prefix  string   `json:"prefix,omitempty"`
	Range   []string `json:"ip-range,omitempty"`
	Inherit int      `json:"inherit,omitempty"`
}

// Generating rest of data
type OutputRes struct {
	Type           string `json:"type"`
	Name           string `json:"name,omitempty"`
	SubjectKeyId   string `json:"subject-key-id,omitempty"`
	AuthorityKeyId string `json:"authority-key-id,omitempty"`
	Path           string `json:"path"`

	Hash string `json:"hash"`

	TA string `json:"ta"`

	SIAs      []string     `json:"sia,omitempty"`
	IPs       []*OutputIP  `json:"ips,omitempty"`
	ASNs      []*OutputASN `json:"asns,omitempty"`
	ROAs      []*OutputROA `json:"roas,omitempty"`
	ASN       uint32       `json:"asn,omitempty"`
	Emitted   int          `json:"emitted,omitempty"`
	ValidFrom int          `json:"validfrom,omitempty"`
	ValidTo   int          `json:"validto,omitempty"`
	Serial    string       `json:"serial,omitempty"`

	FileList       []string `json:"mft-files,omitempty"`
	ManifestNumber string   `json:"mft-number,omitempty"`
	ThisUpdate     int      `json:"mft-thisupdate,omitempty"`
	NextUpdate     int      `json:"mft-nextupdate,omitempty"`

	State   int `json:"state,omitempty"`
	Visible int `json:"visible,omitempty"`
}

type ResourcesJSON struct {
	Metadata struct {
		Generated int `json:"generated"`
	} `json:"metadata"`
	Resources []*OutputRes `json:"resources"`
}
