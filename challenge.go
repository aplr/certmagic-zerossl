package zerossl

type Identifier struct {
	// type (required, string):  The type of identifier.
	Type string `json:"type"`

	// value (required, string):  The identifier itself.
	Value string `json:"value"`
}

type ChallengeType string

const (
	ChallengeTypeHTTP ChallengeType = "http"
	ChallengeTypeDNS  ChallengeType = "dns"
)

type Challenge struct {
	// type (required, string):  The type of challenge encoded in the object.
	Type ChallengeType `json:"type"`

	// The resource path for solving the http challenge.
	HTTPResourcePath string `json:"httpResourcePath,omitempty"`

	// The resource payload for solving the https challenge.
	HTTPResourcePayload []string `json:"httpsResourcePayload,omitempty"`

	// The record name for solving the dns challenge.
	DNSCNAMERecordName string `json:"dnsCnameRecordName,omitempty"`

	// The record pointer for solving the dns challenge.
	DNSCNAMERecordPointer string `json:"dnsCnameRecordPointer,omitempty"`

	// We attach the identifier that this challenge is associated with, which
	// may be useful information for solving a challenge. It is not part of the
	// structure as defined by the spec but is added by us to provide enough
	// information to solve the DNS challenge.
	Identifier Identifier `json:"identifier"`
}
