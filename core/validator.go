package core

// Validator is an interface that allows to validate any given info for a new
// longterm key pair creation or for a new signature request.
// Each validation returns a boolean indicating if the given input is validated
// or not, and a string explaining the reason of the invalidation if any.
type Validator interface {
	ValidateLongtermInfo(*LongtermProposal) (bool, string)
	ValidateSignatureInfo(*SignatureInfo) (bool, string)
}
