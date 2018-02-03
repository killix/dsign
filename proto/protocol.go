package proto

// Protocol is the core of dsign. It runs the necessary sub protocol (dkg / dss)
// with the right parameters to get a dsign-ature.
type Protocol struct {
}

// NewProtocol returns a new protocol
func NewProtocol() *Protocol {
	return &Protocol{}
}
