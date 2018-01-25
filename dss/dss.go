// Package dss implements a distributed schnorr signature protocol.
// It basically consists of using one longterm distributed key,
// running a dkg protocol to get a an ephemeral distributed key
// and compute the Schnorr signature.
package dss

import (
	"errors"
	"sync"

	"github.com/dedis/kyber/share/dss"
	"github.com/nikkolasg/dsign/dkg"
	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/slog"
)

// Config is given to a DSS handler and contains all relevant
// information to correctly run the dss protocol.
type Config struct {
	// Basic information, same as DKG
	*dkg.Config
	// longterm secret share
	Longterm *dkg.Share
	// random ~ ephemeral secret share
	Random *dkg.Share
	// message to sign
	Message []byte
}

// Handler holds the relevant information to perform a distributed
// signature protocol run.
type Handler struct {
	net         Network     // the network interface used to send message
	conf        *Config     // config needed to setup the dss
	state       *dss.DSS    // state containing all DSS info
	signatureCh chan []byte // signature is sent over that channel when ready
	errorCh     chan error  // error is signalled over that channel
	done        bool        // true when the signature have been recovered and sent

	sync.Mutex
}

// NewHandler returns a dss handler using the given conf.
func NewHandler(conf *Config, net Network) *Handler {
	points := key.IdentitiesToPoints(conf.List)
	state, err := dss.NewDSS(key.Curve, conf.Private.Scalar(), points, conf.Longterm, conf.Random, conf.Message, conf.Threshold)
	if err != nil {
		// error only if key is not in list
		panic("dss: error using dss library: " + err.Error())
	}
	return &Handler{
		conf:        conf,
		net:         net,
		state:       state,
		signatureCh: make(chan []byte, 1),
		errorCh:     make(chan error, 1),
	}
}

// Start sends the partial signature
func (h *Handler) Start() {
	h.sendPartialSig()
}

// Process gives any incoming dss packet to the state
func (h *Handler) Process(from *key.Identity, p *Packet) {
	h.Lock()
	defer h.Unlock()
	err := h.state.ProcessPartialSig(p)
	if err != nil {
		slog.Debug("dss: error processing partial sig: ", err)
	}
	if !h.state.EnoughPartialSig() || h.done {
		return
	}

	sig, err := h.state.Signature()
	if err != nil {
		slog.Debug("dss: error recovering sig: ", err)
		// XXX This error should not happen ever except a
		// mistake from DSS library
		panic(err)
	}
	h.done = true
	h.signatureCh <- sig
}

// WaitSignature returns a channel over which the signature is
// sent when ready.
func (h *Handler) WaitSignature() chan []byte {
	return h.signatureCh
}

// WaitError returns a channel over which any error is sent to
func (h *Handler) WaitError() chan error {
	return h.errorCh
}

func (h *Handler) sendPartialSig() {
	ps, err := h.state.PartialSig()
	if err != nil {
		h.errorCh <- err
	}
	var errS string
	for _, id := range h.conf.Config.List {
		if err := h.net.Send(id, ps); err != nil {
			errS += err.Error() + "\n"
		}
	}
	if errS != "" {
		h.errorCh <- errors.New(errS)
	}
}

// Network is used by the Handler to send a DSS protocol packet
// over the network.
type Network interface {
	Send(id *key.Identity, pack *Packet) error
}
