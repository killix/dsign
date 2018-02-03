package core

import (
	"crypto/rand"
	"errors"

	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/dsign/net"
	"github.com/nikkolasg/slog"
)

type lg = key.SharedPrivate

// State is the core of dsign. It runs the necessary sub protocol (dkg / dss)
// with the right parameters to get a dsign-ature.
type State struct {
	gw            net.Gateway // to send / receive packets from network
	st            Store       // to store and load cryptographic material + signature
	val           Validator   // to validate the requests
	hasLongterm   bool        // true if dist. longterm key is already generated.
	longterm      *lg         // private share of the dist. key
	longtermState *lgState
	signingState  *sigState
}

// NewState returns a new state
func NewState(gw net.Gateway, s Store, v Validator) *State {
	state := &State{
		gw:  gw,
		st:  s,
		val: v,
	}
	if lg, err := s.LongtermShare(); err == nil {
		state.hasLongterm = true
		state.longterm = lg
	}
	go state.gw.Start(state.handler)
	return state
}

// StartNewLongterm starts the creation of a new distributed longterm key pair. Once
// finished, the longterm distributed key pair is automatically saved thanks to
// the Store.
func (s *State) StartNewLongterm(lp *LongtermProposal) error {
	if s.hasLongterm {
		return errors.New("dsign only supports one longterm key for the moment")
	}
	if ok, e := s.val.ValidateLongtermInfo(lp); !ok {
		return errors.New("validation of longterm key info failed: " + e)
	}
	sessionID := newSessionID()
	s.longtermState = newLongtermState(s.gw, sessionID, s.st)
	s.longtermState.Start()
	return nil
}

// NewSignature starts the creation of a new distributed signature.
func (s *State) NewSignature(si *SignatureInfo) error {
	return nil
}

// handler receives all packet from network and dispatch it to the right
// recipients for further processing.
func (s *State) handler(id *key.Identity, msg []byte) {
	buff, err := encoder.Unmarshal(msg)
	if err != nil {
		slog.Debugf("dsign: <%s> sent unknown packet", id.Address)
		return
	}
	// if it panics, that means something's wrong with the encoder code, not
	// because of user input.
	packet := buff.(*ProtocolPacket)
	switch {
	case packet.NewKeyPair != nil:
		s.handleNewKeyPair(id, packet.NewKeyPair)
	case packet.NewSignature != nil:
		s.handleNewSignature(id, packet.NewSignature)
	default:
		slog.Debugf("disgn: <%s> sent null packet", id.Address)
	}
}

func (s *State) handleNewKeyPair(id *key.Identity, nkp *NewKeyPair) {
	if s.hasLongterm {
		slog.Debugf("dsign: <%s> sent longterm creation, but already has one", id.Address)
	}
	if s.longterm == nil {
		s.longtermState = newLongtermState(s.gw, nkp.SessionID, s.st)
	}
	s.longtermState.process(id, nkp)
}

func (s *State) handleNewSignature(id *key.Identity, ns *NewSignature) {

}

type lgState struct {
	id []byte
	gw net.Gateway
	st Store
}

func newLongtermState(gw net.Gateway, id []byte, s Store) *lgState {
	return &lgState{
		id: id,
		gw: gw,
		st: s,
	}
}

func (l *lgState) Start() {

}

func (l *lgState) process(id *key.Identity, nkp *NewKeyPair) {

}

type sigState struct {
	id []byte
	gw net.Gateway
}

func newSigState(gw net.Gateway, id []byte) *sigState {
	return &sigState{
		id: id,
		gw: gw,
	}
}

func newSessionID() []byte {
	var sid [32]byte
	if _, err := rand.Read(sid[:]); err != nil {
		panic("can't gather randomness: " + err.Error())
	}
	return sid[:]
}
