package dkg

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/share/dkg/pedersen"
	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/slog"
)

// Config is given to a DKG handler and contains all needed parameters to
// successfully run the DKG protocol.
type Config struct {
	Private       *key.Private    // the longterm private key
	List          []*key.Identity // the list of participants
	Threshold     int             // the threshold of active participants needed
	ShareCallback func(Share)     // callback gets called when share is computed
	// XXX Currently not implemented
	ErrCallback func(err error)
	// XXX Currently not in use / tested
	Timeout time.Duration // after timeout, protocol is finished in any cases.
}

// Handler is the stateful struct that runs a DKG with the peers
type Handler struct {
	net           Network                    // network to send data out
	conf          *Config                    // configuration given at init time
	idx           int                        // the index of the private/public key pair in the list
	state         *dkg.DistKeyGenerator      // dkg stateful struct
	n             int                        // number of participants
	tmpResponses  map[uint32][]*dkg.Response // temporary buffer of responses
	sentDeals     bool                       // true if the deals have been sent already
	dealProcessed int                        // how many deals have we processed so far
	respProcessed int                        // how many responses have we processed so far
	done          bool                       // is the protocol done
	sync.Mutex
}

// NewHandler returns a fresh dkg handler using this private key.
func NewHandler(conf *Config, n Network) *Handler {
	if err := validateConf(conf); err != nil {
		panic(err)
	}
	list := conf.List
	priv := conf.Private
	t := conf.Threshold
	points := make([]kyber.Point, len(list), len(list))
	myIdx := -1
	myPoint := priv.Public.Point()
	for i := range list {
		point := list[i].Point()
		points[i] = point
		if point.Equal(myPoint) {
			myIdx = i
		}
	}
	if myIdx == -1 {
		panic("dkg: no public key corresponding in the given list. BAD.")
	}
	state, err := dkg.NewDistKeyGenerator(key.Curve, priv.Scalar(), points, t)
	if err != nil {
		panic("dkg: error using dkg library: " + err.Error())
	}
	return &Handler{
		conf:         conf,
		state:        state,
		net:          n,
		tmpResponses: make(map[uint32][]*dkg.Response),
		idx:          myIdx,
		n:            len(list),
	}
}

// Process process an incoming message from the network.
func (h *Handler) Process(id *key.Identity, packet *Packet) {
	switch {
	case packet.Deal != nil:
		h.processDeal(id, packet.Deal)
	case packet.Response != nil:
		h.processResponse(id, packet.Response)
	case packet.Justification != nil:
		panic("not yet implemented")
	}
}

// Start sends the first message to run the protocol
func (h *Handler) Start() {
	// XXX catch the error
	h.sendDeals()
}

func (h *Handler) processDeal(id *key.Identity, deal *dkg.Deal) {
	h.Lock()
	h.dealProcessed++
	slog.Debugf("dkg: processing deal from %s (%d processed)", id.ID, h.dealProcessed)
	resp, err := h.state.ProcessDeal(deal)
	defer h.processTmpResponses(deal)
	defer h.Unlock()
	if err != nil {
		slog.Infof("dkg: error processing deal: %s", err)
		return
	}

	if !h.sentDeals {
		h.sendDeals()
		h.sentDeals = true
		slog.Debugf("dkg: sent all deals")
	}
	out := &Packet{
		Response: resp,
	}
	h.broadcast(out)
	slog.Debugf("dkg: broadcasted response")
}

func (h *Handler) processTmpResponses(deal *dkg.Deal) {
	h.Lock()
	defer h.checkCertified()
	defer h.Unlock()
	resps, ok := h.tmpResponses[deal.Index]
	if !ok {
		return
	}
	slog.Debug("dkg: processing ", len(resps), " out-of-order responses for dealer", deal.Index)
	delete(h.tmpResponses, deal.Index)
	for _, r := range resps {
		_, err := h.state.ProcessResponse(r)
		if err != nil {
			slog.Debugf("dkg: err process temp response: ", err)
		}
	}
}
func (h *Handler) processResponse(pub *key.Identity, resp *dkg.Response) {
	h.Lock()
	defer h.checkCertified()
	defer h.Unlock()
	h.respProcessed++
	j, err := h.state.ProcessResponse(resp)
	slog.Debugf("dkg: processing response(%d so far) from %s", h.respProcessed, pub.Address)
	if err != nil {
		if strings.Contains(err.Error(), "no deal for it") {
			h.tmpResponses[resp.Index] = append(h.tmpResponses[resp.Index], resp)
			slog.Debug("dkg: storing future response for unknown deal ", resp.Index)
			return
		}
		slog.Infof("dkg: error process response: %s", err)
		return
	}
	if j != nil {
		slog.Debugf("dkg: broadcasting justification")
		packet := &Packet{
			Justification: j,
		}
		go h.broadcast(packet)
	}
	slog.Debugf("dkg: processResponse(%d so far) from %s --> Certified() ? %v --> done ? %v", h.respProcessed, pub.Address, h.state.Certified(), h.done)
}

// checkCertified checks if there has been enough responses and if so, creates
// the distributed key share, and sends it along the channel returned by
// WaitShare.
func (h *Handler) checkCertified() {
	h.Lock()
	defer h.Unlock()
	if !h.state.Certified() || h.done {
		return
	}
	//slog.Debugf("%s: processResponse(%d) from %s #3", d.addr, d.respProcessed, pub.Address)
	h.done = true
	slog.Infof("dkg: certified!")
	dks, err := h.state.DistKeyShare()
	if err != nil {
		return
	}
	share := Share(*dks)
	h.conf.ShareCallback(share)
}

// sendDeals tries to send the deals to each of the nodes.
// It returns an error if a number of node superior to the threshold have not
// received the deal. It is basically a no-go.
func (h *Handler) sendDeals() error {
	deals, err := h.state.Deals()
	if err != nil {
		return err
	}
	var good = 1
	for i, deal := range deals {
		if i == h.idx {
			panic("end of the universe")
		}
		pub := h.conf.List[i]
		packet := &Packet{
			Deal: deal,
		}
		//fmt.Printf("%s sending deal to %s\n", d.addr, pub.Address)
		if err := h.net.Send(pub, packet); err != nil {
			slog.Debugf("dkg: failed to send deal to %s: %s", pub.Address, err)
		} else {
			good++
		}
	}
	if good < h.conf.Threshold {
		return fmt.Errorf("dkg: could only send deals to %d / %d (threshold %d)", good, h.n, h.conf.Threshold)
	}
	slog.Infof("dkg: sent deals successfully to %d nodes", good-1)
	return nil
}

func (h *Handler) broadcast(p *Packet) {
	for i, id := range h.conf.List {
		if i == h.idx {
			continue
		}
		if err := h.net.Send(id, p); err != nil {
			slog.Debugf("dkg: error sending packet to %s: %s", id.Address, err)
		}
	}
	slog.Debugf("dkg: broadcast done")
}

// Network is used by the Handler to send a DKG protocol packet over the network.
type Network interface {
	Send(id *key.Identity, pack *Packet) error
}

// Share represents the private information that a node holds after a successful
// DKG. This information MUST stay private !
type Share dkg.DistKeyShare

func validateConf(conf *Config) error {
	// XXX TODO
	return nil
}
