package dkg

import (
	"fmt"
	"strings"
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/share/dkg/pedersen"
	"github.com/nikkolasg/dsign/key"
	"github.com/nikkolasg/slog"
)

// Network is used by the Handler to send a DKG protocol packet over the network.
type Network interface {
	Send(id *key.Identity, pack *Packet) error
}

// Share represents the private information that a node holds after a successful
// DKG. This information MUST stay private !
type Share dkg.DistKeyShare

// Handler is the stateful struct that runs a DKG with the peers
type Handler struct {
	net           Network                    // network to send data out
	priv          *key.Private               // the longterm private key
	idx           int                        // the index of the private/public key pair in the list
	list          []*key.Identity            // list of participants
	state         *dkg.DistKeyGenerator      // dkg stateful struct
	n             int                        // number of participants
	t             int                        // threshold of participants needed
	tmpResponses  map[uint32][]*dkg.Response // temporary buffer of responses
	sentDeals     bool                       // true if the deals have been sent already
	dealProcessed int                        // how many deals have we processed so far
	respProcessed int                        // how many responses have we processed so far
	done          bool                       // is the protocol done
	shareCh       chan Share                 // final share is sent over that channel
	sync.Mutex
}

// NewHandler returns a fresh dkg handler using this private key.
func NewHandler(n Network, priv *key.Private, list []*key.Identity, t int) *Handler {
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
		priv:         priv,
		state:        state,
		net:          n,
		tmpResponses: make(map[uint32][]*dkg.Response),
		idx:          myIdx,
		n:            len(list),
		t:            t,
		shareCh:      make(chan Share),
	}
}

// ProcessMessage process an incoming message from the network.
func (h *Handler) ProcessMessage(id *key.Identity, packet *Packet) {
	switch {
	case packet.Deal != nil:
		h.processDeal(id, packet.Deal)
	case packet.Response != nil:
		h.processResponse(id, packet.Response)
	case packet.Justification != nil:
		panic("not yet implemented")
	}
}

// WaitShare returns a channel where the final distributed share for this dkg
// participant is sent over.
func (h *Handler) WaitShare() chan Share {
	return h.shareCh
}

// Timeout triggers the timeout on the dkg library. This is currently needed
// because the implemented DKG protocol works only in synchronous network
// settings, i.e. per "round". Some other DKG schemes have been proposed to
// relieve that assumptions but not yet implemented.
func (h *Handler) Timeout() {
	h.state.SetTimeout()
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
		h.sendDeals(false)
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
	h.shareCh <- share
}

// sendDeals tries to send the deals to each of the nodes. force indicates if
// the local nodeis the initiator or not, and therefore must actively initiates
// the connection or not.
// It returns an error if a number of node superior to the threshold have not
// received the deal. It is basically a no-go.
func (h *Handler) sendDeals(force bool) error {
	deals, err := h.state.Deals()
	if err != nil {
		return err
	}
	var good = 1
	//z, _ := d.group.Index(d.priv.Public)
	//fmt.Printf("Index %d sendDeal() vs %d -- force ? %v\n ", d.idx, z, force)
	for i, deal := range deals {
		if i == h.idx {
			panic("end of the universe")
		}
		pub := h.list[i]
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
	if good < h.t {
		return fmt.Errorf("dkg: could only send deals to %d / %d (threshold %d)", good, h.n, h.t)
	}
	slog.Infof("dkg: sent deals successfully to %d nodes", good-1)
	return nil
}

func (h *Handler) broadcast(p *Packet) {
	for i, id := range h.list {
		if i == h.idx {
			continue
		}
		if err := h.net.Send(id, p); err != nil {
			slog.Debugf("dkg: error sending packet to %s: %s", id.Address, err)
		}
	}
	slog.Debugf("dkg: broadcast done")
}
