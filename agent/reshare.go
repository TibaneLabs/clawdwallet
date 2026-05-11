package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/eddsa/keygen"
	"github.com/KarpelesLab/tss-lib/v2/eddsa/resharing"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/google/uuid"
)

// Reshare runs a reshare ceremony that produces fresh shares for the new
// committee while preserving the wallet's aggregate public key (and thus its
// Solana address). Either committee may invoke this function.
//
// oldPeers must match the committee the existing share was generated for.
// newPeers may overlap with oldPeers and/or introduce a replacement party.
func (a *Agent) Reshare(ctx context.Context, oldPeers, newPeers []PeerSpec, oldThreshold, newThreshold int) error {
	if a.client == nil {
		return errors.New("agent not started")
	}
	sh := a.Share()
	if sh == nil {
		return errors.New("no share on disk; cannot reshare")
	}

	allPeers := mergePeers(oldPeers, newPeers)
	sid := "rs-" + uuid.NewString()
	if err := a.broadcastInit(ctx, sid, allPeers, &InitPayload{
		Kind:         SessionReshare,
		Peers:        oldPeers,
		Threshold:    oldThreshold,
		NewPeers:     newPeers,
		NewThreshold: newThreshold,
	}); err != nil {
		return fmt.Errorf("broadcast reshare init: %w", err)
	}
	return a.runReshare(ctx, sid, oldPeers, newPeers, oldThreshold, newThreshold)
}

func (a *Agent) joinReshare(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	defer cancel()
	if err := a.runReshare(ctx, sid, ip.Peers, ip.NewPeers, ip.Threshold, ip.NewThreshold); err != nil {
		a.log.Error("joinReshare", "err", err)
	}
}

func (a *Agent) runReshare(ctx context.Context, sid string, oldPeers, newPeers []PeerSpec, oldThreshold, newThreshold int) error {
	sh := a.Share()
	sortedOld := SortedPartyIDs(oldPeers)
	sortedNew := SortedPartyIDs(newPeers)
	mySpotID := a.SpotID()
	myID := findMyPartyID(sortedOld, mySpotID)
	if myID == nil {
		myID = findMyPartyID(sortedNew, mySpotID)
	}
	if myID == nil {
		return errors.New("reshare: this agent's PartyID is not in either committee")
	}
	oldCtx := tss.NewPeerContext(sortedOld)
	newCtx := tss.NewPeerContext(sortedNew)
	params := tss.NewReSharingParameters(
		tss.Edwards(),
		oldCtx, newCtx,
		myID,
		len(sortedOld), oldThreshold,
		len(sortedNew), newThreshold,
	)

	outCh := make(chan tss.Message, 4*(len(sortedOld)+len(sortedNew)))
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	var saveData keygen.LocalPartySaveData
	if sh != nil && sh.SaveData != nil {
		saveData = *sh.SaveData
	}
	party := resharing.NewLocalParty(params, saveData, outCh, endCh)

	allPeers := mergePeers(oldPeers, newPeers)
	session := newSession(sid, SessionReshare, allPeers, outCh)
	session.party = party
	a.registry.Put(session)
	defer a.registry.Drop(sid)

	go a.pumpOutbound(session)
	go func() {
		if err := party.Start(); err != nil {
			session.finish(err)
		}
	}()

	select {
	case data := <-endCh:
		session.finish(nil)
		// Old committee parties get an empty save data on completion; only the
		// new committee actually receives a usable share.
		if data == nil || data.EDDSAPub == nil {
			return nil
		}
		newShare := saveDataToShare(sid, newPeers, newThreshold, data)
		return a.SetShare(newShare)
	case <-session.doneCh:
		return session.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func mergePeers(a, b []PeerSpec) []PeerSpec {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]PeerSpec, 0, len(a)+len(b))
	for _, p := range append(append([]PeerSpec{}, a...), b...) {
		if seen[p.SpotID] {
			continue
		}
		seen[p.SpotID] = true
		out = append(out, p)
	}
	return out
}
