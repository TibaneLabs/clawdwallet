package agent

import (
	"context"
	"errors"
)

// Reshare is Stage-2 functionality and is intentionally disabled in Stage 1.
//
// The previous implementation used the legacy `eddsa/keygen` + `eddsa/resharing`
// outCh/endCh API of tss-lib v2.1.x. The Stage-1 transport rewrite moved the
// agent to the broker/JsonMessage `eddsatss` API of v2.2.x, and porting the
// reshare ceremony will be picked up alongside the wdrone-side reshare path.
//
// The function is kept on the type so the `reshare` CLI command continues to
// build; it returns an error at runtime instead of executing.
func (a *Agent) Reshare(ctx context.Context, oldPeers, newPeers []PeerSpec, oldThreshold, newThreshold int) error {
	return errors.New("reshare is Stage 2 — not enabled in this build")
}
