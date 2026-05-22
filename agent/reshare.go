package agent

import (
	"context"
	"errors"
)

// Reshare is Stage-2 functionality and is intentionally disabled in Stage 1.
//
// When enabled it will dispatch on the loaded share's schema:
//   - SchemaFrost  → frosttss.NewResharing
//   - SchemaDkls23 → dklstss.NewResharing (with the joint ECDSAPub binding
//     required for NEW-only committee members)
//
// The function is kept on the type so the `reshare` CLI command continues to
// build; it returns an error at runtime instead of executing.
func (a *Agent) Reshare(ctx context.Context, oldPeers, newPeers []PeerSpec, oldThreshold, newThreshold int) error {
	return errors.New("reshare is Stage 2 — not enabled in this build")
}
