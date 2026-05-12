package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/KarpelesLab/outscript"

	"github.com/TibaneLabs/clawdwallet/policy"
	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/store"
)

// base64URLEncode is a local alias used when assembling InitPayload-style
// peer key fields (raw bytes → base64url).
func base64URLEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TransferOptions is the input to BuildAndPay.
type TransferOptions struct {
	// To is the destination Solana address (base58).
	To string
	// Mint is the SPL token mint base58 (empty = native SOL transfer).
	Mint string
	// Amount in base units (lamports for SOL, mint base units for SPL).
	Amount uint64
	// Decimals is required for SPL transfers (used for TransferChecked).
	Decimals uint8
	// Intent describes why the agent is making this transfer.
	Intent policy.Intent
	// X402 optionally tags the transfer as an x402 payment (Stage 2).
	X402 *policy.X402Context
}

// BuildAndPay constructs the transaction, calls the phplatform policy module's
// `:signRequest` REST endpoint, joins the resulting TSS sign ceremony, and
// submits the signed transaction to Solana. Returns the on-chain signature.
//
// Per Stage 1: the agent self-reports parsed_effects (Decision 8). On approval
// the policy module opens a `Crypto_WalletSign_Verify` row of type `sign` with
// the digest as Data; wdrone polls for it and joins. The agent kicks the
// ceremony off by sending `<wdrone>/walletsign/<sid>/init`.
func (a *Agent) BuildAndPay(ctx context.Context, opts TransferOptions) (string, error) {
	if a.Locked() {
		return "", errors.New("wallet is locked")
	}
	sh := a.Share()
	if sh == nil {
		return "", errors.New("no share on disk; run keygen first")
	}
	if sh.WalletID == "" {
		return "", errors.New("share has no wallet id; cannot call :signRequest")
	}
	addr, err := solana.AddressFromPubKey(sh.SolanaAddressBytes())
	if err != nil {
		return "", err
	}
	myKey, _ := outscript.ParseSolanaKey(addr)

	blockhash, err := a.rpc.GetLatestBlockhash(ctx)
	if err != nil {
		return "", fmt.Errorf("getLatestBlockhash: %w", err)
	}

	var ix outscript.SolanaInstruction
	var parsed policy.ParsedEffects

	switch {
	case opts.Mint == "":
		toKey, err := outscript.ParseSolanaKey(opts.To)
		if err != nil {
			return "", fmt.Errorf("parse dest: %w", err)
		}
		ix = outscript.SolanaTransferInstruction(myKey, toKey, opts.Amount)
		parsed = policy.ParsedEffects{
			SOLDelta:        -int64(opts.Amount),
			ProgramsInvoked: []string{outscript.SolanaSystemProgram.String()},
		}
	default:
		mintKey, err := outscript.ParseSolanaKey(opts.Mint)
		if err != nil {
			return "", fmt.Errorf("parse mint: %w", err)
		}
		toKey, err := outscript.ParseSolanaKey(opts.To)
		if err != nil {
			return "", fmt.Errorf("parse dest: %w", err)
		}
		sourceATA, err := outscript.SolanaGetAssociatedTokenAddress(myKey, mintKey)
		if err != nil {
			return "", fmt.Errorf("derive source ATA: %w", err)
		}
		destATA, err := outscript.SolanaGetAssociatedTokenAddress(toKey, mintKey)
		if err != nil {
			return "", fmt.Errorf("derive dest ATA: %w", err)
		}
		ix = solana.SPLTransferCheckedInstruction(sourceATA, mintKey, destATA, myKey, opts.Amount, opts.Decimals)
		parsed = policy.ParsedEffects{
			TokenDeltas: []policy.TokenDelta{{
				Mint: opts.Mint, Delta: -int64(opts.Amount), Decimals: opts.Decimals,
			}},
			ProgramsInvoked: []string{solana.SolanaTokenProgram.String()},
		}
	}

	tx, err := outscript.NewSolanaTx(myKey, blockhash, ix)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}
	rawTx, err := serializeUnsigned(tx)
	if err != nil {
		return "", err
	}

	resp, err := policy.Submit(ctx, sh.WalletID, rawTx, opts.Intent, parsed)
	if err != nil {
		return "", fmt.Errorf("policy submit: %w", err)
	}
	if !resp.Approved {
		return "", fmt.Errorf("policy denied: %s", resp.Reason)
	}
	sid := resp.SessionID()
	if sid == "" {
		return "", fmt.Errorf("policy approval missing session id (remote_key=%q)", resp.RemoteKey)
	}

	// Prefer the policy module's InitPayload.peers (carries canonical Key
	// bytes per peer) over the bare spot-id list. Falls back to share-derived
	// peers when neither shape is present.
	signers, err := a.resolveSigners(resp, sh)
	if err != nil {
		return "", err
	}

	// Compute the digest the TSS round will sign over. For Solana that's the
	// raw message bytes (NOT a pre-hashed pre-image): tss-lib's EdDSA signing
	// takes the message as a big.Int and treats it directly so the resulting
	// signature verifies under stdlib ed25519.Verify.
	msgBytes, err := solana.MessageBytes(tx)
	if err != nil {
		return "", err
	}

	sig, err := a.SignDigest(ctx, sid, msgBytes, signers)
	if err != nil {
		return "", fmt.Errorf("tss sign: %w", err)
	}
	if err := solana.AttachSignature(tx, myKey, sig); err != nil {
		return "", err
	}
	wire, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal signed tx: %w", err)
	}
	return a.rpc.SendTransaction(ctx, wire)
}

// resolveSigners turns the policy response into PeerSpecs ready for the TSS
// round. Source-of-truth priority:
//
//  1. resp.InitPayload.Peers — canonical, carries SpotID + moniker + key.
//  2. resp.Peers (bare spot-id list) — agent fills moniker + falls back to
//     share-derived keys for the bigint slot.
//  3. share-recorded peers — last resort, only if the policy module returned
//     nothing useful.
//
// In all cases the agent ensures its own SpotID is included once. The result
// is trimmed to Threshold+1 only when the policy module supplied no explicit
// shape (case 3); when the policy module told us the peer set we trust it.
func (a *Agent) resolveSigners(resp *policy.SignResponse, sh *store.Share) ([]PeerSpec, error) {
	mySpot := a.SpotID()

	if resp != nil && resp.InitPayload != nil && len(resp.InitPayload.Peers) > 0 {
		out := make([]PeerSpec, 0, len(resp.InitPayload.Peers))
		for _, p := range resp.InitPayload.Peers {
			moniker := p.Moniker
			if moniker == "" && p.SpotID == mySpot {
				moniker = a.cfg.Moniker
			} else if moniker == "" {
				moniker = "peer"
			}
			out = append(out, PeerSpec{SpotID: p.SpotID, Moniker: moniker, Key: p.Key})
		}
		return out, nil
	}

	if resp != nil && len(resp.Peers) > 0 {
		out := make([]PeerSpec, 0, len(resp.Peers))
		for _, id := range resp.Peers {
			moniker := "peer"
			if id == mySpot {
				moniker = a.cfg.Moniker
			}
			ps := PeerSpec{SpotID: id, Moniker: moniker}
			// Best effort: lift the canonical key bytes from our share's
			// recorded peer keys so the bigint slot matches wdrone's. The
			// shared PartyID.Key fallback (sha256) would otherwise diverge
			// from wdrone's raw-pubkey derivation.
			ps.Key = a.shareKeyFor(sh, id)
			out = append(out, ps)
		}
		return out, nil
	}

	if len(sh.PeerSpotIDs) == 0 {
		return nil, errors.New("no signer peers known")
	}
	out := make([]PeerSpec, 0, sh.Threshold+1)
	out = append(out, PeerSpec{SpotID: mySpot, Moniker: a.cfg.Moniker, Key: a.shareKeyFor(sh, mySpot)})
	for _, id := range sh.PeerSpotIDs {
		if id == mySpot {
			continue
		}
		out = append(out, PeerSpec{SpotID: id, Moniker: "peer", Key: a.shareKeyFor(sh, id)})
		if len(out) >= sh.Threshold+1 {
			break
		}
	}
	return out, nil
}

// shareKeyFor returns the base64url-encoded canonical key bytes for spotID,
// looked up in the persisted share's peer table. Returns "" when the share
// doesn't carry per-peer key bytes (older keygen runs).
func (a *Agent) shareKeyFor(sh *store.Share, spotID string) string {
	if sh == nil {
		return ""
	}
	for i, id := range sh.PeerSpotIDs {
		if id != spotID {
			continue
		}
		if i >= len(sh.PeerKeys) || sh.PeerKeys[i] == nil {
			return ""
		}
		return base64URLEncode(sh.PeerKeys[i].Bytes())
	}
	return ""
}

// serializeUnsigned returns the wire form of a tx with empty signature slots.
// We use it as a stand-in TxBytes for the policy evaluator's parsed_effects
// verification step.
func serializeUnsigned(tx *outscript.SolanaTx) ([]byte, error) {
	n := solana.NumRequiredSignatures(tx)
	if cap(tx.Signatures) < n {
		tx.Signatures = make([][]byte, n)
	}
	for i := 0; i < n; i++ {
		if len(tx.Signatures[i]) == 0 {
			tx.Signatures[i] = make([]byte, 64)
		}
	}
	return tx.MarshalBinary()
}
