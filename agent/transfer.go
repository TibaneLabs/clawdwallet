package agent

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/KarpelesLab/outscript"
	"github.com/google/uuid"

	"github.com/TibaneLabs/clawdwallet/policy"
	"github.com/TibaneLabs/clawdwallet/solana"
)

// TransferOptions is the input to BuildTransfer.
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
	// X402 optionally tags the transfer as an x402 payment.
	X402 *policy.X402Context
}

// BuildAndPay constructs the transaction, requests policy approval, runs the
// TSS signing round, and submits the result to Solana. Returns the on-chain
// signature.
func (a *Agent) BuildAndPay(ctx context.Context, opts TransferOptions) (string, error) {
	if a.Locked() {
		return "", errors.New("wallet is locked")
	}
	sh := a.Share()
	if sh == nil {
		return "", errors.New("no share on disk; run keygen first")
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
	var txType string
	var parsed policy.ParsedEffects

	switch {
	case opts.Mint == "":
		toKey, err := outscript.ParseSolanaKey(opts.To)
		if err != nil {
			return "", fmt.Errorf("parse dest: %w", err)
		}
		ix = outscript.SolanaTransferInstruction(myKey, toKey, opts.Amount)
		txType = "transfer"
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
		ttype := "transfer"
		if opts.X402 != nil {
			ttype = "x402_payment"
		}
		txType = ttype
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

	req := &policy.SignRequest{
		RequestID:     uuid.NewString(),
		TxBytes:       base64.StdEncoding.EncodeToString(rawTx),
		TxType:        txType,
		Intent:        opts.Intent,
		ParsedEffects: parsed,
		X402Context:   opts.X402,
	}
	pc := policy.New(a.client, a.cfg.PolicyID)
	resp, err := pc.Submit(ctx, req)
	if err != nil {
		return "", fmt.Errorf("policy submit: %w", err)
	}
	if !resp.Approved {
		if resp.EscalatedToOwner {
			return "", fmt.Errorf("policy escalated to owner; reason: %s", resp.Reason)
		}
		if resp.Question != "" {
			return "", fmt.Errorf("policy requested clarification: %s", resp.Question)
		}
		return "", fmt.Errorf("policy denied: %s", resp.Reason)
	}

	// Compute the digest the TSS round will sign over. For Solana that's the
	// raw message bytes (NOT a sha-hashed pre-image). tss-lib's EdDSA signing
	// takes the message as a big.Int and treats it directly, so we pass the
	// message bytes through unchanged.
	msgBytes, err := solana.MessageBytes(tx)
	if err != nil {
		return "", err
	}

	// Most TSS-EdDSA implementations sign over a hash-then-clamp transcript; the
	// outscript Sign path uses ed25519.Sign which performs the standard
	// pre-hash internally. The eddsa signing.LocalParty in tss-lib v2 expects
	// the *message* (not hash), but to keep wire compatibility with stdlib
	// Ed25519 verification we sign over the message exactly as ed25519.Sign
	// would see it.
	_ = sha512.New // documents the relationship; not used directly

	sig, err := a.SignDigest(ctx, msgBytes, nil)
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
