package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/KarpelesLab/outscript"

	"github.com/TibaneLabs/clawdwallet/policy"
	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/x402"
)

// X402Payer adapts the agent to x402.Payer.
//
// Stage 2: the x402 client surface is flag-gated. Pay is wired up against the
// same policy REST + walletsign TSS plumbing as BuildAndPay so the path stays
// compilable, but the CLI/MCP commands that hand out an X402Payer are gated
// behind CLAWDWALLET_ENABLE_X402.
type X402Payer struct{ A *Agent }

// Pay implements x402.Payer.
func (p *X402Payer) Pay(ctx context.Context, mint, recipient string, amount uint64, req *x402.PaymentRequirement) ([]byte, error) {
	a := p.A
	if a.Locked() {
		return nil, errors.New("wallet locked")
	}
	sh := a.Share()
	if sh == nil {
		return nil, errors.New("no share available")
	}
	if sh.WalletID == "" {
		return nil, errors.New("share has no wallet id")
	}
	addr, err := solana.AddressFromPubKey(sh.SolanaAddressBytes())
	if err != nil {
		return nil, err
	}
	myKey, _ := outscript.ParseSolanaKey(addr)
	mintKey, err := outscript.ParseSolanaKey(mint)
	if err != nil {
		return nil, fmt.Errorf("parse mint: %w", err)
	}
	toKey, err := outscript.ParseSolanaKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("parse recipient: %w", err)
	}
	sourceATA, err := outscript.SolanaGetAssociatedTokenAddress(myKey, mintKey)
	if err != nil {
		return nil, err
	}
	destATA, err := outscript.SolanaGetAssociatedTokenAddress(toKey, mintKey)
	if err != nil {
		return nil, err
	}

	decimals, err := a.rpc.GetTokenSupplyDecimals(ctx, mint)
	if err != nil {
		return nil, fmt.Errorf("fetch decimals: %w", err)
	}
	blockhash, err := a.rpc.GetLatestBlockhash(ctx)
	if err != nil {
		return nil, err
	}

	ix := solana.SPLTransferCheckedInstruction(sourceATA, mintKey, destATA, myKey, amount, decimals)
	tx, err := outscript.NewSolanaTx(myKey, blockhash, ix)
	if err != nil {
		return nil, err
	}

	msgBytes, err := solana.MessageBytes(tx)
	if err != nil {
		return nil, err
	}
	hashHex := hex.EncodeToString(msgBytes)

	parsed := policy.ParsedEffects{
		TokenDeltas: []policy.TokenDelta{{
			Mint: mint, Delta: -int64(amount), Decimals: decimals,
		}},
		ProgramsInvoked: []string{solana.SolanaTokenProgram.String()},
	}
	intent := policy.Intent{
		Description: "x402 payment",
		Skill:       "x402",
		Reason:      "required by remote endpoint",
	}

	x402Ctx := &policy.X402Context{Endpoint: ""}
	if req != nil {
		x402Ctx.Endpoint = recipient
	}

	parsedJSON, err := encodeParsedEffects(intent, parsed, x402Ctx)
	if err != nil {
		return nil, fmt.Errorf("encode parsed_effects: %w", err)
	}

	resp, err := policy.Submit(ctx, sh.WalletID, hashHex, parsedJSON)
	if err != nil {
		return nil, fmt.Errorf("policy submit: %w", err)
	}
	if !resp.Approved {
		return nil, fmt.Errorf("policy denied: %s", resp.Reason)
	}
	sid := resp.SessionID()
	if sid == "" {
		return nil, fmt.Errorf("policy approval missing session id (remote_key=%q)", resp.RemoteKey)
	}

	signers, err := a.resolveSigners(resp, sh)
	if err != nil {
		return nil, err
	}

	sig, err := a.SignDigest(ctx, sid, msgBytes, signers)
	if err != nil {
		return nil, err
	}
	if err := solana.AttachSignature(tx, myKey, sig); err != nil {
		return nil, err
	}
	return tx.MarshalBinary()
}
