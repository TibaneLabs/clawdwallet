package agent

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/KarpelesLab/outscript"

	"github.com/TibaneLabs/clawdwallet/internal/policy"
	"github.com/TibaneLabs/clawdwallet/internal/solana"
	"github.com/TibaneLabs/clawdwallet/internal/x402"
)

// X402Payer adapts the agent to x402.Payer, producing a signed TransferChecked
// transaction without broadcasting (the x402 facilitator will broadcast).
type X402Payer struct{ A *Agent }

// Pay implements x402.Payer.
func (p *X402Payer) Pay(ctx context.Context, mint, recipient string, amount uint64, req *x402.PaymentRequirement) ([]byte, error) {
	a := p.A
	if a.Locked() {
		return nil, fmt.Errorf("wallet locked")
	}
	sh := a.Share()
	if sh == nil {
		return nil, fmt.Errorf("no share available")
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
	rawUnsigned, err := serializeUnsigned(tx)
	if err != nil {
		return nil, err
	}

	pr := &policy.SignRequest{
		RequestID: "x402-" + base64.RawURLEncoding.EncodeToString([]byte(req.Receiver))[:12],
		TxBytes:   base64.StdEncoding.EncodeToString(rawUnsigned),
		TxType:    "x402_payment",
		Intent: policy.Intent{
			Description: "x402 payment",
			Skill:       "x402",
			Reason:      "required by remote endpoint",
		},
		ParsedEffects: policy.ParsedEffects{
			TokenDeltas: []policy.TokenDelta{{
				Mint: mint, Delta: -int64(amount), Decimals: decimals,
			}},
			ProgramsInvoked: []string{solana.SolanaTokenProgram.String()},
		},
		X402Context: &policy.X402Context{
			Endpoint: req.Receiver,
		},
	}
	pcli := policy.New(a.client, a.cfg.PolicyID)
	resp, err := pcli.Submit(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("policy submit: %w", err)
	}
	if !resp.Approved {
		return nil, fmt.Errorf("policy denied: %s", resp.Reason)
	}

	msgBytes, err := solana.MessageBytes(tx)
	if err != nil {
		return nil, err
	}
	sig, err := a.SignDigest(ctx, msgBytes, nil)
	if err != nil {
		return nil, err
	}
	if err := solana.AttachSignature(tx, myKey, sig); err != nil {
		return nil, err
	}
	return tx.MarshalBinary()
}
