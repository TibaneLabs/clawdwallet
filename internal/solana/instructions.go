package solana

import (
	"encoding/binary"
	"fmt"

	"github.com/KarpelesLab/outscript"
)

// SolanaTokenProgram is the SPL Token program ID. It is exported by outscript as
// part of the instruction helpers; we re-derive it here so we can build
// TransferChecked without depending on an unexported variable.
var SolanaTokenProgram = mustParse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

// SPLTransferCheckedInstruction returns an SPL Token Program TransferChecked
// instruction (index 12). This is the variant required by the x402 "exact"
// scheme on Solana — the on-chain program verifies the supplied mint and
// decimals match the source account, which prevents a class of confused-deputy
// bugs against the simpler Transfer (index 3) instruction.
//
// outscript exposes Transfer (index 3) but not TransferChecked; the architecture
// doc flags this as a required gap. This function fills it.
//
//	source       -- the sender's associated token account (ATA)
//	mint         -- the token mint (e.g. USDC mint)
//	destination  -- the recipient's ATA
//	owner        -- the wallet that authorises the transfer (our TSS pubkey)
//	amount       -- amount in token base units
//	decimals     -- the mint's decimals; must match the on-chain value
func SPLTransferCheckedInstruction(
	source, mint, destination, owner outscript.SolanaKey,
	amount uint64,
	decimals uint8,
) outscript.SolanaInstruction {
	data := make([]byte, 10)
	data[0] = 12 // TransferChecked instruction index
	binary.LittleEndian.PutUint64(data[1:9], amount)
	data[9] = decimals
	return outscript.SolanaInstruction{
		ProgramID: SolanaTokenProgram,
		Accounts: []outscript.SolanaAccountMeta{
			{Pubkey: source, IsSigner: false, IsWritable: true},
			{Pubkey: mint, IsSigner: false, IsWritable: false},
			{Pubkey: destination, IsSigner: false, IsWritable: true},
			{Pubkey: owner, IsSigner: true, IsWritable: false},
		},
		Data: data,
	}
}

func mustParse(s string) outscript.SolanaKey {
	k, err := outscript.ParseSolanaKey(s)
	if err != nil {
		panic(fmt.Errorf("solana: bad constant %q: %w", s, err))
	}
	return k
}
