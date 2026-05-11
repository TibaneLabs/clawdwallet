# clawdwallet

Agent-side CLI for the **ClawdWallet** TSS custody wallet for AI agents on
Solana. The full architecture lives in
[`../hackaton/ARCHITECTURE.md`](../hackaton/ARCHITECTURE.md); this binary is the
"Agent Process" box in that diagram — the party that holds **Share 1** of a
2-of-3 EdDSA threshold signature, talks to the Policy Evaluator and Owner
Mobile over [Spot](https://github.com/KarpelesLab/spotlib), and builds Solana
transactions that can never be signed without cooperation from at least one
other share holder.

## Build

```sh
go build ./cmd/clawdwallet
```

## Commands

```text
clawdwallet init       Initialise agent identity + write a default config
clawdwallet status     Show identity, address, lock state, balance
clawdwallet daemon     Run the agent in the foreground (accepts Spot msgs)
clawdwallet keygen     Initiate (or --join) a 3-party EdDSA TSS keygen
clawdwallet reshare    Run a reshare ceremony (preserves the wallet address)
clawdwallet balance    SOL balance (and optionally an SPL balance)
clawdwallet send       Build a transfer, ask policy, sign via TSS, submit
clawdwallet x402 <url> Perform an HTTP request that may demand x402 payment
clawdwallet sign       Run a TSS signing round over an arbitrary 32-byte digest
clawdwallet mcp        Speak MCP (JSON-RPC 2.0) on stdio
```

## Module layout

```text
cmd/clawdwallet/         CLI entry
internal/cli/            subcommand wiring (one file per command)
internal/agent/          runtime: Spot client, TSS session bridge,
                         keygen/sign/reshare, transfer + x402 payer
internal/config/         ~/.config/clawdwallet/config.json
internal/store/          encrypted gobottle holding the TSS share
internal/solana/         JSON-RPC client, TransferChecked, sig attach helpers
internal/policy/         policy-evaluator Spot client
internal/x402/           HTTP 402 client (parses X-PAYMENT-REQUIRED)
internal/mcp/            JSON-RPC 2.0 MCP server over stdin/stdout
```

## TSS-over-Spot bridge

`spotlib` only routes by the first path segment of an endpoint, so the
architecture's `walletsign/<sid>/init` and `walletsign/<sid>/broadcast` are
multiplexed onto a single `wallet` Spot endpoint. The envelope carries the
sub-action and session id:

```json
{
  "action": "init" | "broadcast",
  "sid": "kg-<uuid>",
  "from": "k.<spot-id>",
  "payload": { ... }
}
```

Per-round `tss.Message` frames are produced on the party's `outCh`, base64'd
into a `BroadcastPayload`, and sent to each peer (`SendTo(target, body)` with
`target = "<spotID>/wallet"`). Inbound frames are routed back into
`Party.UpdateFromBytes` via the session registry.

## What's wired vs. what isn't

Wired and exercised in unit tests (`go test ./...`):

- Solana address derivation from a 32-byte EdDSA pubkey.
- The `TransferChecked` (index 12) instruction — the architecture flags this
  as a required gap in `outscript`; this package fills it.
- `MessageBytes` / `AttachSignature` helpers so a TSS-produced signature can be
  attached to a tx without going through `outscript.SolanaTx.Sign` (which
  requires the private key directly).
- Deterministic `PartyKey` derivation from a Spot identity, so every party
  computes the same canonical ordering.

Wired and ready for a live Spot relay + a real Policy Evaluator + an Owner Mobile
peer, but not unit-tested in this hackathon cut:

- Keygen, signing, and reshare ceremonies via `tss-lib/v2` `eddsa.{keygen,
  signing, resharing}.LocalParty`.
- Policy evaluator request envelope (`policy/sign-request` schema from the
  architecture doc).
- x402 client (parses `X-PAYMENT-REQUIRED`, asks the agent for a signed tx,
  retries with `X-PAYMENT`).
- MCP stdio server with `get_address`, `get_status`, `get_balance`, `transfer`,
  `pay_x402` tools.

## Threat model reminders

- The agent process never sees the private key — it only holds one EdDSA
  share. Compromising the agent process alone yields nothing signable.
- The TSS share is stored as an encrypted `gobottle`. The decryption key is the
  agent's Spot identity, which `spotlib` keeps as a PKCS#8 PEM next to the
  config.
- `Locked()` on the agent is advisory; the cryptographic kill switch is the
  policy evaluator refusing to participate in the signing round.
- Skill manifests are *owner-signed* documents stored as Spot blobs; the agent
  never modifies them locally.
