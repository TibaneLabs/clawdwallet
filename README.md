# clawdwallet

Agent-side runtime for the **ClawdWallet** TSS custody wallet on Solana. This
binary is the **Agent Process** — the party that holds **Share 1** of a 2-of-3
EdDSA threshold signature, talks to the Policy Evaluator and Owner Mobile
over [Spot](https://github.com/KarpelesLab/spotlib), and builds Solana
transactions that can never be signed without cooperation from at least one
other share holder.

If you are an AI agent reading this to bring up your own wallet, start at
[Quickstart for an AI agent](#quickstart-for-an-ai-agent).

## Build

```sh
go build .
```

## Quickstart for an AI agent

Goal: end with a wallet whose Solana address you control via threshold
signing, paired to your human's mobile app, and reachable from your tool
loop through MCP.

You need **two things from your human** before the wallet exists:

1. They install the **ClawdWallet mobile app** (tibaneapp) and have it open.
2. They are willing to scan one deep-link URL you generate.

You do **not** need to know their mobile's Spot id in advance — pairing
gives it to them via the URL, not the other way around.

### 1. Mint your identity

```sh
clawdwallet init --moniker "<your-agent-name>"
```

This creates `~/.config/clawdwallet/` (or `$CLAWDWALLET_HOME`), generates a
Spot identity keypair, and writes a default config. Running it twice is
harmless — it preserves the existing identity.

After this, `clawdwallet status` shows your Spot id (a `k.<base64url>`
string). You have an identity but no wallet yet — `has_share: false`.

### 2. Stay online

Pairing and keygen both run over Spot, which means the agent process has to
be reachable. In a long-lived terminal:

```sh
clawdwallet daemon
```

Leave it running. Every CLI command below assumes the daemon is up.

### 3. Pair with the human's mobile

In a second terminal:

```sh
clawdwallet pair
```

This prints a single-use URL of the form
`tibane://pair?agent=<your-spot-id>&token=<one-shot>` along with a unicode
QR code rendering of the same URL. Give either to your human — they can
scan the QR from the terminal directly, or you can paste the URL through
whatever channel you share with them. The token is valid for 5 minutes and
dies on first use; if they miss the window, run `pair` again.

When they tap the URL, the mobile verifies you over Spot and the `pair`
command exits with the mobile's Spot id printed. That is your confirmation
that the human is now holding the other end of the handshake. You do not
need to record the mobile's Spot id — phplatform will route the rest.

The wire-level contract for this handshake lives in
[`tibaneapp/docs/clawdwallet-pairing.md`](../tibaneapp/docs/clawdwallet-pairing.md).

### 4. Wait for keygen

After pairing, the human confirms the wallet on the **Create agent wallet**
screen. That triggers `Crypto/WalletSign:newAgent` on phplatform, which in
turn sends a `walletsign/<sid>/init` message to your `daemon`. The daemon
runs the 3-party EdDSA keygen ceremony against the policy evaluator and the
mobile, then writes an encrypted share to disk.

You can either let `daemon` do this in the background, or run
`clawdwallet keygen` in a third terminal which blocks until a share lands
(handy if you want a clean exit code to gate on).

Confirm with:

```sh
clawdwallet status
```

`has_share` should be `true` and `solana_address` should be populated.

### 5. Use the wallet via MCP

For day-to-day operation, plug `clawdwallet mcp` into your tool loop as an
MCP stdio server:

```sh
clawdwallet mcp
```

Tools exposed:

| Tool          | What it does                                                      |
|---------------|-------------------------------------------------------------------|
| `get_address` | Your Solana address (base58)                                      |
| `get_status`  | Spot id, address, lock state, whether a share is present          |
| `get_balance` | SOL balance in lamports; SPL balance lookup is not yet wired      |
| `transfer`    | Build a transfer (SOL or SPL), ask policy, sign via TSS, submit   |
| `pay_x402`    | HTTP request with auto-pay on `402 Payment Required` (CLI only for now — use `clawdwallet x402 <url>`) |

Every `transfer` call goes through the policy evaluator. If the human has
hit the kill switch, or the transfer violates a policy rule (per-tx cap,
daily cap, allowlist), the policy refuses to co-sign and the call returns
an error — your share alone cannot move funds.

## Direct CLI commands

```text
clawdwallet init       Initialise agent identity + write a default config
clawdwallet status     Show identity, address, lock state, balance
clawdwallet daemon     Run the agent in the foreground (accepts Spot msgs)
clawdwallet pair       Print a one-shot tibane:// URL to pair with the mobile
clawdwallet keygen     Block until a server-issued walletsign keygen completes
clawdwallet reshare    Run a reshare ceremony (preserves the wallet address)
clawdwallet balance    SOL balance (and optionally an SPL balance)
clawdwallet send       Build a transfer, ask policy, sign via TSS, submit
clawdwallet x402 <url> Perform an HTTP request that may demand x402 payment
clawdwallet sign       Run a TSS signing round over an arbitrary 32-byte digest
clawdwallet mcp        Speak MCP (JSON-RPC 2.0) on stdio
```

## Module layout

Importable packages — every directory below can be imported by code outside
this repo (no `internal/`):

```text
agent/      runtime: Spot client, TSS session bridge, pairing registry,
            keygen/sign/reshare, transfer + x402 payer
config/     config file shape + load/save
store/      encrypted gobottle holding the TSS share
solana/     JSON-RPC client, TransferChecked instruction,
            MessageBytes / AttachSignature helpers
policy/     policy-evaluator request schema + Spot client
x402/       HTTP 402 client (parses X-PAYMENT-REQUIRED)
mcp/        JSON-RPC 2.0 MCP server over stdin/stdout
```

The repo root holds the binary itself: `main.go` plus one
`<subcommand>.go` per CLI command (all `package main`).

## Spot endpoints served by the agent

spotlib routes inbound messages by the second path segment of the recipient
(`<spot-id>/<endpoint>[/...]`). The agent registers four handlers:

| Endpoint     | Purpose                                                          |
|--------------|------------------------------------------------------------------|
| `walletsign` | TSS-over-Spot: keygen, signing, reshare. `<my-id>/walletsign/<sid>[/init\|broadcast\|single]`. Mirrors wdrone. |
| `pair`       | One-shot pairing handshake with the mobile (see Quickstart §3).  |
| `agent`      | `{"action": "status"}` introspection; reserved for future control actions. |
| `policy`     | Lock/unlock notifications from the policy evaluator.             |
| `owner`      | Reserved; currently returns a "go via policy" notice.            |

## What's wired vs. what isn't

Wired and exercised in unit tests (`go test ./...`):

- Solana address derivation from a 32-byte EdDSA pubkey.
- The `TransferChecked` (index 12) SPL Token instruction, required by the
  x402 "exact" scheme on Solana and not (yet) exported by `outscript`; this
  package fills the gap.
- `MessageBytes` / `AttachSignature` helpers so a TSS-produced signature can
  be attached to a tx without going through `outscript.SolanaTx.Sign`.
- Deterministic `PartyKey` derivation from a Spot identity, so every party
  computes the same canonical ordering.
- Pairing token registry (single-use, 5-minute TTL) + the `pair` Spot
  endpoint, including the four contract error codes.

Wired and ready for a live Spot relay + a real Policy Evaluator + an Owner
Mobile peer, but not yet unit-tested end-to-end:

- Keygen, signing, and reshare ceremonies via `tss-lib/v2`
  `eddsa.{keygen, signing, resharing}.LocalParty`.
- Policy evaluator request envelope (`policy/sign-request`).
- x402 client (parses `X-PAYMENT-REQUIRED`, asks the agent for a signed tx,
  retries with `X-PAYMENT`).
- MCP stdio server with `get_address`, `get_status`, `get_balance`,
  `transfer` tools. `pay_x402` is wired in the CLI but not yet in MCP.

## Threat model reminders for the AI

- You never see the private key. You hold one EdDSA share. Compromising
  your process alone yields nothing signable.
- Your share is stored as an encrypted `gobottle`. The decryption key is
  your Spot identity, which `spotlib` keeps as a PKCS#8 PEM next to the
  config.
- `Locked()` on the agent is advisory. The cryptographic kill switch is the
  **policy evaluator refusing to participate** in the signing round. You
  cannot bypass it by ignoring `Locked()`.
- The pairing URL is the only out-of-band step. Anyone who intercepts the
  URL before the human taps it can pair *their own* mobile to you instead.
  Treat the URL as a short-lived secret — don't post it publicly, and
  prefer a channel only your human reads.
