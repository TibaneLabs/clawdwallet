// Package mcp implements a minimal Model Context Protocol server over stdio.
//
// The server speaks JSON-RPC 2.0 with newline-framed messages on stdin/stdout.
// It exposes a small set of tools that wrap the agent's high-level operations
// so an LLM host (Claude, etc.) can drive the wallet.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/policy"
)

const (
	protocolVersion = "2025-06-18"
	serverName      = "clawdwallet"
	serverVersion   = "0.1.0"
)

// Server is the stdio MCP server.
type Server struct {
	A     *agent.Agent
	In    io.Reader
	Out   io.Writer
	mu    sync.Mutex // serializes writes
	tools []toolSpec
}

// New returns a Server with the default tool set bound to a.
func New(a *agent.Agent) *Server {
	s := &Server{A: a, In: os.Stdin, Out: os.Stdout}
	s.tools = s.buildTools()
	return s
}

// Serve reads requests until stdin closes. Returns the first I/O error.
func (s *Server) Serve(ctx context.Context) error {
	r := bufio.NewReader(s.In)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(line) > 0 {
			go s.handle(ctx, line)
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// rpcRequest matches the JSON-RPC 2.0 request envelope.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcResponse / rpcError mirror the JSON-RPC 2.0 response envelopes.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (s *Server) write(resp *rpcResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = s.Out.Write(b)
}

func (s *Server) handle(ctx context.Context, line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(&rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	// Notifications carry no id and expect no response.
	notif := len(req.ID) == 0 || string(req.ID) == "null"

	resp := &rpcResponse{JSONRPC: "2.0", ID: req.ID}
	var (
		result any
		rerr   *rpcError
	)
	switch req.Method {
	case "initialize":
		result = s.initialize()
	case "notifications/initialized", "initialized":
		// no-op
	case "tools/list":
		result = s.toolsList()
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			rerr = &rpcError{Code: -32602, Message: "invalid params"}
		} else {
			result, rerr = s.toolsCall(ctx, params.Name, params.Arguments)
		}
	case "ping":
		result = map[string]any{}
	case "shutdown":
		result = map[string]any{}
	default:
		rerr = &rpcError{Code: -32601, Message: "method not found"}
	}
	if notif {
		return
	}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	s.write(resp)
}

func (s *Server) initialize() any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"serverInfo": map[string]any{
			"name":    serverName,
			"version": serverVersion,
		},
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
	}
}

// toolSpec describes one MCP tool.
type toolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Run         func(ctx context.Context, args json.RawMessage) (any, error)
}

func (s *Server) toolsList() any {
	specs := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		specs = append(specs, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return map[string]any{"tools": specs}
}

func (s *Server) toolsCall(ctx context.Context, name string, args json.RawMessage) (any, *rpcError) {
	for _, t := range s.tools {
		if t.Name != name {
			continue
		}
		v, err := t.Run(ctx, args)
		if err != nil {
			return map[string]any{
				"isError": true,
				"content": []map[string]any{
					{"type": "text", "text": err.Error()},
				},
			}, nil
		}
		// MCP tool response: content is a list of content blocks.
		text, _ := json.Marshal(v)
		return map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": string(text)},
			},
		}, nil
	}
	return nil, &rpcError{Code: -32601, Message: fmt.Sprintf("tool %q not found", name)}
}

// --- tool implementations ----------------------------------------------------

func (s *Server) buildTools() []toolSpec {
	a := s.A
	return []toolSpec{
		{
			Name:        "get_address",
			Description: "Return the Solana address controlled by this wallet.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ json.RawMessage) (any, error) {
				return map[string]any{"address": a.SolanaAddress()}, nil
			},
		},
		{
			Name:        "get_status",
			Description: "Return the agent's current status: identity, address, lock state, etc.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ json.RawMessage) (any, error) {
				return map[string]any{
					"spot_id":        a.SpotID(),
					"solana_address": a.SolanaAddress(),
					"locked":         a.Locked(),
					"has_share":      a.Share() != nil,
					"moniker":        a.Config().Moniker,
				}, nil
			},
		},
		{
			Name:        "get_balance",
			Description: "Return the wallet's SOL balance (in lamports). If 'mint' is given, return that SPL balance instead.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"mint": map[string]any{"type": "string"},
				},
			},
			Run: func(ctx context.Context, args json.RawMessage) (any, error) {
				var in struct{ Mint string `json:"mint"` }
				_ = json.Unmarshal(args, &in)
				addr := a.SolanaAddress()
				if in.Mint == "" {
					lamports, err := a.RPC().GetBalance(ctx, addr)
					if err != nil {
						return nil, err
					}
					return map[string]any{"lamports": lamports, "sol": float64(lamports) / 1e9}, nil
				}
				return nil, fmt.Errorf("SPL balance via mint lookup not yet implemented; query the ATA directly")
			},
		},
		{
			Name:        "transfer",
			Description: "Transfer SOL or an SPL token. Required: to, amount. For SPL: also mint and decimals.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to":          map[string]any{"type": "string", "description": "destination address (base58)"},
					"amount":      map[string]any{"type": "integer", "description": "amount in base units"},
					"mint":        map[string]any{"type": "string", "description": "optional SPL mint"},
					"decimals":    map[string]any{"type": "integer", "description": "required for SPL"},
					"description": map[string]any{"type": "string", "description": "human-readable intent"},
					"reason":      map[string]any{"type": "string", "description": "why this transfer"},
					"skill":       map[string]any{"type": "string"},
				},
				"required": []string{"to", "amount"},
			},
			Run: func(ctx context.Context, args json.RawMessage) (any, error) {
				var in struct {
					To          string `json:"to"`
					Amount      uint64 `json:"amount"`
					Mint        string `json:"mint"`
					Decimals    uint8  `json:"decimals"`
					Description string `json:"description"`
					Reason      string `json:"reason"`
					Skill       string `json:"skill"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, err
				}
				sig, err := a.BuildAndPay(ctx, agent.TransferOptions{
					To:       in.To,
					Mint:     in.Mint,
					Amount:   in.Amount,
					Decimals: in.Decimals,
					Intent: policy.Intent{
						Description: in.Description,
						Skill:       in.Skill,
						Reason:      in.Reason,
					},
				})
				if err != nil {
					return nil, err
				}
				return map[string]any{"signature": sig}, nil
			},
		},
		{
			Name:        "pay_x402",
			Description: "Perform an HTTP request that may return 402 Payment Required. Pays automatically if the endpoint demands USDC.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url":    map[string]any{"type": "string"},
					"method": map[string]any{"type": "string", "default": "GET"},
				},
				"required": []string{"url"},
			},
			Run: func(ctx context.Context, args json.RawMessage) (any, error) {
				return nil, fmt.Errorf("pay_x402 not wired into MCP; use the `clawdwallet x402` CLI subcommand")
			},
		},
	}
}
