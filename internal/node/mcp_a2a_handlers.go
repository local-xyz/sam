// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

// A2A agents as MCP tools, ported from cmd/sam-a2a-bridge so that any MCP
// client of a node (a host harness or the mobile FFI node's in-app agent) can
// talk to mesh A2A agents without a second binary. Unlike the bridge, which
// round-trips through the sidecar's /sam/<peer>/a2a/<service> route over
// loopback, these handlers take the same in-process path the egress proxy
// does: labels gate, biscuit header, then HTTP over a libp2p stream to the
// peer. That is what makes them work identically on a socket-only host node
// and on the FFI node.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/google/sam/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// a2aCardTimeout and a2aCallTimeout mirror the bridge's HTTP client timeouts.
	a2aCardTimeout = 30 * time.Second
	a2aCallTimeout = 60 * time.Second
	// a2aStateMessage is the synthetic state reported when an agent answers
	// with a direct Message instead of a Task.
	a2aStateMessage = "message"
)

// GetAgentCardParams defines the parameters for the get_agent_card tool.
type GetAgentCardParams struct {
	PeerID  string `json:"peer_id" jsonschema:"Peer ID of the node hosting the agent, as returned by discover_remote_services with type a2a"`
	Service string `json:"service" jsonschema:"Name of the a2a service registered on that peer"`
}

// SendAgentTaskParams defines the parameters for the send_agent_task tool.
type SendAgentTaskParams struct {
	PeerID         string `json:"peer_id" jsonschema:"Peer ID of the node hosting the agent"`
	Service        string `json:"service" jsonschema:"Name of the a2a service registered on that peer"`
	Message        string `json:"message" jsonschema:"Plain-text message for the agent"`
	ContextID      string `json:"context_id,omitempty" jsonschema:"Continue an existing conversation: pass the context_id returned by an earlier send_agent_task call"`
	TaskID         string `json:"task_id,omitempty" jsonschema:"Reply into an existing task, e.g. one whose state is TASK_STATE_INPUT_REQUIRED"`
	RequiredLabels string `json:"required_labels,omitempty" jsonschema:"Comma-separated key=value labels the provider must have attested (e.g. region=eu-west-1). Fails closed: nothing is sent unless the peer attests one of them. Empty means no requirement."`
}

// GetAgentTaskParams defines the parameters for the get_agent_task tool.
type GetAgentTaskParams struct {
	PeerID  string `json:"peer_id" jsonschema:"Peer ID of the node hosting the agent"`
	Service string `json:"service" jsonschema:"Name of the a2a service registered on that peer"`
	TaskID  string `json:"task_id" jsonschema:"ID of the task to fetch, as returned by send_agent_task"`
}

// agentTaskResult is the flattened send_agent_task response: the reply text a
// model can read directly, plus the ids it needs for follow-ups.
type agentTaskResult struct {
	Reply     string `json:"reply"`
	ContextID string `json:"context_id"`
	TaskID    string `json:"task_id"`
	State     string `json:"state"`
}

// handleGetAgentCard implements the get_agent_card tool.
func (n *SamNode) handleGetAgentCard(ctx context.Context, req *mcp.CallToolRequest, params GetAgentCardParams) (*mcp.CallToolResult, any, error) {
	logger.Infof("[MCP] get_agent_card called for peer %s, service %s", params.PeerID, params.Service)
	target, err := n.newA2AEgress(ctx, params.PeerID, params.Service, "")
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, a2aCardTimeout)
	defer cancel()
	card, err := target.fetchCard(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(card)
	if err != nil {
		return nil, nil, err
	}
	return textResult(string(out)), nil, nil
}

// handleSendAgentTask implements the send_agent_task tool.
func (n *SamNode) handleSendAgentTask(ctx context.Context, req *mcp.CallToolRequest, params SendAgentTaskParams) (*mcp.CallToolResult, any, error) {
	logger.Infof("[MCP] send_agent_task called for peer %s, service %s", params.PeerID, params.Service)
	if strings.TrimSpace(params.Message) == "" {
		return nil, nil, fmt.Errorf("message is required")
	}
	target, err := n.newA2AEgress(ctx, params.PeerID, params.Service, params.RequiredLabels)
	if err != nil {
		return nil, nil, err
	}
	client, err := target.client(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = client.Destroy() }()

	part := a2a.NewTextPart(params.Message)
	var msg *a2a.Message
	if params.TaskID != "" || params.ContextID != "" {
		msg = a2a.NewMessageForTask(a2a.MessageRoleUser,
			a2a.TaskInfo{TaskID: a2a.TaskID(params.TaskID), ContextID: params.ContextID}, part)
	} else {
		msg = a2a.NewMessage(a2a.MessageRoleUser, part)
	}
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		return nil, nil, fmt.Errorf("send message to %s/%s: %w", params.PeerID, params.Service, err)
	}
	out, err := json.Marshal(toAgentTaskResult(result))
	if err != nil {
		return nil, nil, err
	}
	return textResult(string(out)), nil, nil
}

// handleGetAgentTask implements the get_agent_task tool.
func (n *SamNode) handleGetAgentTask(ctx context.Context, req *mcp.CallToolRequest, params GetAgentTaskParams) (*mcp.CallToolResult, any, error) {
	logger.Infof("[MCP] get_agent_task called for peer %s, service %s, task %s", params.PeerID, params.Service, params.TaskID)
	if params.TaskID == "" {
		return nil, nil, fmt.Errorf("task_id is required")
	}
	target, err := n.newA2AEgress(ctx, params.PeerID, params.Service, "")
	if err != nil {
		return nil, nil, err
	}
	client, err := target.client(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = client.Destroy() }()

	task, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: a2a.TaskID(params.TaskID)})
	if err != nil {
		return nil, nil, fmt.Errorf("get task %s from %s/%s: %w", params.TaskID, params.PeerID, params.Service, err)
	}
	out, err := json.Marshal(task)
	if err != nil {
		return nil, nil, err
	}
	return textResult(string(out)), nil, nil
}

// toAgentTaskResult flattens the SDK's Message|Task union the way the bridge
// does: a direct Message reply is its text parts; a Task is its status
// message's text, falling back to the text of its artifacts.
func toAgentTaskResult(result a2a.SendMessageResult) agentTaskResult {
	switch v := result.(type) {
	case *a2a.Message:
		return agentTaskResult{
			Reply:     a2aTextOf(v.Parts),
			ContextID: v.ContextID,
			TaskID:    string(v.TaskID),
			State:     a2aStateMessage,
		}
	case *a2a.Task:
		out := agentTaskResult{TaskID: string(v.ID), ContextID: v.ContextID, State: string(v.Status.State)}
		if v.Status.Message != nil {
			out.Reply = a2aTextOf(v.Status.Message.Parts)
		}
		if out.Reply == "" {
			var texts []string
			for _, artifact := range v.Artifacts {
				if s := a2aTextOf(artifact.Parts); s != "" {
					texts = append(texts, s)
				}
			}
			out.Reply = strings.Join(texts, "\n")
		}
		return out
	}
	return agentTaskResult{}
}

// a2aTextOf joins the text of every text part with newlines.
func a2aTextOf(parts a2a.ContentParts) string {
	var texts []string
	for _, part := range parts {
		if s := part.Text(); s != "" {
			texts = append(texts, s)
		}
	}
	return strings.Join(texts, "\n")
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// a2aEgress is one gated, in-process route to a remote A2A service: the peer
// has passed the labels gate and the node's biscuit is ready to be attached.
type a2aEgress struct {
	node    *SamNode
	route   egressRoute
	pid     peer.ID
	biscuit string
}

// newA2AEgress runs the checks createEgressProxy and a2aEgressGate perform
// on a sidecar request, in the same order, before anything leaves the node:
// the caller's required labels and the operator's egress floor are verified
// against the peer's control-plane-signed biscuit (fail-closed), and the
// node's own identity must be loadable to authenticate the stream.
func (n *SamNode) newA2AEgress(ctx context.Context, peerID, service, requiredLabels string) (*a2aEgress, error) {
	if n == nil || n.Host == nil {
		return nil, fmt.Errorf("node not initialized")
	}
	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("invalid peer_id %q: %w", peerID, err)
	}
	if service == "" || strings.Contains(service, "/") {
		return nil, fmt.Errorf("invalid service name %q", service)
	}
	required, err := parseRequiredLabels(requiredLabels)
	if err != nil {
		return nil, fmt.Errorf("invalid required_labels: %w", err)
	}
	biscuitBytes := n.GetIdentity()
	if biscuitBytes == nil {
		return nil, fmt.Errorf("node identity unavailable; is this node enrolled?")
	}

	ctx = allowLimitedEgressConn(ctx)
	n.prepareEgressPeer(ctx, pid.String())
	if err := n.VerifyPeerLabels(ctx, pid, required); err != nil {
		logger.Warnf("[A2A] label gate refused egress to %s: %v", pid, err)
		switch {
		case len(required) > 0:
			return nil, fmt.Errorf("required labels not attested by provider %s: %w", pid, err)
		case len(n.egressFloor()) > 0:
			return nil, fmt.Errorf("provider %s does not attest the egress floor: %w", pid, err)
		default:
			return nil, fmt.Errorf("destination %s is not an enrolled peer: %w", pid, err)
		}
	}
	return &a2aEgress{
		node:    n,
		route:   egressRoute{peerID: pid.String(), serviceType: api.ServiceTypeStringA2A, serviceName: service},
		pid:     pid,
		biscuit: base64.StdEncoding.EncodeToString(biscuitBytes),
	}, nil
}

// transport returns the RoundTripper the egress proxy would use for this
// peer, wrapped so every request carries the egress headers.
func (e *a2aEgress) transport() http.RoundTripper {
	return &a2aMeshTransport{base: libp2phttp.NewTransport(e.node.Host), egress: e}
}

// endpoint is the libp2p URL of the service root, where the JSON-RPC
// binding is served (createEgressProxy's Director rewrites /sam/<peer>/a2a/<svc>
// to exactly this).
func (e *a2aEgress) endpoint() string {
	return fmt.Sprintf("libp2p://%s/%s/%s", e.route.peerID, e.route.serviceType, url.PathEscape(e.route.serviceName))
}

// client builds an a2a-go JSON-RPC client bound to the mesh transport. No
// card is fetched: the endpoint is known, so this costs no extra round trip.
func (e *a2aEgress) client(ctx context.Context) (*a2aclient.Client, error) {
	httpClient := &http.Client{Timeout: a2aCallTimeout, Transport: e.transport()}
	client, err := a2aclient.NewFromEndpoints(ctx,
		[]*a2a.AgentInterface{a2a.NewAgentInterface(e.endpoint(), a2a.TransportProtocolJSONRPC)},
		a2aclient.WithJSONRPCTransport(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("a2a client for %s/%s: %w", e.route.peerID, e.route.serviceName, err)
	}
	return client, nil
}

// fetchCard fetches the remote agent card and regenerates it for the mesh the
// same way a2aServeAgentCard does, so the returned card names this node's
// proxy path as the agent's interface.
func (e *a2aEgress) fetchCard(ctx context.Context) (*a2a.AgentCard, error) {
	// fetchRemoteAgentCard copies the egress headers from an inbound request;
	// synthesize the one createEgressProxy would have prepared.
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(api.HeaderSamBiscuit, e.biscuit)
	resp, err := fetchRemoteAgentCard(e.node, libp2phttp.NewTransport(e.node.Host), r, e.route)
	if err != nil {
		return nil, fmt.Errorf("agent card fetch from %s/%s failed: %w", e.route.peerID, e.route.serviceName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := io.LimitReader(resp.Body, maxAgentCardBytes)
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(body, 4096))
		return nil, fmt.Errorf("agent card of %s/%s: %s: %s", e.route.peerID, e.route.serviceName, resp.Status, strings.TrimSpace(string(msg)))
	}
	var card a2a.AgentCard
	if err := json.NewDecoder(body).Decode(&card); err != nil {
		return nil, fmt.Errorf("agent card from %s/%s is not valid JSON: %w", e.route.peerID, e.route.serviceName, err)
	}
	base := e.node.localProxyURL(e.pid, e.route.serviceType, e.route.serviceName)
	if err := regenerateAgentCardForMesh(&card, base); err != nil {
		return nil, fmt.Errorf("agent card from %s/%s unusable through the mesh: %w", e.route.peerID, e.route.serviceName, err)
	}
	return &card, nil
}

// a2aMeshTransport attaches the egress headers createEgressProxy sets on a
// proxied request and surfaces non-2xx replies as errors carrying the body,
// so a refusal from the peer (policy denial, unknown service) reaches the
// model verbatim instead of as "unexpected HTTP status".
type a2aMeshTransport struct {
	base   http.RoundTripper
	egress *a2aEgress
}

func (t *a2aMeshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(allowLimitedEgressConn(req.Context()))
	req.Host = t.egress.route.peerID
	req.Header.Set(api.HeaderSamBiscuit, t.egress.biscuit)
	// Local gate headers never travel off-node.
	req.Header.Del(api.HeaderSamAuthentication)
	req.Header.Del(api.HeaderSamRequiredLabels)
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}
