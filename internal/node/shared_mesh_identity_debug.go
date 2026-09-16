//go:build sam_debug

package node

import (
	"context"
	"crypto/ed25519"
	"fmt"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/peer"
)

// StartSharedMesh verifies the stored identity and uses proof-of-possession
// refresh when needed. Rejection returns to the app; it cannot reach the CLI's
// process-exiting recovery or fallback enrollment, even if verification times out.
func (n *SamNode) StartSharedMesh(ctx context.Context) error {
	if err := n.prepareSharedMeshIdentity(ctx); err != nil {
		return err
	}
	return n.start(ctx, false)
}

func (n *SamNode) prepareSharedMeshIdentity(ctx context.Context) error {
	token := n.GetIdentity()
	if _, err := biscuit.Unmarshal(token); err != nil {
		return fmt.Errorf("malformed stored identity: %w", err)
	}
	id, err := peer.IDFromPrivateKey(n.config.PrivKey)
	if err != nil {
		return err
	}
	n.keysMu.RLock()
	keys := make([]ed25519.PublicKey, 0, len(n.trustedKeys))
	for _, tk := range n.trustedKeys {
		keys = append(keys, tk.Key)
	}
	n.keysMu.RUnlock()
	verify := func(token []byte) error {
		b, key, err := identity.VerifyBiscuitAndGetKey(token, id, keys, n.BiscuitTimeout)
		if err != nil {
			return err
		}
		return identity.RequireRole(b, key, n.config.RequiredRole, n.BiscuitTimeout)
	}
	if err := verify(token); err == nil {
		return nil
	}
	if err := n.refreshEnrollment(ctx, false, verify); err != nil {
		return fmt.Errorf("stored mesh identity refresh rejected: %w", err)
	}
	return nil
}
