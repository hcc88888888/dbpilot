package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var errMissingVerifiedIdentity = errors.New("verified Agent identity is required")

const spiffeTrustDomain = "dbpilot.local"

func verifiedAgentID(ctx context.Context) (string, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.AuthInfo == nil {
		return "", errMissingVerifiedIdentity
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errMissingVerifiedIdentity
	}
	return spiffeAgentFromTLS(tlsInfo.State)
}

func verifiedAgentCredential(ctx context.Context, expectedAgentID string) ([sha256.Size]byte, string, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.AuthInfo == nil {
		return [sha256.Size]byte{}, "", errMissingVerifiedIdentity
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return [sha256.Size]byte{}, "", errMissingVerifiedIdentity
	}
	return credentialFromTLSState(tlsInfo.State, expectedAgentID)
}

func credentialFromTLSState(state tls.ConnectionState, expectedAgentID string) ([sha256.Size]byte, string, error) {
	agentID, err := spiffeAgentFromTLS(state)
	if len(state.PeerCertificates) == 0 {
		return [sha256.Size]byte{}, "", errMissingVerifiedIdentity
	}
	leaf := state.PeerCertificates[0]
	if err != nil || agentID != expectedAgentID || leaf == nil || len(leaf.Raw) == 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return [sha256.Size]byte{}, "", errMissingVerifiedIdentity
	}
	return sha256.Sum256(leaf.Raw), leaf.SerialNumber.Text(16), nil
}

func spiffeAgentFromTLS(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", errMissingVerifiedIdentity
	}
	var identity *url.URL
	for _, uri := range state.PeerCertificates[0].URIs {
		if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") {
			continue
		}
		if identity != nil {
			return "", fmt.Errorf("%w: exactly one SPIFFE URI SAN is required", errMissingVerifiedIdentity)
		}
		identity = uri
	}
	if identity == nil {
		return "", fmt.Errorf("%w: SPIFFE URI SAN is absent", errMissingVerifiedIdentity)
	}
	if identity.Host != spiffeTrustDomain || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" {
		return "", fmt.Errorf("%w: SPIFFE trust domain is invalid", errMissingVerifiedIdentity)
	}
	const prefix = "/agent/"
	if !strings.HasPrefix(identity.Path, prefix) {
		return "", fmt.Errorf("%w: SPIFFE Agent path is invalid", errMissingVerifiedIdentity)
	}
	agentID := strings.TrimPrefix(identity.Path, prefix)
	if agentID == "" || agentID != strings.TrimSpace(agentID) || strings.Contains(agentID, "/") {
		return "", fmt.Errorf("%w: SPIFFE Agent ID is invalid", errMissingVerifiedIdentity)
	}
	return agentID, nil
}
