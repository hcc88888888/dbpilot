package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDiscoveryRuleValidationIsDeclarativeAndRE2Compatible(t *testing.T) {
	rule := Rule{ID: "mysql-native", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, ExecutablePathPatterns: []string{`^/usr/(s?bin|libexec)/mysqld$`}, DefaultPorts: []uint16{3306}}
	require.NoError(t, rule.Validate())

	unsafe := rule
	unsafe.ExecutablePathPatterns = []string{`^(a+)\1$`}
	require.ErrorIs(t, unsafe.Validate(), ErrInvalidRule)
	unsafe = rule
	unsafe.ProcessNames = []string{"mysqld; curl example.invalid"}
	require.ErrorIs(t, unsafe.Validate(), ErrInvalidRule)
}

func TestSignedRuleSetRejectsTamperRollbackAndUnsafeIntervals(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	rules := RuleSet{Revision: 9, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), ScanInterval: 5 * time.Minute, DisappearanceGrace: 10 * time.Minute, Rules: []Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}
	envelope, err := SignRuleSet(privateKey, rules)
	require.NoError(t, err)
	verified, err := VerifyRuleSet(publicKey, envelope, now, 8)
	require.NoError(t, err)
	require.Equal(t, uint64(9), verified.Revision)

	envelope.RuleSet.Rules[0].DatabaseFamily = "oracle"
	_, err = VerifyRuleSet(publicKey, envelope, now, 8)
	require.ErrorIs(t, err, ErrInvalidSignature)

	envelope, err = SignRuleSet(privateKey, rules)
	require.NoError(t, err)
	_, err = VerifyRuleSet(publicKey, envelope, now, 9)
	require.ErrorIs(t, err, ErrRuleRevisionRollback)

	rules.ScanInterval = 30 * time.Second
	_, err = SignRuleSet(privateKey, rules)
	require.ErrorIs(t, err, ErrInvalidRuleSet)
}

func TestSignedRuleSetRejectsNotYetActiveIssuance(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	rules := RuleSet{Revision: 1, IssuedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), ScanInterval: time.Minute, DisappearanceGrace: time.Minute, Rules: []Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}}}}
	envelope, err := SignRuleSet(privateKey, rules)
	require.NoError(t, err)
	_, err = VerifyRuleSet(publicKey, envelope, now, 0)
	require.ErrorIs(t, err, ErrInvalidRuleSet)
}
