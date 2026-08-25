package policy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
)

func validPolicy(source policy.Source) policy.Policy {
	return policy.Policy{
		AgentID:   "agent-01",
		Version:   2,
		IssuedAt:  time.Now().Add(-time.Minute).UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Sources:   []policy.Source{source},
		Limits: policy.Limits{
			MaxSpoolBytes:   1024,
			MaxBatchBytes:   512,
			MaxEventsPerSec: 10,
		},
	}
}

func fileSource(path string) policy.Source {
	return policy.Source{ID: "application-log", Kind: policy.SourceFileLog, Path: path, Interval: 5 * time.Second}
}

func testEnvironment(resolve func(string) (string, error)) policy.ValidationEnvironment {
	return policy.ValidationEnvironment{
		AllowedRoots:   []string{"/var/log/app"},
		ForbiddenRoots: []string{"/proc", "/sys"},
		PluginIDs:      map[string]struct{}{"postgres": {}},
		PluginDefinitions: map[string]policy.PluginDefinition{
			"postgres": {Parameters: map[string]policy.ParameterSchema{
				"database": {MaxLength: 32, ValuePattern: "^[a-z][a-z0-9_]{0,31}$"},
				"timeout":  {MaxLength: 8, ValuePattern: "^[0-9]+s$"},
			}},
		},
		ResolvePath: resolve,
	}
}

func TestValidateAcceptsFileSourceWithinAllowedRoot(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	if err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil })); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// A platform-native absolute path is required for the embedded file receiver
// to run on the Agent's host operating system.
func TestValidateStructuralAcceptsNativeAbsoluteFilePath(t *testing.T) {
	p := validPolicy(fileSource(filepath.Join(t.TempDir(), "application.log")))
	if err := policy.ValidateStructural(p); err != nil {
		t.Fatalf("ValidateStructural() error = %v", err)
	}
}

func TestValidateRejectsPathTraversal(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/../secrets.log"))
	err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil }))
	if !errors.Is(err, policy.ErrPathTraversal) {
		t.Fatalf("Validate() error = %v, want ErrPathTraversal", err)
	}
}

func TestValidateRejectsResolvedPathOutsideAllowRoot(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	env := testEnvironment(func(string) (string, error) { return "/etc/shadow", nil })
	if err := policy.Validate(p, env); !errors.Is(err, policy.ErrPathOutsideAllowRoots) {
		t.Fatalf("Validate() error = %v, want ErrPathOutsideAllowRoots", err)
	}
}

func TestValidateRejectsProcPath(t *testing.T) {
	p := validPolicy(fileSource("/proc/self/status"))
	err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil }))
	if !errors.Is(err, policy.ErrForbiddenPath) {
		t.Fatalf("Validate() error = %v, want ErrForbiddenPath", err)
	}
}

func TestValidateRejectsRawOtelAndVectorKinds(t *testing.T) {
	for _, kind := range []policy.SourceKind{"OTEL", "VECTOR"} {
		t.Run(string(kind), func(t *testing.T) {
			p := validPolicy(fileSource("/var/log/app/current.log"))
			p.Sources[0].Kind = kind
			err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil }))
			if !errors.Is(err, policy.ErrSourceKindNotAllowed) {
				t.Fatalf("Validate() error = %v, want ErrSourceKindNotAllowed", err)
			}
		})
	}
}

func TestValidateRejectsDuplicateSourceIDs(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	p.Sources = append(p.Sources, fileSource("/var/log/app/other.log"))
	err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil }))
	if !errors.Is(err, policy.ErrDuplicateSourceID) {
		t.Fatalf("Validate() error = %v, want ErrDuplicateSourceID", err)
	}
}

func TestValidateRejectsZeroOrNegativeLimits(t *testing.T) {
	for _, value := range []int64{0, -1} {
		t.Run("max spool", func(t *testing.T) {
			p := validPolicy(fileSource("/var/log/app/current.log"))
			p.Limits.MaxSpoolBytes = value
			err := policy.Validate(p, testEnvironment(func(path string) (string, error) { return path, nil }))
			if !errors.Is(err, policy.ErrInvalidLimits) {
				t.Fatalf("Validate() error = %v, want ErrInvalidLimits", err)
			}
		})
	}
}

func TestVerifyRejectsPolicyMutation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.Sign(priv, validPolicy(fileSource("/var/log/app/app.log")))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	envelope.Policy.Limits.MaxSpoolBytes++
	_, err = policy.Verify(pub, envelope, time.Now())
	if !errors.Is(err, policy.ErrInvalidSignature) {
		t.Fatalf("Verify() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsExpiredPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(fileSource("/var/log/app/app.log"))
	p.ExpiresAt = time.Now().Add(-time.Second)
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	_, err = policy.Verify(pub, envelope, time.Now())
	if !errors.Is(err, policy.ErrExpiredPolicy) {
		t.Fatalf("Verify() error = %v, want ErrExpiredPolicy", err)
	}
}

func TestVerifyRejectsVersionRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(fileSource("/var/log/app/app.log"))
	p.Version = 0
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	_, err = policy.Verify(pub, envelope, time.Now())
	if !errors.Is(err, policy.ErrPolicyVersionRollback) {
		t.Fatalf("Verify() error = %v, want ErrPolicyVersionRollback", err)
	}
}

func TestVerifyAcceptsSignedPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(fileSource("/var/log/app/app.log"))
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	got, err := policy.Verify(pub, envelope, time.Now())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got.AgentID != p.AgentID || got.Version != p.Version {
		t.Fatalf("Verify() = %+v, want agent %q version %d", got, p.AgentID, p.Version)
	}
}

func TestVerifyAndValidateRejectsResolvedSymlinkEscape(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.Sign(priv, validPolicy(fileSource("/var/log/app/current.log")))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	env := testEnvironment(func(string) (string, error) { return "/etc/shadow", nil })
	_, err = policy.VerifyAndValidate(pub, envelope, time.Now(), env)
	if !errors.Is(err, policy.ErrPathOutsideAllowRoots) {
		t.Fatalf("VerifyAndValidate() error = %v, want ErrPathOutsideAllowRoots", err)
	}
}

func TestVerifyAndValidateAcceptsRegisteredPlugin(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(policy.Source{
		ID: "postgres-plugin", Kind: policy.SourcePluginMetrics, PluginID: "postgres",
		Params: map[string]string{"database": "app", "timeout": "5s"}, Interval: 5 * time.Second,
	})
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	got, err := policy.VerifyAndValidate(pub, envelope, time.Now(), testEnvironment(nil))
	if err != nil {
		t.Fatalf("VerifyAndValidate() error = %v", err)
	}
	if got.Sources[0].PluginID != "postgres" {
		t.Fatalf("VerifyAndValidate() plugin = %q, want postgres", got.Sources[0].PluginID)
	}
}

func TestVerifyAndValidateRejectsVersionAtOrBelowPersistedVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(fileSource("/var/log/app/current.log"))
	p.Version = 7
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	env := testEnvironment(func(path string) (string, error) { return path, nil })
	env.PreviousVersion = 7
	_, err = policy.VerifyAndValidate(pub, envelope, time.Now(), env)
	if !errors.Is(err, policy.ErrPolicyVersionRollback) {
		t.Fatalf("VerifyAndValidate() error = %v, want ErrPolicyVersionRollback", err)
	}
}

func TestValidateRejectsExecutablePluginParameters(t *testing.T) {
	for name, params := range map[string]map[string]string{
		"command key":     {"command": "curl https://attacker.invalid"},
		"shell expansion": {"database": "$(whoami)"},
	} {
		t.Run(name, func(t *testing.T) {
			p := validPolicy(policy.Source{
				ID: "postgres-plugin", Kind: policy.SourcePluginMetrics, PluginID: "postgres",
				Params: params, Interval: 5 * time.Second,
			})
			err := policy.Validate(p, testEnvironment(nil))
			if !errors.Is(err, policy.ErrUnsafePluginParameter) {
				t.Fatalf("Validate() error = %v, want ErrUnsafePluginParameter", err)
			}
		})
	}
}

func TestValidateAllowsRootDirectory(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	env := testEnvironment(func(path string) (string, error) { return path, nil })
	env.AllowedRoots = []string{"/"}
	if err := policy.Validate(p, env); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsPathResolutionError(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	env := testEnvironment(func(string) (string, error) { return "", errors.New("permission denied") })
	err := policy.Validate(p, env)
	if !errors.Is(err, policy.ErrPathResolution) {
		t.Fatalf("Validate() error = %v, want ErrPathResolution", err)
	}
}

func TestValidateRejectsFileSourceWithoutPathResolver(t *testing.T) {
	p := validPolicy(fileSource("/var/log/app/current.log"))
	env := testEnvironment(nil)
	err := policy.Validate(p, env)
	if !errors.Is(err, policy.ErrPathResolution) {
		t.Fatalf("Validate() error = %v, want ErrPathResolution", err)
	}
}

func TestVerifyAcceptsStructurallyValidPluginPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := validPolicy(policy.Source{
		ID: "postgres-plugin", Kind: policy.SourcePluginMetrics, PluginID: "postgres",
		Params: map[string]string{"database": "app"}, Interval: 5 * time.Second,
	})
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := policy.Verify(pub, envelope, time.Now()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyAndValidatePersistsAndRejectsVersionRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(t.TempDir(), "versions.json")
	store, err := policy.OpenVersionStore(storePath)
	if err != nil {
		t.Fatalf("OpenVersionStore() error = %v", err)
	}
	p := validPolicy(fileSource("/var/log/app/current.log"))
	p.Version = 8
	envelope, err := policy.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	env := testEnvironment(func(path string) (string, error) { return path, nil })
	env.VersionStore = store
	if _, err := policy.VerifyAndValidate(pub, envelope, time.Now(), env); err != nil {
		t.Fatalf("first VerifyAndValidate() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := policy.OpenVersionStore(storePath)
	if err != nil {
		t.Fatalf("reopen version store: %v", err)
	}
	defer reopened.Close()
	env.VersionStore = reopened
	_, err = policy.VerifyAndValidate(pub, envelope, time.Now(), env)
	if !errors.Is(err, policy.ErrPolicyVersionRollback) {
		t.Fatalf("second VerifyAndValidate() error = %v, want ErrPolicyVersionRollback", err)
	}
}

func TestVerifyAndValidateEnforcesPluginParameterSchema(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvironment(nil)
	env.PluginDefinitions = map[string]policy.PluginDefinition{
		"postgres": {Parameters: map[string]policy.ParameterSchema{
			"database": {MaxLength: 32, ValuePattern: "^[a-z][a-z0-9_]{0,31}$"},
		}},
	}
	for name, value := range map[string]string{"declarative": "app_01", "network command": "curl https://attacker.invalid"} {
		t.Run(name, func(t *testing.T) {
			p := validPolicy(policy.Source{
				ID: "postgres-plugin", Kind: policy.SourcePluginMetrics, PluginID: "postgres",
				Params: map[string]string{"database": value}, Interval: 5 * time.Second,
			})
			envelope, err := policy.Sign(priv, p)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			_, err = policy.VerifyAndValidate(pub, envelope, time.Now(), env)
			if name == "declarative" && err != nil {
				t.Fatalf("VerifyAndValidate() error = %v", err)
			}
			if name == "network command" && !errors.Is(err, policy.ErrUnsafePluginParameter) {
				t.Fatalf("VerifyAndValidate() error = %v, want ErrUnsafePluginParameter", err)
			}
		})
	}
}
