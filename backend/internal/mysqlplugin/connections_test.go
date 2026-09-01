package mysqlplugin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRuntimeAtomicallySwapsTwoInstancePoolsAndClosesOldPools(t *testing.T) {
	factory := &fakePoolFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	first := Config{AssignmentID: "assignment-a", Revision: 1, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "one"), fixtureDecodedInstance("mysql-b", "two")}}
	require.NoError(t, runtime.Apply(context.Background(), first))
	one, ok := runtime.Instance("mysql-a")
	require.True(t, ok)
	two, ok := runtime.Instance("mysql-b")
	require.True(t, ok)
	require.NotSame(t, one.Pool, two.Pool)

	second := Config{AssignmentID: "assignment-a", Revision: 2, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "rotated"), fixtureDecodedInstance("mysql-b", "rotated")}}
	require.NoError(t, runtime.Apply(context.Background(), second))
	require.True(t, underlyingFake(one.Pool).closed)
	require.True(t, underlyingFake(two.Pool).closed)
	require.Equal(t, uint64(2), runtime.Revision())
}

func TestRuntimeFailedCandidateDoesNotReplaceWorkingInstances(t *testing.T) {
	factory := &fakePoolFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 1, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "one"), fixtureDecodedInstance("mysql-b", "two")}}))
	working, _ := runtime.Instance("mysql-a")
	factory.failUsername = "broken"
	err := runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 2, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "rotated"), fixtureDecodedInstance("mysql-b", "broken")}})
	require.ErrorIs(t, err, ErrConnectionRejected)
	stillWorking, _ := runtime.Instance("mysql-a")
	require.Same(t, working.Pool, stillWorking.Pool)
	require.False(t, underlyingFake(working.Pool).closed)
	require.Equal(t, uint64(1), runtime.Revision())
}

func TestRuntimeCredentialRemovalIsPerInstanceAndSameRevisionCanRecover(t *testing.T) {
	factory := &fakePoolFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	initial := Config{AssignmentID: "assignment-a", Revision: 4, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "old-a"), fixtureDecodedInstance("mysql-b", "stable-b")}}
	require.NoError(t, runtime.Apply(context.Background(), initial))
	oldA, _ := runtime.Instance("mysql-a")
	stableB, _ := runtime.Instance("mysql-b")

	withoutA := Config{AssignmentID: "assignment-a", Revision: 4, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", ""), fixtureDecodedInstance("mysql-b", "stable-b")}}
	withoutA.Instances[0].Credential = Credential{}
	require.NoError(t, runtime.Apply(context.Background(), withoutA))
	removedA, ok := runtime.Instance("mysql-a")
	require.True(t, ok)
	require.Nil(t, removedA.Pool)
	currentB, _ := runtime.Instance("mysql-b")
	require.Same(t, stableB.Pool, currentB.Pool)
	require.True(t, underlyingFake(oldA.Pool).closed)
	require.Equal(t, make([]byte, len("secret")), initial.Instances[0].Credential.Secret)

	recovered := Config{AssignmentID: "assignment-a", Revision: 4, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "new-a"), fixtureDecodedInstance("mysql-b", "stable-b")}}
	require.NoError(t, runtime.Apply(context.Background(), recovered))
	newA, _ := runtime.Instance("mysql-a")
	require.NotNil(t, newA.Pool)
	require.NotSame(t, oldA.Pool, newA.Pool)
	currentB, _ = runtime.Instance("mysql-b")
	require.Same(t, stableB.Pool, currentB.Pool)
}

func TestRuntimeReusesPoolButReplacesTemplatesAndRejectsCredentialReplay(t *testing.T) {
	factory := &fakePoolFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	first := fixtureDecodedInstance("mysql-a", "monitor")
	first.Credential.Revision = 5
	first.Templates = map[string]TemplateConfig{"custom-a": {ID: "custom-a", Revision: 1, Statement: "SELECT 1"}}
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 6, Instances: []InstanceConfig{first}}))
	old, _ := runtime.Instance("mysql-a")

	updated := fixtureDecodedInstance("mysql-a", "monitor")
	updated.Credential.Revision = 5
	updated.Templates = map[string]TemplateConfig{"custom-a": {ID: "custom-a", Revision: 2, Statement: "SELECT 2"}}
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 7, Instances: []InstanceConfig{updated}}))
	current, _ := runtime.Instance("mysql-a")
	require.Same(t, old.Pool, current.Pool)
	require.Equal(t, uint64(2), current.Config.Templates["custom-a"].Revision)

	replay := fixtureDecodedInstance("mysql-a", "monitor")
	replay.Credential.Revision = 4
	require.ErrorIs(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 7, Instances: []InstanceConfig{replay}}), ErrConfigurationRejected)
}

func TestRuntimeCredentialLeaseRenewalUpdatesMetadataWithoutRebuildingPool(t *testing.T) {
	factory := &fakePoolFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	initial := fixtureDecodedInstance("mysql-a", "monitor")
	initial.Credential.LeaseID = "lease-old"
	initial.Credential.Revision = 8
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 5, Instances: []InstanceConfig{initial}}))
	old, _ := runtime.Instance("mysql-a")
	renewed := fixtureDecodedInstance("mysql-a", "monitor")
	renewed.Credential.LeaseID = "lease-new"
	renewed.Credential.Revision = 8
	renewed.Credential.ExpiresAt = time.Now().Add(2 * time.Minute)
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 5, Instances: []InstanceConfig{renewed}}))
	current, _ := runtime.Instance("mysql-a")
	require.Same(t, old.Pool, current.Pool)
	require.Equal(t, "lease-new", current.Config.Credential.LeaseID)
	require.False(t, underlyingFake(old.Pool).closed)
}

func TestRuntimeWaitsForRetiredInstanceRowsWithoutBlockingOtherInstances(t *testing.T) {
	factory := &guardFactory{}
	runtime := NewRuntime(factory, RuntimeOptions{})
	require.NoError(t, runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 1, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "old-a"), fixtureDecodedInstance("mysql-b", "stable-b")}}))
	oldA, _ := runtime.Instance("mysql-a")
	rows, err := oldA.Pool.QueryContext(context.Background(), "SELECT 1")
	require.NoError(t, err)
	applyDone := make(chan error, 1)
	go func() {
		applyDone <- runtime.Apply(context.Background(), Config{AssignmentID: "assignment-a", Revision: 2, Instances: []InstanceConfig{fixtureDecodedInstance("mysql-a", "new-a"), fixtureDecodedInstance("mysql-b", "stable-b")}})
	}()
	require.Eventually(t, func() bool { current, ok := runtime.Instance("mysql-a"); return ok && current.Pool != oldA.Pool }, time.Second, 5*time.Millisecond)
	require.False(t, factory.first("mysql-a").closed)
	currentB, ok := runtime.Instance("mysql-b")
	require.True(t, ok)
	require.NoError(t, currentB.Pool.PingContext(context.Background()))
	require.NoError(t, rows.Close())
	require.NoError(t, <-applyDone)
	require.True(t, factory.first("mysql-a").closed)
}

func fixtureDecodedInstance(id, username string) InstanceConfig {
	return InstanceConfig{ID: id, Variant: "mysql", Endpoint: "127.0.0.1:3306", Credential: Credential{LeaseID: "lease-" + id, Revision: 1, Username: username, Secret: []byte("secret"), ExpiresAt: time.Now().Add(time.Minute)}}
}

type fakePoolFactory struct {
	mu           sync.Mutex
	failUsername string
	pools        []*fakePool
}

func (factory *fakePoolFactory) Open(_ context.Context, config InstanceConfig) (Pool, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	pool := &fakePool{}
	factory.pools = append(factory.pools, pool)
	if config.Credential.Username == factory.failUsername {
		pool.pingErr = errors.New("credential rejected")
	}
	return pool, nil
}

type fakePool struct {
	closed  bool
	pingErr error
}

func (pool *fakePool) PingContext(context.Context) error { return pool.pingErr }
func (pool *fakePool) QueryContext(_ context.Context, query string, _ ...any) (Rows, error) {
	if query == "SELECT VERSION(), @@version_comment" {
		return &staticRows{rows: [][]string{{"8.4.0", "MySQL Community Server"}}}, nil
	}
	return nil, errors.New("not configured")
}
func (pool *fakePool) Close() error      { pool.closed = true; return nil }
func underlyingFake(pool Pool) *fakePool { return pool.(*guardedPool).pool.(*fakePool) }

type guardFactory struct {
	mu     sync.Mutex
	byUser map[string][]*guardRawPool
}

func (factory *guardFactory) Open(_ context.Context, config InstanceConfig) (Pool, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.byUser == nil {
		factory.byUser = map[string][]*guardRawPool{}
	}
	pool := &guardRawPool{}
	factory.byUser[config.Credential.Username] = append(factory.byUser[config.Credential.Username], pool)
	return pool, nil
}
func (factory *guardFactory) first(id string) *guardRawPool {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	users := map[string]string{"mysql-a": "old-a", "mysql-b": "stable-b"}
	return factory.byUser[users[id]][0]
}

type guardRawPool struct {
	mu     sync.Mutex
	closed bool
}

func (*guardRawPool) PingContext(context.Context) error { return nil }
func (*guardRawPool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return &staticRows{rows: [][]string{{"1", "1"}}}, nil
}
func (pool *guardRawPool) Close() error {
	pool.mu.Lock()
	pool.closed = true
	pool.mu.Unlock()
	return nil
}
