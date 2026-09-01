package mysqlplugin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/go-sql-driver/mysql"
	"google.golang.org/protobuf/proto"
)

type PoolFactory interface {
	Open(context.Context, InstanceConfig) (Pool, error)
}

type guardedPool struct {
	mu     sync.RWMutex
	pool   Pool
	closed bool
}

func newGuardedPool(pool Pool) *guardedPool { return &guardedPool{pool: pool} }
func (pool *guardedPool) PingContext(ctx context.Context) error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if pool.closed {
		return ErrConnectionRejected
	}
	return pool.pool.PingContext(ctx)
}
func (pool *guardedPool) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	pool.mu.RLock()
	if pool.closed {
		pool.mu.RUnlock()
		return nil, ErrConnectionRejected
	}
	rows, err := pool.pool.QueryContext(ctx, query, args...)
	if err != nil {
		pool.mu.RUnlock()
		return nil, err
	}
	return &guardedRows{Rows: rows, release: pool.mu.RUnlock}, nil
}
func (pool *guardedPool) Close() error {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closed {
		return nil
	}
	pool.closed = true
	return pool.pool.Close()
}

type guardedRows struct {
	Rows
	once    sync.Once
	release func()
}

func (rows *guardedRows) Close() error {
	err := rows.Rows.Close()
	rows.once.Do(rows.release)
	return err
}

type SQLPool struct{ DB *sql.DB }

func (pool SQLPool) PingContext(ctx context.Context) error { return pool.DB.PingContext(ctx) }
func (pool SQLPool) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	return pool.DB.QueryContext(ctx, query, args...)
}
func (pool SQLPool) Close() error { return pool.DB.Close() }

type MySQLPoolFactory struct {
	ConnectTimeout time.Duration
	MaxOpen        int
}

func (factory MySQLPoolFactory) Open(_ context.Context, instance InstanceConfig) (Pool, error) {
	timeout := factory.ConnectTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxOpen := factory.MaxOpen
	if maxOpen <= 0 {
		maxOpen = 2
	}
	config := mysql.NewConfig()
	config.User = instance.Credential.Username
	config.Passwd = string(instance.Credential.Secret)
	config.Net = "tcp"
	config.Addr = instance.Endpoint
	if instance.UnixSocket != "" {
		config.Net = "unix"
		config.Addr = instance.UnixSocket
	}
	config.Timeout = timeout
	config.ReadTimeout = timeout
	config.WriteTimeout = timeout
	config.ParseTime = true
	config.InterpolateParams = false
	database, err := sql.Open("mysql", config.FormatDSN())
	config.Passwd = ""
	if err != nil {
		return nil, ErrConnectionRejected
	}
	database.SetMaxOpenConns(maxOpen)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(5 * time.Minute)
	return SQLPool{DB: database}, nil
}

type RuntimeOptions struct{ PingTimeout time.Duration }

type InstanceRuntime struct {
	Config      InstanceConfig
	Pool        Pool
	fingerprint [sha256.Size]byte
}

type Runtime struct {
	factory             PoolFactory
	options             RuntimeOptions
	mu                  sync.RWMutex
	config              Config
	values              map[string]InstanceRuntime
	credentialRevisions map[string]uint64
	generation          uint64
}

func NewRuntime(factory PoolFactory, options RuntimeOptions) *Runtime {
	return &Runtime{factory: factory, options: options, values: map[string]InstanceRuntime{}, credentialRevisions: map[string]uint64{}}
}

func (runtime *Runtime) Apply(ctx context.Context, configuration Config) error {
	return runtime.apply(ctx, configuration, nil)
}

func (runtime *Runtime) ApplyWithSwap(ctx context.Context, configuration Config, onSwap func()) error {
	return runtime.apply(ctx, configuration, onSwap)
}

func (runtime *Runtime) apply(ctx context.Context, configuration Config, onSwap func()) error {
	defer configuration.Release()
	if runtime == nil || runtime.factory == nil || ctx == nil || ctx.Err() != nil || configuration.AssignmentID == "" || configuration.Revision == 0 || len(configuration.Instances) == 0 || len(configuration.Instances) > MaxInstances {
		return ErrConfigurationRejected
	}
	seen := map[string]struct{}{}
	for _, source := range configuration.Instances {
		if source.ID == "" {
			return ErrConfigurationRejected
		}
		if _, duplicate := seen[source.ID]; duplicate {
			return ErrConfigurationRejected
		}
		seen[source.ID] = struct{}{}
	}
	runtime.mu.RLock()
	if runtime.config.AssignmentID != "" && runtime.config.AssignmentID != configuration.AssignmentID {
		runtime.mu.RUnlock()
		return ErrConfigurationRejected
	}
	if configuration.Revision < runtime.config.Revision {
		runtime.mu.RUnlock()
		return ErrConfigurationRejected
	}
	snapshotGeneration := runtime.generation
	snapshotAssignment, snapshotRevision := runtime.config.AssignmentID, runtime.config.Revision
	snapshotValues := make(map[string]InstanceRuntime, len(runtime.values))
	for id, value := range runtime.values {
		snapshotValues[id] = value
	}
	snapshotCredentialRevisions := make(map[string]uint64, len(runtime.credentialRevisions))
	for id, revision := range runtime.credentialRevisions {
		snapshotCredentialRevisions[id] = revision
	}
	runtime.mu.RUnlock()
	candidates := make(map[string]InstanceRuntime, len(configuration.Instances))
	newPools := make([]Pool, 0)
	failed := true
	defer func() {
		if failed {
			for _, pool := range newPools {
				_ = pool.Close()
			}
			for id, candidate := range candidates {
				candidate.Config.Release()
				candidates[id] = candidate
			}
		}
	}()
	for _, source := range configuration.Instances {
		if source.Credential.Revision > 0 && source.Credential.Revision < snapshotCredentialRevisions[source.ID] {
			return ErrConfigurationRejected
		}
		fingerprint := instanceFingerprint(source)
		if old, exists := snapshotValues[source.ID]; exists && old.fingerprint == fingerprint {
			candidates[source.ID] = InstanceRuntime{Config: cloneInstanceWithoutSecret(source), Pool: old.Pool, fingerprint: old.fingerprint}
			continue
		}
		retained := cloneInstanceWithoutSecret(source)
		candidate := InstanceRuntime{Config: retained, fingerprint: fingerprint}
		if source.Credential.LeaseID != "" {
			rawPool, err := runtime.factory.Open(ctx, source)
			if err != nil {
				return ErrConnectionRejected
			}
			pool := newGuardedPool(rawPool)
			newPools = append(newPools, pool)
			timeout := runtime.options.PingTimeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			pingContext, cancel := context.WithTimeout(ctx, timeout)
			err = pool.PingContext(pingContext)
			cancel()
			if err != nil {
				return ErrConnectionRejected
			}
			candidate.Pool = pool
		}
		candidates[source.ID] = candidate
	}
	runtime.mu.Lock()
	if runtime.generation != snapshotGeneration || runtime.config.AssignmentID != snapshotAssignment || runtime.config.Revision != snapshotRevision || runtime.config.AssignmentID != "" && runtime.config.AssignmentID != configuration.AssignmentID || configuration.Revision < runtime.config.Revision {
		runtime.mu.Unlock()
		return ErrConfigurationRejected
	}
	for _, source := range configuration.Instances {
		if source.Credential.Revision > 0 && source.Credential.Revision < runtime.credentialRevisions[source.ID] {
			runtime.mu.Unlock()
			return ErrConfigurationRejected
		}
	}
	retired := make([]Pool, 0)
	retiredConfigs := make([]InstanceConfig, 0, len(runtime.values))
	for id, old := range runtime.values {
		candidate, retained := candidates[id]
		if !retained || candidate.Pool != old.Pool {
			if old.Pool != nil {
				retired = append(retired, old.Pool)
			}
		}
		retiredConfigs = append(retiredConfigs, old.Config)
	}
	runtime.config = Config{AssignmentID: configuration.AssignmentID, Revision: configuration.Revision}
	runtime.values = candidates
	for _, source := range configuration.Instances {
		if source.Credential.Revision > runtime.credentialRevisions[source.ID] {
			runtime.credentialRevisions[source.ID] = source.Credential.Revision
		}
	}
	runtime.generation++
	failed = false
	if onSwap != nil {
		onSwap()
	}
	runtime.mu.Unlock()
	for index := range retiredConfigs {
		retiredConfigs[index].Release()
	}
	for _, pool := range retired {
		_ = pool.Close()
	}
	return nil
}

func (runtime *Runtime) Instance(id string) (InstanceRuntime, bool) {
	if runtime == nil {
		return InstanceRuntime{}, false
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	value, ok := runtime.values[id]
	if !ok {
		return InstanceRuntime{}, false
	}
	value.Config = cloneInstanceWithoutSecret(value.Config)
	return value, true
}

func (runtime *Runtime) Instances() []InstanceRuntime {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	result := make([]InstanceRuntime, 0, len(runtime.values))
	for _, value := range runtime.values {
		value.Config = cloneInstanceWithoutSecret(value.Config)
		result = append(result, value)
	}
	return result
}

func (runtime *Runtime) Revision() uint64 {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.config.Revision
}
func (runtime *Runtime) AssignmentID() string {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.config.AssignmentID
}

func (runtime *Runtime) withRevision(revision uint64, action func()) bool {
	if runtime == nil || action == nil {
		return false
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.config.Revision != revision {
		return false
	}
	action()
	return true
}

func (runtime *Runtime) Close() {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for id, value := range runtime.values {
		if value.Pool != nil {
			_ = value.Pool.Close()
		}
		value.Config.Release()
		delete(runtime.values, id)
	}
}

func (runtime *Runtime) replaceForTest(configuration Config, values map[string]InstanceRuntime) {
	runtime.mu.Lock()
	runtime.config = configuration
	runtime.values = values
	runtime.generation++
	runtime.mu.Unlock()
}

func instanceFingerprint(value InstanceConfig) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(value.ID))
	hash.Write([]byte{0})
	hash.Write([]byte(value.Endpoint))
	hash.Write([]byte{0})
	hash.Write([]byte(value.UnixSocket))
	hash.Write([]byte{0})
	hash.Write([]byte(value.Credential.Username))
	hash.Write(value.Credential.Secret)
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], value.Credential.Revision)
	hash.Write(revision[:])
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func cloneInstanceWithoutSecret(source InstanceConfig) InstanceConfig {
	result := source
	result.Credential.Secret = nil
	result.Templates = make(map[string]TemplateConfig, len(source.Templates))
	for key, template := range source.Templates {
		copied := template
		copied.Digest = append([]byte(nil), template.Digest...)
		copied.ValueMappings = make([]*pluginv1.MetricValueMapping, len(template.ValueMappings))
		for index, mapping := range template.ValueMappings {
			if mapping != nil {
				copied.ValueMappings[index] = proto.Clone(mapping).(*pluginv1.MetricValueMapping)
			}
		}
		copied.LabelMappings = make([]*pluginv1.MetricLabelMapping, len(template.LabelMappings))
		for index, mapping := range template.LabelMappings {
			if mapping != nil {
				copied.LabelMappings[index] = proto.Clone(mapping).(*pluginv1.MetricLabelMapping)
			}
		}
		result.Templates[key] = copied
	}
	return result
}
