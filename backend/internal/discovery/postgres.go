package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

const candidateColumns = "candidate_id, tenant_id, project_id, host_id, agent_id, observation_id, discovery_source, database_family, database_variant, version_hint, normalized_endpoint, unix_socket, process_identity, service_name, container_identity, container_image, discovered_role, confidence, evidence_summary, fingerprint, rule_revision, observation_revision, first_seen_at, last_seen_at, status, ignore_reason"

type PostgresRepository struct{ database *sql.DB }

func NewPostgresRepository(database *sql.DB) *PostgresRepository {
	return &PostgresRepository{database: database}
}

func (repository *PostgresRepository) ResolveAgentBinding(ctx context.Context, agentID string) (AgentBinding, error) {
	if repository == nil || repository.database == nil || ctx == nil || !identifierPattern.MatchString(agentID) {
		return AgentBinding{}, ErrInvalid
	}
	var binding AgentBinding
	var status string
	err := repository.database.QueryRowContext(ctx, `SELECT tenant_id, project_id, host_id, agent_id, status FROM managed_hosts WHERE agent_id = $1`, agentID).Scan(&binding.Scope.TenantID, &binding.Scope.ProjectID, &binding.HostID, &binding.AgentID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentBinding{}, ErrNotFound
	}
	if err != nil {
		return AgentBinding{}, mapPostgresError(err)
	}
	if binding.Validate() != nil || status == "decommissioned" {
		return AgentBinding{}, ErrConflict
	}
	return binding, nil
}

func (repository *PostgresRepository) CommittedReport(ctx context.Context, report Report) (bool, error) {
	if repository == nil || repository.database == nil || ctx == nil || report.Validate() != nil {
		return false, ErrInvalid
	}
	digest, err := reportDigest(report)
	if err != nil {
		return false, err
	}
	var committed bool
	err = repository.database.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_scan_state WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4 AND observation_revision=$5 AND report_digest=$6 AND rule_revision=$7 AND rule_set_digest=$8)`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, report.AgentID, report.ObservationRevision, digest[:], report.RuleRevision, report.RuleAttestation.Digest[:]).Scan(&committed)
	if err != nil {
		return false, mapPostgresError(err)
	}
	return committed, nil
}

func (repository *PostgresRepository) RecordReport(ctx context.Context, report Report, receivedAt time.Time, grace time.Duration) ([]Candidate, error) {
	if repository == nil || repository.database == nil || ctx == nil || report.Validate() != nil || grace < time.Minute || grace > 24*time.Hour {
		return nil, ErrInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	rollback := func() { _ = transaction.Rollback() }
	lockDigest := sha256.Sum256([]byte(report.Scope.Key() + "\x00" + report.HostID))
	if _, err := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(lockDigest[:8]))); err != nil {
		rollback()
		return nil, mapPostgresError(err)
	}
	if err := transaction.QueryRowContext(ctx, "SELECT CURRENT_TIMESTAMP").Scan(&receivedAt); err != nil {
		rollback()
		return nil, mapPostgresError(err)
	}
	receivedAt = receivedAt.UTC()
	digest, err := reportDigest(report)
	if err != nil {
		rollback()
		return nil, err
	}
	var previousRevision uint64
	var previousRuleRevision uint64
	var previousDigest []byte
	var previousRuleDigest []byte
	var previousObservedAt sql.NullTime
	err = transaction.QueryRowContext(ctx, `SELECT observation_revision,rule_revision,report_digest,rule_set_digest,agent_observed_at FROM discovery_scan_state WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 FOR UPDATE`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID).Scan(&previousRevision, &previousRuleRevision, &previousDigest, &previousRuleDigest, &previousObservedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		rollback()
		return nil, mapPostgresError(err)
	}
	if err == nil && report.ObservationRevision == previousRevision {
		if !equalBytes(previousDigest, digest[:]) {
			rollback()
			return nil, ErrConflict
		}
		values, listErr := listCandidatesTx(ctx, transaction, report.Scope, Filter{HostID: report.HostID, Limit: 100})
		if listErr != nil {
			rollback()
			return nil, listErr
		}
		if commitErr := transaction.Commit(); commitErr != nil {
			return nil, mapPostgresError(commitErr)
		}
		return values.Items, nil
	}
	if !newReportActiveAt(report, receivedAt) {
		rollback()
		return nil, ErrConflict
	}
	if err == nil {
		if report.RuleRevision < previousRuleRevision {
			rollback()
			return nil, ErrStaleRevision
		}
		if report.RuleRevision == previousRuleRevision && len(previousRuleDigest) == 32 && !equalBytes(previousRuleDigest, report.RuleAttestation.Digest[:]) {
			rollback()
			return nil, ErrConflict
		}
		if previousObservedAt.Valid && report.ObservedAt.Before(previousObservedAt.Time) {
			rollback()
			return nil, ErrStaleRevision
		}
		if report.ObservationRevision < previousRevision {
			rollback()
			return nil, ErrStaleRevision
		}
		_, err = transaction.ExecContext(ctx, `UPDATE discovery_scan_state SET agent_id=$4,observation_revision=$5,rule_revision=$6,report_digest=$7,observed_at=$8,received_at=$9,rule_set_digest=$10,disappearance_grace_seconds=$11,agent_observed_at=$8 WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, report.AgentID, report.ObservationRevision, report.RuleRevision, digest[:], report.ObservedAt, receivedAt, report.RuleAttestation.Digest[:], int64(grace/time.Second))
	} else {
		_, err = transaction.ExecContext(ctx, `INSERT INTO discovery_scan_state (tenant_id,project_id,host_id,agent_id,observation_revision,rule_revision,report_digest,observed_at,received_at,rule_set_digest,disappearance_grace_seconds,agent_observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$8)`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, report.AgentID, report.ObservationRevision, report.RuleRevision, digest[:], report.ObservedAt, receivedAt, report.RuleAttestation.Digest[:], int64(grace/time.Second))
	}
	if err != nil {
		rollback()
		return nil, mapPostgresError(err)
	}
	sourceResults := effectiveSourceResults(report)
	for _, sourceResult := range sourceResults {
		if sourceResult.Status == SourceNotRequested {
			continue
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO discovery_scan_sources (tenant_id,project_id,host_id,discovery_source,result_status,reason_code,observation_revision,rule_revision,rule_set_digest,observed_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (tenant_id,project_id,host_id,discovery_source) DO UPDATE SET result_status=EXCLUDED.result_status,reason_code=EXCLUDED.reason_code,observation_revision=EXCLUDED.observation_revision,rule_revision=EXCLUDED.rule_revision,rule_set_digest=EXCLUDED.rule_set_digest,observed_at=EXCLUDED.observed_at,updated_at=EXCLUDED.updated_at WHERE discovery_scan_sources.observation_revision < EXCLUDED.observation_revision`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, string(sourceResult.Source), string(sourceResult.Status), string(sourceResult.Reason), report.ObservationRevision, report.RuleRevision, report.RuleAttestation.Digest[:], sourceResult.ObservedAt, receivedAt)
		if err != nil {
			rollback()
			return nil, mapPostgresError(err)
		}
	}
	for _, observation := range report.Candidates {
		evidence, err := json.Marshal(observation.Evidence)
		if err != nil {
			rollback()
			return nil, ErrInvalid
		}
		candidateID := "candidate-" + hex.EncodeToString(observation.Fingerprint[:])
		_, err = transaction.ExecContext(ctx, `INSERT INTO discovery_candidates (candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,version_hint,normalized_endpoint,unix_socket,process_identity,service_name,container_identity,container_image,discovered_role,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$23,'awaiting_confirmation',$23) ON CONFLICT (tenant_id,project_id,host_id,fingerprint) DO UPDATE SET observation_id=EXCLUDED.observation_id, agent_id=EXCLUDED.agent_id, database_family=EXCLUDED.database_family, database_variant=EXCLUDED.database_variant, version_hint=EXCLUDED.version_hint, normalized_endpoint=EXCLUDED.normalized_endpoint, unix_socket=EXCLUDED.unix_socket, process_identity=EXCLUDED.process_identity, service_name=EXCLUDED.service_name, container_identity=EXCLUDED.container_identity, container_image=EXCLUDED.container_image, discovered_role=EXCLUDED.discovered_role, confidence=EXCLUDED.confidence, evidence_summary=EXCLUDED.evidence_summary, rule_revision=EXCLUDED.rule_revision, observation_revision=EXCLUDED.observation_revision, last_seen_at=GREATEST(discovery_candidates.last_seen_at,EXCLUDED.last_seen_at), status=CASE WHEN discovery_candidates.status='disappeared' THEN 'awaiting_confirmation' ELSE discovery_candidates.status END, updated_at=EXCLUDED.updated_at WHERE discovery_candidates.observation_revision < EXCLUDED.observation_revision`, candidateID, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, report.AgentID, observation.ObservationID, string(observation.Source), observation.DatabaseFamily, observation.DatabaseVariant, observation.VersionHint, observation.NormalizedEndpoint, observation.UnixSocket, observation.ProcessIdentity, observation.ServiceName, observation.ContainerIdentity, observation.ContainerImage, observation.DiscoveredRole, observation.Confidence, evidence, observation.Fingerprint[:], report.RuleRevision, report.ObservationRevision, receivedAt)
		if err != nil {
			rollback()
			return nil, mapPostgresError(err)
		}
	}
	for _, sourceResult := range sourceResults {
		if sourceResult.Status != SourceCompleted {
			continue
		}
		_, err = transaction.ExecContext(ctx, `UPDATE discovery_candidates SET status='disappeared', updated_at=$6 WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND discovery_source=$4 AND status IN ('discovered','awaiting_confirmation') AND last_seen_at <= $5`, report.Scope.TenantID, report.Scope.ProjectID, report.HostID, string(sourceResult.Source), receivedAt.Add(-grace), receivedAt)
		if err != nil {
			rollback()
			return nil, mapPostgresError(err)
		}
	}
	page, err := listCandidatesTx(ctx, transaction, report.Scope, Filter{HostID: report.HostID, Limit: 100})
	if err != nil {
		rollback()
		return nil, err
	}
	if err := transaction.Commit(); err != nil {
		return nil, mapPostgresError(err)
	}
	return page.Items, nil
}

func effectiveSourceResults(report Report) []SourceResult {
	if len(report.SourceResults) > 0 {
		return append([]SourceResult(nil), report.SourceResults...)
	}
	seen := map[Source]struct{}{}
	results := make([]SourceResult, 0, 2)
	for _, candidate := range report.Candidates {
		if _, exists := seen[candidate.Source]; exists {
			continue
		}
		seen[candidate.Source] = struct{}{}
		results = append(results, SourceResult{Source: candidate.Source, Status: SourceCompleted, Reason: SourceHealthy, ObservedAt: report.ObservedAt})
	}
	return results
}

func (repository *PostgresRepository) SourceResults(ctx context.Context, scope platformscope.Scope, hostID string) ([]SourceResult, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) {
		return nil, ErrInvalid
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT discovery_source,result_status,reason_code,observed_at FROM discovery_scan_sources WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 ORDER BY CASE discovery_source WHEN 'native' THEN 1 ELSE 2 END`, scope.TenantID, scope.ProjectID, hostID)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	results := make([]SourceResult, 0, 2)
	for rows.Next() {
		var result SourceResult
		if err := rows.Scan(&result.Source, &result.Status, &result.Reason, &result.ObservedAt); err != nil {
			return nil, mapPostgresError(err)
		}
		result.ObservedAt = result.ObservedAt.UTC()
		if result.Validate() != nil {
			return nil, ErrInvalid
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}
	return results, nil
}

func newReportActiveAt(report Report, databaseNow time.Time) bool {
	return !databaseNow.Before(report.RuleAttestation.IssuedAt) && report.RuleAttestation.ExpiresAt.After(databaseNow) && !report.ObservedAt.Before(databaseNow.Add(-5*time.Minute)) && !report.ObservedAt.After(databaseNow.Add(5*time.Minute))
}

func (repository *PostgresRepository) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return Page{}, ErrInvalid
	}
	return listCandidates(ctx, repository.database, scope, filter)
}

func (repository *PostgresRepository) Get(ctx context.Context, scope platformscope.Scope, candidateID string) (Candidate, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) {
		return Candidate{}, ErrInvalid
	}
	value, err := scanCandidate(repository.database.QueryRowContext(ctx, `SELECT `+candidateColumns+` FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3`, scope.TenantID, scope.ProjectID, candidateID))
	if errors.Is(err, sql.ErrNoRows) {
		return Candidate{}, ErrNotFound
	}
	return value, mapPostgresError(err)
}

func (repository *PostgresRepository) Ignore(ctx context.Context, scope platformscope.Scope, candidateID, reason string, at time.Time) (Candidate, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) || !familyPattern.MatchString(reason) || !validUTC(at) {
		return Candidate{}, ErrInvalid
	}
	value, err := scanCandidate(repository.database.QueryRowContext(ctx, `UPDATE discovery_candidates SET status='ignored', ignore_reason=$4, updated_at=$5 WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3 AND (status IN ('discovered','awaiting_confirmation','disappeared') OR (status='ignored' AND ignore_reason=$4)) RETURNING `+candidateColumns, scope.TenantID, scope.ProjectID, candidateID, reason, at))
	if errors.Is(err, sql.ErrNoRows) {
		current, getErr := repository.Get(ctx, scope, candidateID)
		if getErr != nil {
			return Candidate{}, getErr
		}
		if current.Status == StatusIgnored && current.IgnoreReason != reason {
			return Candidate{}, ErrConflict
		}
		return Candidate{}, ErrConflict
	}
	return value, mapPostgresError(err)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listCandidates(ctx context.Context, source queryer, scope platformscope.Scope, filter Filter) (Page, error) {
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	rows, err := source.QueryContext(ctx, `SELECT `+candidateColumns+` FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2 AND ($3='' OR candidate_id>$3) AND ($4='' OR host_id=$4) AND ($5='' OR status=$5) AND ($6='' OR discovery_source=$6) AND ($7='' OR database_family=$7) ORDER BY candidate_id LIMIT $8`, scope.TenantID, scope.ProjectID, filter.Cursor, filter.HostID, string(filter.Status), string(filter.Source), filter.DatabaseFamily, limit+1)
	if err != nil {
		return Page{}, mapPostgresError(err)
	}
	defer rows.Close()
	page := Page{Items: make([]Candidate, 0, limit)}
	for rows.Next() {
		value, err := scanCandidate(rows)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return Page{}, mapPostgresError(err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}
func listCandidatesTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, filter Filter) (Page, error) {
	return listCandidates(ctx, tx, scope, filter)
}

type scanner interface{ Scan(...any) error }

func scanCandidate(row scanner) (Candidate, error) {
	var value Candidate
	var source, status string
	var evidence []byte
	var fingerprint []byte
	err := row.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.ObservationID, &source, &value.DatabaseFamily, &value.DatabaseVariant, &value.VersionHint, &value.NormalizedEndpoint, &value.UnixSocket, &value.ProcessIdentity, &value.ServiceName, &value.ContainerIdentity, &value.ContainerImage, &value.DiscoveredRole, &value.Confidence, &evidence, &fingerprint, &value.RuleRevision, &value.ObservationRevision, &value.FirstSeenAt, &value.LastSeenAt, &status, &value.IgnoreReason)
	if err != nil {
		return Candidate{}, err
	}
	value.Source = Source(source)
	value.Status = Status(status)
	copy(value.Fingerprint[:], fingerprint)
	if err := json.Unmarshal(evidence, &value.Evidence); err != nil {
		return Candidate{}, ErrInvalid
	}
	value.ObservedAt = value.LastSeenAt.UTC()
	value.FirstSeenAt = value.FirstSeenAt.UTC()
	value.LastSeenAt = value.LastSeenAt.UTC()
	if value.Validate() != nil {
		return Candidate{}, ErrInvalid
	}
	return value, nil
}

func reportDigest(report Report) ([32]byte, error) {
	wire, err := reportToProto(report)
	if err != nil {
		return [32]byte{}, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}
func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func mapPostgresError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23503":
			return ErrNotFound
		case "23505", "23514":
			return ErrConflict
		}
	}
	if strings.TrimSpace(err.Error()) == "" {
		return fmt.Errorf("discovery persistence failed")
	}
	return err
}
