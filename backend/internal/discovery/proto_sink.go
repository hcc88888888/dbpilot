package discovery

import (
	"context"
	"crypto/subtle"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
)

type ProtoSink struct{ Service Service }

func (sink ProtoSink) RecordDiscoveryReport(ctx context.Context, agentID string, report *agentv1.DiscoveryReport) error {
	if sink.Service == nil || ctx == nil || report == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(report.GetAgentId())) != 1 {
		return ErrInvalid
	}
	observedAt, ok := protobufTime(report.GetObservedAt())
	if !ok {
		return ErrInvalid
	}
	converted := Report{HostID: report.GetHostId(), AgentID: agentID, ObservationRevision: report.GetObservationRevision(), RuleRevision: report.GetRuleRevision(), ObservedAt: observedAt, Candidates: make([]CandidateObservation, 0, len(report.GetCandidates()))}
	for _, candidate := range report.GetCandidates() {
		value, err := candidateFromProto(candidate)
		if err != nil {
			return err
		}
		converted.Candidates = append(converted.Candidates, value)
	}
	_, err := sink.Service.RecordReport(ctx, converted)
	return err
}

func candidateFromProto(value *agentv1.DiscoveryCandidateObservation) (CandidateObservation, error) {
	if value == nil || len(value.GetFingerprint()) != 32 {
		return CandidateObservation{}, ErrInvalid
	}
	observedAt, ok := protobufTime(value.GetObservedAt())
	if !ok {
		return CandidateObservation{}, ErrInvalid
	}
	source := SourceNative
	if value.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER {
		source = SourceDocker
	} else if value.GetSource() != agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE {
		return CandidateObservation{}, ErrInvalid
	}
	result := CandidateObservation{ObservationID: value.GetObservationId(), Source: source, DatabaseFamily: value.GetDatabaseFamily(), DatabaseVariant: value.GetDatabaseVariant(), VersionHint: value.GetVersionHint(), NormalizedEndpoint: value.GetNormalizedEndpoint(), UnixSocket: value.GetUnixSocket(), ProcessIdentity: value.GetProcessIdentity(), ServiceName: value.GetServiceName(), ContainerIdentity: value.GetContainerIdentity(), ContainerImage: value.GetContainerImage(), DiscoveredRole: value.GetDiscoveredRole(), Confidence: value.GetConfidence(), ObservedAt: observedAt, Evidence: make([]Evidence, 0, len(value.GetEvidence()))}
	copy(result.Fingerprint[:], value.GetFingerprint())
	for _, item := range value.GetEvidence() {
		kind, ok := evidenceKindFromProto(item.GetKind())
		if item == nil || !ok {
			return CandidateObservation{}, ErrInvalid
		}
		result.Evidence = append(result.Evidence, Evidence{Kind: kind, Value: item.GetRedactedValue()})
	}
	if result.Validate() != nil {
		return CandidateObservation{}, ErrInvalid
	}
	return result, nil
}

func evidenceKindFromProto(kind agentv1.DiscoveryEvidenceKind) (EvidenceKind, bool) {
	values := map[agentv1.DiscoveryEvidenceKind]EvidenceKind{agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_PROCESS_NAME: EvidenceProcessName, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_EXECUTABLE_PATH: EvidenceExecutablePath, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_SYSTEMD_UNIT: EvidenceSystemdUnit, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_LISTEN_ENDPOINT: EvidenceListenEndpoint, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_UNIX_SOCKET: EvidenceUnixSocket, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_IMAGE: EvidenceContainerImage, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_LABEL: EvidenceContainerLabel, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_PORT: EvidenceContainerPort, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_VERSION_HINT: EvidenceVersionHint}
	value, ok := values[kind]
	return value, ok
}

func protobufTime(value interface {
	IsValid() bool
	AsTime() time.Time
}) (time.Time, bool) {
	if value == nil || !value.IsValid() {
		return time.Time{}, false
	}
	result := value.AsTime().UTC()
	return result, !result.IsZero()
}
