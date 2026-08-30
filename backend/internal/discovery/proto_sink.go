package discovery

import (
	"context"
	"crypto/subtle"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	converted := Report{HostID: report.GetHostId(), AgentID: agentID, ObservationRevision: report.GetObservationRevision(), RuleRevision: report.GetRuleRevision(), ObservedAt: observedAt, Candidates: make([]CandidateObservation, 0, len(report.GetCandidates())), SourceResults: make([]SourceResult, 0, len(report.GetSourceResults()))}
	issuedAt, issuedOK := protobufTime(report.GetRuleIssuedAt())
	expiresAt, expiresOK := protobufTime(report.GetRuleExpiresAt())
	if !issuedOK || !expiresOK || len(report.GetRuleSetDigest()) != 32 {
		return ErrInvalid
	}
	copy(converted.RuleAttestation.Digest[:], report.GetRuleSetDigest())
	converted.RuleAttestation.Version = report.GetRuleAttestationVersion()
	converted.RuleAttestation.Algorithm = report.GetRuleAttestationAlgorithm()
	converted.RuleAttestation.KeyID = report.GetRuleAttestationKeyId()
	converted.RuleAttestation.Revision = report.GetRuleRevision()
	converted.RuleAttestation.IssuedAt = issuedAt
	converted.RuleAttestation.ExpiresAt = expiresAt
	converted.RuleAttestation.DisappearanceGrace = time.Duration(report.GetDisappearanceGraceSeconds()) * time.Second
	converted.RuleAttestation.Signature = append([]byte(nil), report.GetRuleAttestationSignature()...)
	for _, candidate := range report.GetCandidates() {
		value, err := candidateFromProto(candidate)
		if err != nil {
			return err
		}
		converted.Candidates = append(converted.Candidates, value)
	}
	for _, sourceResult := range report.GetSourceResults() {
		value, err := sourceResultFromProto(sourceResult)
		if err != nil {
			return err
		}
		converted.SourceResults = append(converted.SourceResults, value)
	}
	_, err := sink.Service.RecordReport(ctx, converted)
	return err
}

func sourceResultFromProto(value *agentv1.DiscoverySourceResult) (SourceResult, error) {
	if value == nil {
		return SourceResult{}, ErrInvalid
	}
	observedAt, ok := protobufTime(value.GetObservedAt())
	if !ok {
		return SourceResult{}, ErrInvalid
	}
	source := Source("")
	if value.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE {
		source = SourceNative
	}
	if value.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER {
		source = SourceDocker
	}
	statuses := map[agentv1.DiscoverySourceResultStatus]SourceResultStatus{
		agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED:      SourceCompleted,
		agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNAVAILABLE:    SourceUnavailable,
		agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_CONFIGURED: SourceNotConfigured,
		agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_REQUESTED:  SourceNotRequested,
	}
	reasons := map[agentv1.DiscoverySourceReason]SourceReason{
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HEALTHY:            SourceHealthy,
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HELPER_UNAVAILABLE: SourceHelperUnavailable,
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_PERMISSION_DENIED:  SourcePermissionDenied,
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_DETECTOR_ERROR:     SourceDetectorError,
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_CONFIGURED:     SourceReasonNotConfigured,
		agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_REQUESTED:      SourceReasonNotRequested,
	}
	result := SourceResult{Source: source, Status: statuses[value.GetStatus()], Reason: reasons[value.GetReason()], ObservedAt: observedAt}
	if result.Validate() != nil {
		return SourceResult{}, ErrInvalid
	}
	return result, nil
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
	values := map[agentv1.DiscoveryEvidenceKind]EvidenceKind{agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_PROCESS_NAME: EvidenceProcessName, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_EXECUTABLE_PATH: EvidenceExecutablePath, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_SYSTEMD_UNIT: EvidenceSystemdUnit, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_LISTEN_ENDPOINT: EvidenceListenEndpoint, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_UNIX_SOCKET: EvidenceUnixSocket, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_IMAGE: EvidenceContainerImage, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_LABEL: EvidenceContainerLabel, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_PORT: EvidenceContainerPort, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_VERSION_HINT: EvidenceVersionHint, agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_ID: EvidenceContainerID}
	value, ok := values[kind]
	return value, ok
}

func reportToProto(report Report) (*agentv1.DiscoveryReport, error) {
	candidates := make([]*agentv1.DiscoveryCandidateObservation, 0, len(report.Candidates))
	for _, candidate := range report.Candidates {
		source := agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE
		if candidate.Source == SourceDocker {
			source = agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER
		} else if candidate.Source != SourceNative {
			return nil, ErrInvalid
		}
		evidence := make([]*agentv1.DiscoveryEvidence, 0, len(candidate.Evidence))
		for _, item := range candidate.Evidence {
			kind, ok := evidenceKindToProto(item.Kind)
			if !ok {
				return nil, ErrInvalid
			}
			evidence = append(evidence, &agentv1.DiscoveryEvidence{Kind: kind, RedactedValue: item.Value})
		}
		candidates = append(candidates, &agentv1.DiscoveryCandidateObservation{ObservationId: candidate.ObservationID, Source: source, DatabaseFamily: candidate.DatabaseFamily, DatabaseVariant: candidate.DatabaseVariant, VersionHint: candidate.VersionHint, NormalizedEndpoint: candidate.NormalizedEndpoint, UnixSocket: candidate.UnixSocket, ProcessIdentity: candidate.ProcessIdentity, ServiceName: candidate.ServiceName, ContainerIdentity: candidate.ContainerIdentity, ContainerImage: candidate.ContainerImage, DiscoveredRole: candidate.DiscoveredRole, Confidence: candidate.Confidence, Evidence: evidence, Fingerprint: append([]byte(nil), candidate.Fingerprint[:]...), ObservedAt: timestamppb.New(candidate.ObservedAt)})
	}
	sourceResults := make([]*agentv1.DiscoverySourceResult, 0, len(report.SourceResults))
	for _, value := range report.SourceResults {
		wire, err := sourceResultToProto(value)
		if err != nil {
			return nil, err
		}
		sourceResults = append(sourceResults, wire)
	}
	return &agentv1.DiscoveryReport{HostId: report.HostID, AgentId: report.AgentID, ObservationRevision: report.ObservationRevision, RuleRevision: report.RuleRevision, Candidates: candidates, SourceResults: sourceResults, ObservedAt: timestamppb.New(report.ObservedAt), RuleSetDigest: append([]byte(nil), report.RuleAttestation.Digest[:]...), DisappearanceGraceSeconds: uint64(report.RuleAttestation.DisappearanceGrace / time.Second), RuleIssuedAt: timestamppb.New(report.RuleAttestation.IssuedAt), RuleExpiresAt: timestamppb.New(report.RuleAttestation.ExpiresAt), RuleAttestationSignature: append([]byte(nil), report.RuleAttestation.Signature...), RuleAttestationVersion: report.RuleAttestation.Version, RuleAttestationAlgorithm: report.RuleAttestation.Algorithm, RuleAttestationKeyId: report.RuleAttestation.KeyID}, nil
}

func sourceResultToProto(value SourceResult) (*agentv1.DiscoverySourceResult, error) {
	if value.Validate() != nil {
		return nil, ErrInvalid
	}
	sources := map[Source]agentv1.DiscoverySource{SourceNative: agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, SourceDocker: agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER}
	statuses := map[SourceResultStatus]agentv1.DiscoverySourceResultStatus{SourceCompleted: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, SourceUnavailable: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNAVAILABLE, SourceNotConfigured: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_CONFIGURED, SourceNotRequested: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_REQUESTED}
	reasons := map[SourceReason]agentv1.DiscoverySourceReason{SourceHealthy: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HEALTHY, SourceHelperUnavailable: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HELPER_UNAVAILABLE, SourcePermissionDenied: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_PERMISSION_DENIED, SourceDetectorError: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_DETECTOR_ERROR, SourceReasonNotConfigured: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_CONFIGURED, SourceReasonNotRequested: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_REQUESTED}
	return &agentv1.DiscoverySourceResult{Source: sources[value.Source], Status: statuses[value.Status], Reason: reasons[value.Reason], ObservedAt: timestamppb.New(value.ObservedAt)}, nil
}
func evidenceKindToProto(kind EvidenceKind) (agentv1.DiscoveryEvidenceKind, bool) {
	values := map[EvidenceKind]agentv1.DiscoveryEvidenceKind{EvidenceProcessName: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_PROCESS_NAME, EvidenceExecutablePath: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_EXECUTABLE_PATH, EvidenceSystemdUnit: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_SYSTEMD_UNIT, EvidenceListenEndpoint: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_LISTEN_ENDPOINT, EvidenceUnixSocket: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_UNIX_SOCKET, EvidenceContainerImage: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_IMAGE, EvidenceContainerLabel: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_LABEL, EvidenceContainerPort: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_PORT, EvidenceVersionHint: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_VERSION_HINT, EvidenceContainerID: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_ID}
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
