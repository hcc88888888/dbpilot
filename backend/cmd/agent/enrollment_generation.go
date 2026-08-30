package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	enrollmentCSRFilename         = "agent.csr"
	enrollmentPrepareFilename     = ".generation-prepared.json"
	enrollmentCompleteFilename    = ".generation-complete.json"
	enrollmentCommitFilename      = "generation.json"
	enrollmentGenerationFormat    = 1
	enrollmentGenerationReady     = "prepared"
	enrollmentGenerationComplete  = "complete"
	enrollmentGenerationFinalized = "finalized"
	enrollmentTemporaryPrefix     = ".dbpilot-enrollment-tmp-"
)

type enrollmentWritableFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type enrollmentFileSystem struct {
	createTemp      func(string, string) (enrollmentWritableFile, error)
	renameCanonical func(string, string) error
	renameNoReplace func(string, string) error
	remove          func(string) error
	syncDirectory   func(string) error
}

func systemEnrollmentFilesystem() enrollmentFileSystem {
	return enrollmentFileSystem{
		createTemp: func(directory, pattern string) (enrollmentWritableFile, error) {
			return os.CreateTemp(directory, pattern)
		},
		renameCanonical: os.Rename,
		renameNoReplace: renameEnrollmentGenerationNoReplace,
		remove:          os.Remove,
		syncDirectory:   syncEnrollmentDirectory,
	}
}

type enrollmentGenerationManifest struct {
	Version            int    `json:"version"`
	State              string `json:"state"`
	AgentID            string `json:"agent_id"`
	HostID             string `json:"host_id,omitempty"`
	EnrollmentRevision uint64 `json:"enrollment_revision,omitempty"`
	TokenSHA256        string `json:"token_sha256"`
	PrivateKeySHA256   string `json:"private_key_sha256"`
	CSRPublicSHA256    string `json:"csr_public_sha256"`
	CertificateSHA256  string `json:"certificate_sha256,omitempty"`
	CASHA256           string `json:"ca_sha256,omitempty"`
	ExpiresAtUTC       string `json:"expires_at_utc,omitempty"`
}

type enrollmentGeneration struct {
	outputDirectory string
	stageDirectory  string
	request         *agentv1.EnrollAgentRequest
	files           enrollmentFiles
	manifest        enrollmentGenerationManifest
	published       bool
	filesystem      enrollmentFileSystem
}

func enrollmentStageDirectory(outputDirectory string) string {
	parent := filepath.Dir(outputDirectory)
	return filepath.Join(parent, "."+filepath.Base(outputDirectory)+".dbpilot-enrollment")
}

func prepareEnrollmentGeneration(outputDirectory, agentID string, token []byte, observation hostinventory.Observation, random io.Reader) (*enrollmentGeneration, error) {
	return prepareEnrollmentGenerationWithFilesystem(outputDirectory, agentID, token, observation, random, systemEnrollmentFilesystem())
}

func prepareEnrollmentGenerationWithFilesystem(outputDirectory, agentID string, token []byte, observation hostinventory.Observation, random io.Reader, filesystem enrollmentFileSystem) (*enrollmentGeneration, error) {
	if !filepath.IsAbs(outputDirectory) || filepath.Clean(outputDirectory) != outputDirectory || strings.TrimSpace(agentID) == "" || len(token) != enrollment.EnrollmentTokenBytes || random == nil {
		return nil, errors.New("enrollment generation input is invalid")
	}
	probe := observation
	if probe.HostID == "" {
		probe.HostID = "enrollment-host"
	}
	if observation.AgentID != agentID || probe.Validate() != nil {
		return nil, errors.New("enrollment generation input is invalid")
	}
	parent := filepath.Dir(outputDirectory)
	if err := ensureDirectoryPathWithoutSymlinks(parent); err != nil {
		return nil, errors.New("enrollment output parent is unavailable")
	}
	tokenDigest := enrollmentDigest(token)
	if outputInfo, err := os.Lstat(outputDirectory); err == nil {
		if !isSecureEnrollmentDirectory(outputInfo) {
			return nil, errors.New("enrollment output path is unsafe")
		}
		generation, loadErr := loadFinalizedEnrollmentOutput(outputDirectory, agentID, tokenDigest, filesystem)
		if loadErr != nil {
			if _, markerErr := os.Lstat(filepath.Join(outputDirectory, enrollmentCommitFilename)); markerErr == nil {
				return nil, errors.New("existing enrollment output is invalid")
			}
			return nil, errors.New("enrollment output path already exists")
		}
		generation.published = true
		return generation, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect enrollment output failed")
	}

	stageDirectory := enrollmentStageDirectory(outputDirectory)
	if stageInfo, err := os.Lstat(stageDirectory); err == nil {
		if !isSecureEnrollmentDirectory(stageInfo) {
			return nil, errors.New("enrollment staging path is unsafe")
		}
		if err := cleanupEnrollmentTemporaryFiles(stageDirectory, filesystem); err != nil {
			return nil, err
		}
		generation, loadErr := loadEnrollmentGeneration(outputDirectory, stageDirectory, agentID, tokenDigest, token, observation, filesystem)
		if loadErr != nil {
			generation, loadErr = recoverPreparedEnrollmentGeneration(outputDirectory, stageDirectory, agentID, tokenDigest, token, observation, filesystem)
		}
		if loadErr != nil {
			if err := resetIncompleteEnrollmentStage(stageDirectory, filesystem); err != nil {
				return nil, loadErr
			}
			return prepareEnrollmentGenerationWithFilesystem(outputDirectory, agentID, token, observation, random, filesystem)
		}
		if err := filesystem.syncDirectory(stageDirectory); err != nil {
			return nil, fmt.Errorf("sync enrollment staging directory: %w", err)
		}
		if err := filesystem.syncDirectory(parent); err != nil {
			return nil, fmt.Errorf("sync enrollment output parent: %w", err)
		}
		return generation, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect enrollment staging path failed")
	}
	if err := os.Mkdir(stageDirectory, 0o700); err != nil {
		return nil, errors.New("create enrollment staging directory failed")
	}
	request, files, err := generateEnrollmentMaterial(agentID, token, observation, random)
	if err != nil {
		return nil, err
	}
	files.CSRPEM = append([]byte(nil), request.GetCertificateSigningRequestPem()...)
	if err := writeEnrollmentFileAtomic(stageDirectory, agentKeyFilename, files.PrivateKeyPEM, filesystem); err != nil {
		return nil, err
	}
	if err := writeEnrollmentFileAtomic(stageDirectory, enrollmentCSRFilename, files.CSRPEM, filesystem); err != nil {
		return nil, err
	}
	manifest := enrollmentGenerationManifest{
		Version: enrollmentGenerationFormat, State: enrollmentGenerationReady, AgentID: agentID,
		TokenSHA256: tokenDigest, PrivateKeySHA256: enrollmentDigest(files.PrivateKeyPEM),
		CSRPublicSHA256: enrollmentDigest(request.GetCertificateSigningRequestPem()),
	}
	if err := writeEnrollmentManifestAtomic(stageDirectory, enrollmentPrepareFilename, manifest, filesystem); err != nil {
		return nil, err
	}
	if err := filesystem.syncDirectory(stageDirectory); err != nil {
		return nil, fmt.Errorf("sync enrollment staging directory: %w", err)
	}
	if err := filesystem.syncDirectory(parent); err != nil {
		return nil, fmt.Errorf("sync enrollment output parent: %w", err)
	}
	return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: stageDirectory, request: request, files: files, manifest: manifest, filesystem: filesystem}, nil
}

func loadFinalizedEnrollmentOutput(outputDirectory, agentID, tokenDigest string, filesystem enrollmentFileSystem) (*enrollmentGeneration, error) {
	manifest, err := readEnrollmentGenerationManifest(filepath.Join(outputDirectory, enrollmentCommitFilename))
	if err != nil || manifest.Version != enrollmentGenerationFormat || manifest.State != enrollmentGenerationFinalized || manifest.AgentID != agentID || manifest.TokenSHA256 != tokenDigest {
		return nil, errors.New("finalized enrollment manifest is invalid")
	}
	privateKey, err := readEnrollmentFile(filepath.Join(outputDirectory, agentKeyFilename), 1<<20)
	if err != nil || enrollmentDigest(privateKey) != manifest.PrivateKeySHA256 {
		return nil, errors.New("finalized enrollment private key is invalid")
	}
	certificate, err := readEnrollmentFile(filepath.Join(outputDirectory, agentCertificateFilename), 4<<20)
	if err != nil || enrollmentDigest(certificate) != manifest.CertificateSHA256 {
		return nil, errors.New("finalized enrollment certificate is invalid")
	}
	ca, err := readEnrollmentFile(filepath.Join(outputDirectory, agentCAFilename), 4<<20)
	if err != nil || enrollmentDigest(ca) != manifest.CASHA256 {
		return nil, errors.New("finalized enrollment CA is invalid")
	}
	if err := validatePublishedEnrollmentEntries(outputDirectory); err != nil {
		return nil, err
	}
	return &enrollmentGeneration{
		outputDirectory: outputDirectory, stageDirectory: outputDirectory, published: true, filesystem: filesystem,
		files: enrollmentFiles{PrivateKeyPEM: privateKey, CertificatePEM: certificate, ChainPEM: ca}, manifest: manifest,
	}, nil
}

func loadEnrollmentGeneration(outputDirectory, directory, agentID, tokenDigest string, token []byte, observation hostinventory.Observation, filesystem enrollmentFileSystem) (*enrollmentGeneration, error) {
	type candidate struct{ name, state string }
	candidates := []candidate{
		{name: enrollmentCommitFilename, state: enrollmentGenerationFinalized},
		{name: enrollmentCompleteFilename, state: enrollmentGenerationComplete},
		{name: enrollmentPrepareFilename, state: enrollmentGenerationReady},
	}
	var manifest enrollmentGenerationManifest
	var invalidHigherPriority []string
	found := false
	for _, candidate := range candidates {
		path := filepath.Join(directory, candidate.name)
		value, readErr := readEnrollmentGenerationManifest(path)
		if readErr == nil && value.State == candidate.state {
			manifest = value
			found = true
			break
		}
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("enrollment manifest path is unsafe")
			}
			invalidHigherPriority = append(invalidHigherPriority, path)
		}
	}
	if !found || manifest.Version != enrollmentGenerationFormat || manifest.AgentID != agentID || manifest.TokenSHA256 != tokenDigest {
		return nil, errors.New("enrollment staging manifest is invalid")
	}
	for _, invalidPath := range invalidHigherPriority {
		if err := filesystem.remove(invalidPath); err != nil {
			return nil, fmt.Errorf("remove invalid enrollment manifest: %w", err)
		}
	}
	if len(invalidHigherPriority) > 0 {
		if err := filesystem.syncDirectory(directory); err != nil {
			return nil, fmt.Errorf("sync enrollment manifest fallback: %w", err)
		}
	}
	privateKey, err := readEnrollmentFile(filepath.Join(directory, agentKeyFilename), 1<<20)
	if err != nil || enrollmentDigest(privateKey) != manifest.PrivateKeySHA256 {
		return nil, errors.New("enrollment private key is invalid")
	}
	files := enrollmentFiles{PrivateKeyPEM: privateKey}
	if manifest.State == enrollmentGenerationComplete || manifest.State == enrollmentGenerationFinalized {
		files.CertificatePEM, err = readEnrollmentFile(filepath.Join(directory, agentCertificateFilename), 4<<20)
		if err != nil || enrollmentDigest(files.CertificatePEM) != manifest.CertificateSHA256 {
			return nil, errors.New("enrollment certificate is invalid")
		}
		files.ChainPEM, err = readEnrollmentFile(filepath.Join(directory, agentCAFilename), 4<<20)
		if err != nil || enrollmentDigest(files.ChainPEM) != manifest.CASHA256 {
			return nil, errors.New("enrollment CA is invalid")
		}
		if csr, csrErr := readEnrollmentFile(filepath.Join(directory, enrollmentCSRFilename), 1<<20); csrErr == nil {
			files.CSRPEM = csr
		} else if manifest.State == enrollmentGenerationComplete {
			return nil, errors.New("completed enrollment CSR is invalid")
		}
		return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: directory, files: files, manifest: manifest, filesystem: filesystem}, nil
	}
	csr, err := readEnrollmentFile(filepath.Join(directory, enrollmentCSRFilename), 1<<20)
	if err != nil || enrollmentDigest(csr) != manifest.CSRPublicSHA256 {
		return nil, errors.New("enrollment CSR is invalid")
	}
	request, err := buildEnrollmentRequest(agentID, token, observation, privateKey, csr)
	if err != nil {
		return nil, err
	}
	files.CSRPEM = csr
	return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: directory, request: request, files: files, manifest: manifest, filesystem: filesystem}, nil
}

func recoverPreparedEnrollmentGeneration(outputDirectory, directory, agentID, tokenDigest string, token []byte, observation hostinventory.Observation, filesystem enrollmentFileSystem) (*enrollmentGeneration, error) {
	privateKey, keyErr := readEnrollmentFile(filepath.Join(directory, agentKeyFilename), 1<<20)
	csr, csrErr := readEnrollmentFile(filepath.Join(directory, enrollmentCSRFilename), 1<<20)
	if keyErr != nil || csrErr != nil {
		return nil, errors.New("incomplete enrollment generation has no recoverable key and CSR")
	}
	request, err := buildEnrollmentRequest(agentID, token, observation, privateKey, csr)
	if err != nil {
		return nil, err
	}
	manifest := enrollmentGenerationManifest{
		Version: enrollmentGenerationFormat, State: enrollmentGenerationReady, AgentID: agentID,
		TokenSHA256: tokenDigest, PrivateKeySHA256: enrollmentDigest(privateKey), CSRPublicSHA256: enrollmentDigest(csr),
	}
	preparedPath := filepath.Join(directory, enrollmentPrepareFilename)
	if info, statErr := os.Lstat(preparedPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("invalid enrollment prepared manifest is unsafe")
		}
		if err := filesystem.remove(preparedPath); err != nil {
			return nil, err
		}
	}
	if err := writeEnrollmentManifestAtomic(directory, enrollmentPrepareFilename, manifest, filesystem); err != nil {
		return nil, err
	}
	return &enrollmentGeneration{
		outputDirectory: outputDirectory, stageDirectory: directory, request: request,
		files: enrollmentFiles{PrivateKeyPEM: privateKey, CSRPEM: csr}, manifest: manifest, filesystem: filesystem,
	}, nil
}

func (generation *enrollmentGeneration) readyToPublish() bool {
	return generation != nil && (generation.manifest.State == enrollmentGenerationComplete || generation.manifest.State == enrollmentGenerationFinalized)
}

func (generation *enrollmentGeneration) complete(response *agentv1.EnrollAgentResponse, serverCA []byte) error {
	if generation == nil || generation.published || generation.manifest.State == "" {
		return errors.New("enrollment generation is unavailable")
	}
	if err := verifyEnrollmentResponse(generation.manifest.AgentID, generation.files.PrivateKeyPEM, response); err != nil {
		return err
	}
	certificate := append(append([]byte(nil), response.GetCertificatePem()...), response.GetCertificateChainPem()...)
	if len(serverCA) == 0 {
		return errors.New("enrollment CA is empty")
	}
	if generation.manifest.State == enrollmentGenerationComplete {
		if !bytes.Equal(generation.files.CertificatePEM, certificate) || !bytes.Equal(generation.files.ChainPEM, serverCA) {
			return errors.New("completed enrollment generation does not match response")
		}
		return validateEnrollmentGenerationSemantics(generation.manifest, generation.files, serverCA, true)
	}
	if err := cleanupEnrollmentTemporaryFiles(generation.stageDirectory, generation.filesystem); err != nil {
		return err
	}
	if err := writeEnrollmentFileAtomicResumable(generation.stageDirectory, agentCertificateFilename, certificate, generation.filesystem); err != nil {
		return err
	}
	if err := writeEnrollmentFileAtomicResumable(generation.stageDirectory, agentCAFilename, serverCA, generation.filesystem); err != nil {
		return err
	}
	manifest := generation.manifest
	manifest.State = enrollmentGenerationComplete
	manifest.HostID = response.GetHostId()
	manifest.EnrollmentRevision = response.GetEnrollmentRevision()
	manifest.CertificateSHA256 = enrollmentDigest(certificate)
	manifest.CASHA256 = enrollmentDigest(serverCA)
	manifest.ExpiresAtUTC = response.GetExpiresAt().AsTime().UTC().Format(time.RFC3339Nano)
	if err := writeEnrollmentManifestAtomicResumable(generation.stageDirectory, enrollmentCompleteFilename, manifest, generation.filesystem); err != nil {
		return err
	}
	if err := generation.filesystem.syncDirectory(generation.stageDirectory); err != nil {
		return fmt.Errorf("sync completed enrollment generation: %w", err)
	}
	generation.files.CertificatePEM = certificate
	generation.files.ChainPEM = append([]byte(nil), serverCA...)
	generation.manifest = manifest
	return validateEnrollmentGenerationSemantics(manifest, generation.files, serverCA, true)
}

func (generation *enrollmentGeneration) publish(serverCA []byte) error {
	if generation == nil || (generation.manifest.State != enrollmentGenerationComplete && generation.manifest.State != enrollmentGenerationFinalized) {
		return errors.New("enrollment generation is incomplete")
	}
	if generation.published {
		loaded, err := loadFinalizedEnrollmentOutput(generation.outputDirectory, generation.manifest.AgentID, generation.manifest.TokenSHA256, generation.filesystem)
		if err != nil {
			return errors.New("published enrollment output is invalid")
		}
		if err := validateEnrollmentGenerationSemantics(loaded.manifest, loaded.files, serverCA, false); err != nil {
			return err
		}
		generation.stageDirectory = generation.outputDirectory
		generation.files = loaded.files
		generation.manifest = loaded.manifest
		if err := generation.filesystem.syncDirectory(filepath.Dir(generation.outputDirectory)); err != nil {
			return fmt.Errorf("sync published enrollment output parent: %w", err)
		}
		return nil
	}
	if err := cleanupEnrollmentTemporaryFiles(generation.stageDirectory, generation.filesystem); err != nil {
		return err
	}
	loaded, err := loadEnrollmentGeneration(generation.outputDirectory, generation.stageDirectory, generation.manifest.AgentID, generation.manifest.TokenSHA256, nil, hostinventory.Observation{}, generation.filesystem)
	if err != nil || (loaded.manifest.State != enrollmentGenerationComplete && loaded.manifest.State != enrollmentGenerationFinalized) {
		return errors.New("enrollment generation validation failed")
	}
	requireCSR := loaded.manifest.State == enrollmentGenerationComplete
	if err := validateEnrollmentGenerationSemantics(loaded.manifest, loaded.files, serverCA, requireCSR); err != nil {
		return err
	}
	if _, err := os.Lstat(generation.outputDirectory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enrollment output path already exists")
	}
	if err := validateCompletedEnrollmentStage(generation.stageDirectory); err != nil {
		return err
	}
	if loaded.manifest.State == enrollmentGenerationComplete {
		finalManifest := loaded.manifest
		finalManifest.State = enrollmentGenerationFinalized
		if err := writeEnrollmentManifestAtomicResumable(generation.stageDirectory, enrollmentCommitFilename, finalManifest, generation.filesystem); err != nil {
			return err
		}
		loaded.manifest = finalManifest
		generation.manifest = finalManifest
	}
	for _, transitionalName := range []string{enrollmentCSRFilename, enrollmentPrepareFilename, enrollmentCompleteFilename} {
		if err := generation.filesystem.remove(filepath.Join(generation.stageDirectory, transitionalName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove enrollment staging file: %w", err)
		}
	}
	if err := generation.filesystem.syncDirectory(generation.stageDirectory); err != nil {
		return fmt.Errorf("sync finalized enrollment generation: %w", err)
	}
	if err := validatePublishedEnrollmentEntries(generation.stageDirectory); err != nil {
		return err
	}
	if err := generation.filesystem.renameNoReplace(generation.stageDirectory, generation.outputDirectory); err != nil {
		return fmt.Errorf("publish enrollment generation: %w", err)
	}
	generation.published = true
	generation.stageDirectory = generation.outputDirectory
	if err := generation.filesystem.syncDirectory(filepath.Dir(generation.outputDirectory)); err != nil {
		return fmt.Errorf("sync enrollment output parent: %w", err)
	}
	return nil
}

func validateEnrollmentGenerationSemantics(manifest enrollmentGenerationManifest, files enrollmentFiles, serverCA []byte, requireCSR bool) error {
	if manifest.Version != enrollmentGenerationFormat || (manifest.State != enrollmentGenerationComplete && manifest.State != enrollmentGenerationFinalized) || strings.TrimSpace(manifest.AgentID) == "" ||
		strings.TrimSpace(manifest.HostID) == "" || manifest.EnrollmentRevision == 0 || !validEnrollmentDigest(manifest.TokenSHA256) ||
		!validEnrollmentDigest(manifest.PrivateKeySHA256) || !validEnrollmentDigest(manifest.CSRPublicSHA256) ||
		!validEnrollmentDigest(manifest.CertificateSHA256) || !validEnrollmentDigest(manifest.CASHA256) {
		return errors.New("completed enrollment manifest is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAtUTC)
	if err != nil || !expiresAt.After(time.Now()) {
		return errors.New("completed enrollment expiry is invalid")
	}
	if enrollmentDigest(files.PrivateKeyPEM) != manifest.PrivateKeySHA256 || enrollmentDigest(files.CertificatePEM) != manifest.CertificateSHA256 ||
		enrollmentDigest(files.ChainPEM) != manifest.CASHA256 || enrollmentDigest(serverCA) != manifest.CASHA256 {
		return errors.New("completed enrollment material does not match its manifest or configured CA")
	}
	if requireCSR {
		if len(files.CSRPEM) == 0 || enrollmentDigest(files.CSRPEM) != manifest.CSRPublicSHA256 {
			return errors.New("completed enrollment CSR is invalid")
		}
		if _, err := buildEnrollmentRequest(manifest.AgentID, nil, hostinventory.Observation{}, files.PrivateKeyPEM, files.CSRPEM); err != nil {
			return errors.New("completed enrollment key and CSR do not match")
		}
	}
	response := &agentv1.EnrollAgentResponse{
		HostId: manifest.HostID, AgentId: manifest.AgentID,
		ExpiresAt: timestamppb.New(expiresAt), EnrollmentRevision: manifest.EnrollmentRevision,
	}
	response.CertificatePem, response.CertificateChainPem, err = splitEnrollmentCertificateBundle(files.CertificatePEM)
	if err != nil {
		return err
	}
	if err := verifyEnrollmentResponse(manifest.AgentID, files.PrivateKeyPEM, response); err != nil {
		return errors.New("completed enrollment certificate is invalid")
	}
	block, _ := pem.Decode(files.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("completed enrollment certificate is invalid")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.NotAfter.Unix() != expiresAt.Unix() {
		return errors.New("completed enrollment certificate expiry is inconsistent")
	}
	return nil
}

func splitEnrollmentCertificateBundle(bundle []byte) ([]byte, []byte, error) {
	remaining := bytes.TrimSpace(bundle)
	var leafPEM, chainPEM []byte
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("completed enrollment certificate bundle is invalid")
		}
		encoded := pem.EncodeToMemory(block)
		if len(leafPEM) == 0 {
			leafPEM = encoded
		} else {
			chainPEM = append(chainPEM, encoded...)
		}
		remaining = bytes.TrimSpace(rest)
	}
	if len(leafPEM) == 0 || len(chainPEM) == 0 {
		return nil, nil, errors.New("completed enrollment certificate chain is missing")
	}
	return leafPEM, chainPEM, nil
}

func validEnrollmentDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validateCompletedEnrollmentStage(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !isSecureEnrollmentDirectory(info) {
		return errors.New("enrollment staging directory is unsafe")
	}
	allowed := map[string]struct{}{
		agentKeyFilename: {}, enrollmentCSRFilename: {}, agentCertificateFilename: {}, agentCAFilename: {},
		enrollmentPrepareFilename: {}, enrollmentCompleteFilename: {}, enrollmentCommitFilename: {},
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("read enrollment staging directory failed")
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok {
			return errors.New("enrollment staging directory contains an unexpected entry")
		}
		if _, err := readEnrollmentFile(filepath.Join(directory, entry.Name()), 4<<20); err != nil {
			return errors.New("enrollment staging directory contains an unsafe entry")
		}
	}
	return nil
}

func isSecureEnrollmentDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || info.Mode().Perm() == 0o700)
}

func validatePublishedEnrollmentEntries(directory string) error {
	want := map[string]struct{}{
		agentKeyFilename: {}, agentCertificateFilename: {}, agentCAFilename: {}, enrollmentCommitFilename: {},
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(want) {
		return errors.New("completed enrollment generation has unexpected entries")
	}
	for _, entry := range entries {
		if _, ok := want[entry.Name()]; !ok {
			return errors.New("completed enrollment generation has unexpected entries")
		}
	}
	return nil
}

func readEnrollmentGenerationManifest(path string) (enrollmentGenerationManifest, error) {
	data, err := readEnrollmentFile(path, 64<<10)
	if err != nil {
		return enrollmentGenerationManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest enrollmentGenerationManifest
	if err := decoder.Decode(&manifest); err != nil {
		return enrollmentGenerationManifest{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return enrollmentGenerationManifest{}, errors.New("enrollment manifest contains trailing data")
	}
	return manifest, nil
}

func writeEnrollmentManifestAtomic(directory, name string, manifest enrollmentGenerationManifest, filesystem enrollmentFileSystem) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeEnrollmentFileAtomic(directory, name, data, filesystem)
}

func writeEnrollmentManifestAtomicResumable(directory, name string, manifest enrollmentGenerationManifest, filesystem enrollmentFileSystem) error {
	path := filepath.Join(directory, name)
	if existing, err := readEnrollmentGenerationManifest(path); err == nil {
		if existing == manifest {
			return filesystem.syncDirectory(directory)
		}
		if err := filesystem.remove(path); err != nil {
			return fmt.Errorf("remove enrollment manifest superseded by replayed response: %w", err)
		}
		if err := filesystem.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync superseded enrollment manifest removal: %w", err)
		}
	} else if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("enrollment manifest path is unsafe")
		}
		if err := filesystem.remove(path); err != nil {
			return fmt.Errorf("remove incomplete enrollment manifest: %w", err)
		}
		if err := filesystem.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync incomplete enrollment manifest removal: %w", err)
		}
	}
	return writeEnrollmentManifestAtomic(directory, name, manifest, filesystem)
}

func writeEnrollmentFileAtomicResumable(directory, name string, data []byte, filesystem enrollmentFileSystem) error {
	path := filepath.Join(directory, name)
	if existing, err := readEnrollmentFile(path, int64(len(data))+1); err == nil {
		if bytes.Equal(existing, data) {
			return filesystem.syncDirectory(directory)
		}
		if err := filesystem.remove(path); err != nil {
			return fmt.Errorf("remove incomplete enrollment staging file: %w", err)
		}
		if err := filesystem.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync incomplete enrollment staging removal: %w", err)
		}
	} else if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("enrollment staging file is unsafe")
		}
		if err := filesystem.remove(path); err != nil {
			return fmt.Errorf("remove unreadable enrollment staging file: %w", err)
		}
		if err := filesystem.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync unreadable enrollment staging removal: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("inspect enrollment staging file failed")
	}
	return writeEnrollmentFileAtomic(directory, name, data, filesystem)
}

func writeEnrollmentFileAtomic(directory, name string, data []byte, filesystem enrollmentFileSystem) error {
	path := filepath.Join(directory, name)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enrollment canonical staging path already exists")
	}
	file, err := filesystem.createTemp(directory, enrollmentTemporaryPrefix+name+"-")
	if err != nil {
		return fmt.Errorf("create enrollment temporary file: %w", err)
	}
	temporaryPath := file.Name()
	remove := true
	defer func() {
		if remove {
			_ = filesystem.remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure enrollment temporary file: %w", err)
	}
	if err := writeFull(file, data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write enrollment temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync enrollment temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close enrollment temporary file: %w", err)
	}
	if err := filesystem.renameCanonical(temporaryPath, path); err != nil {
		return fmt.Errorf("commit enrollment canonical file: %w", err)
	}
	remove = false
	if err := filesystem.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync enrollment canonical file: %w", err)
	}
	return nil
}

func cleanupEnrollmentTemporaryFiles(directory string, filesystem enrollmentFileSystem) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), enrollmentTemporaryPrefix) {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil || info.IsDir() {
			return errors.New("enrollment temporary residue is unsafe")
		}
		if err := filesystem.remove(filepath.Join(directory, entry.Name())); err != nil {
			return fmt.Errorf("remove enrollment temporary residue: %w", err)
		}
		removed = true
	}
	if removed {
		return filesystem.syncDirectory(directory)
	}
	return nil
}

func resetIncompleteEnrollmentStage(directory string, filesystem enrollmentFileSystem) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	known := map[string]struct{}{
		agentKeyFilename: {}, enrollmentCSRFilename: {}, agentCertificateFilename: {}, agentCAFilename: {},
		enrollmentPrepareFilename: {}, enrollmentCompleteFilename: {}, enrollmentCommitFilename: {},
	}
	for _, entry := range entries {
		_, expected := known[entry.Name()]
		if !expected && !strings.HasPrefix(entry.Name(), enrollmentTemporaryPrefix) {
			return errors.New("incomplete enrollment stage contains an unexpected entry")
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil || info.IsDir() {
			return errors.New("incomplete enrollment stage contains an unsafe entry")
		}
		if err := filesystem.remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	if err := filesystem.syncDirectory(directory); err != nil {
		return err
	}
	if err := filesystem.remove(directory); err != nil {
		return err
	}
	return filesystem.syncDirectory(filepath.Dir(directory))
}

func writeFull(writer io.Writer, data []byte) error {
	written, err := writer.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func readEnrollmentFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		return nil, errors.New("enrollment file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("enrollment file exceeds its limit")
	}
	return data, nil
}

func ensureDirectoryPathWithoutSymlinks(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(absolute) {
		return errors.New("directory path is invalid")
	}
	volume := filepath.VolumeName(absolute)
	root := string(os.PathSeparator)
	if volume != "" {
		root = volume + string(os.PathSeparator)
	}
	relative := strings.TrimPrefix(absolute, root)
	current := root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("directory path contains an unavailable or symbolic component")
		}
	}
	return nil
}

func syncEnrollmentDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func enrollmentDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func buildEnrollmentRequest(agentID string, token []byte, observation hostinventory.Observation, privateKeyPEM, csrPEM []byte) (*agentv1.EnrollAgentRequest, error) {
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("decode enrollment private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse enrollment private key")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("enrollment private key is not Ed25519")
	}
	csrBlock, csrRest := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(csrRest)) != 0 {
		return nil, errors.New("decode enrollment CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, errors.New("parse enrollment CSR")
	}
	csrPublicKey, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || csr.CheckSignature() != nil || !csrPublicKey.Equal(privateKey.Public()) {
		return nil, errors.New("enrollment CSR does not match private key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, errors.New("encode enrollment public key")
	}
	proofMessage, err := enrollment.CSRProofMessage(agentID, csrPEM, publicDER)
	if err != nil {
		return nil, err
	}
	return newEnrollmentRequest(agentID, token, observation, csrPEM, publicDER, ed25519.Sign(privateKey, proofMessage)), nil
}
