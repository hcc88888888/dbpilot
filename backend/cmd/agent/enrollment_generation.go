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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
)

const (
	enrollmentCSRFilename        = "agent.csr"
	enrollmentPrepareFilename    = ".generation-prepared.json"
	enrollmentCommitFilename     = "generation.json"
	enrollmentGenerationFormat   = 1
	enrollmentGenerationReady    = "prepared"
	enrollmentGenerationComplete = "complete"
)

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
}

type enrollmentGeneration struct {
	outputDirectory string
	stageDirectory  string
	request         *agentv1.EnrollAgentRequest
	files           enrollmentFiles
	manifest        enrollmentGenerationManifest
	published       bool
}

func enrollmentStageDirectory(outputDirectory string) string {
	parent := filepath.Dir(outputDirectory)
	return filepath.Join(parent, "."+filepath.Base(outputDirectory)+".dbpilot-enrollment")
}

func prepareEnrollmentGeneration(outputDirectory, agentID string, token []byte, observation hostinventory.Observation, random io.Reader) (*enrollmentGeneration, error) {
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
		generation, loadErr := loadEnrollmentGeneration(outputDirectory, outputDirectory, agentID, tokenDigest, token, observation)
		if loadErr != nil || generation.manifest.State != enrollmentGenerationComplete {
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
		return loadEnrollmentGeneration(outputDirectory, stageDirectory, agentID, tokenDigest, token, observation)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect enrollment staging path failed")
	}
	if err := os.Mkdir(stageDirectory, 0o700); err != nil {
		return nil, errors.New("create enrollment staging directory failed")
	}
	removeStage := true
	defer func() {
		if removeStage {
			for _, name := range []string{agentKeyFilename, enrollmentCSRFilename, enrollmentPrepareFilename} {
				_ = os.Remove(filepath.Join(stageDirectory, name))
			}
			_ = os.Remove(stageDirectory)
		}
	}()
	request, files, err := generateEnrollmentMaterial(agentID, token, observation, random)
	if err != nil {
		return nil, err
	}
	if err := writeEnrollmentFileExclusive(filepath.Join(stageDirectory, agentKeyFilename), files.PrivateKeyPEM); err != nil {
		return nil, err
	}
	if err := writeEnrollmentFileExclusive(filepath.Join(stageDirectory, enrollmentCSRFilename), request.GetCertificateSigningRequestPem()); err != nil {
		return nil, err
	}
	manifest := enrollmentGenerationManifest{
		Version: enrollmentGenerationFormat, State: enrollmentGenerationReady, AgentID: agentID,
		TokenSHA256: tokenDigest, PrivateKeySHA256: enrollmentDigest(files.PrivateKeyPEM),
		CSRPublicSHA256: enrollmentDigest(request.GetCertificateSigningRequestPem()),
	}
	if err := writeEnrollmentManifestExclusive(filepath.Join(stageDirectory, enrollmentPrepareFilename), manifest); err != nil {
		return nil, err
	}
	if err := syncEnrollmentDirectory(stageDirectory); err != nil {
		return nil, errors.New("sync enrollment staging directory failed")
	}
	removeStage = false
	return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: stageDirectory, request: request, files: files, manifest: manifest}, nil
}

func loadEnrollmentGeneration(outputDirectory, directory, agentID, tokenDigest string, token []byte, observation hostinventory.Observation) (*enrollmentGeneration, error) {
	manifestPath := filepath.Join(directory, enrollmentCommitFilename)
	manifest, err := readEnrollmentGenerationManifest(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		manifestPath = filepath.Join(directory, enrollmentPrepareFilename)
		manifest, err = readEnrollmentGenerationManifest(manifestPath)
	}
	if err != nil || manifest.Version != enrollmentGenerationFormat || manifest.AgentID != agentID || manifest.TokenSHA256 != tokenDigest || (manifest.State != enrollmentGenerationReady && manifest.State != enrollmentGenerationComplete) {
		return nil, errors.New("enrollment staging manifest is invalid")
	}
	privateKey, err := readEnrollmentFile(filepath.Join(directory, agentKeyFilename), 1<<20)
	if err != nil || enrollmentDigest(privateKey) != manifest.PrivateKeySHA256 {
		return nil, errors.New("enrollment private key is invalid")
	}
	files := enrollmentFiles{PrivateKeyPEM: privateKey}
	if manifest.State == enrollmentGenerationComplete {
		files.CertificatePEM, err = readEnrollmentFile(filepath.Join(directory, agentCertificateFilename), 4<<20)
		if err != nil || enrollmentDigest(files.CertificatePEM) != manifest.CertificateSHA256 {
			return nil, errors.New("enrollment certificate is invalid")
		}
		files.ChainPEM, err = readEnrollmentFile(filepath.Join(directory, agentCAFilename), 4<<20)
		if err != nil || enrollmentDigest(files.ChainPEM) != manifest.CASHA256 {
			return nil, errors.New("enrollment CA is invalid")
		}
		return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: directory, files: files, manifest: manifest}, nil
	}
	csr, err := readEnrollmentFile(filepath.Join(directory, enrollmentCSRFilename), 1<<20)
	if err != nil || enrollmentDigest(csr) != manifest.CSRPublicSHA256 {
		return nil, errors.New("enrollment CSR is invalid")
	}
	request, err := buildEnrollmentRequest(agentID, token, observation, privateKey, csr)
	if err != nil {
		return nil, err
	}
	return &enrollmentGeneration{outputDirectory: outputDirectory, stageDirectory: directory, request: request, files: files, manifest: manifest}, nil
}

func (generation *enrollmentGeneration) readyToPublish() bool {
	return generation != nil && generation.manifest.State == enrollmentGenerationComplete
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
		return nil
	}
	if err := writeEnrollmentFileResumable(filepath.Join(generation.stageDirectory, agentCertificateFilename), certificate); err != nil {
		return err
	}
	if err := writeEnrollmentFileResumable(filepath.Join(generation.stageDirectory, agentCAFilename), serverCA); err != nil {
		return err
	}
	manifest := generation.manifest
	manifest.State = enrollmentGenerationComplete
	manifest.HostID = response.GetHostId()
	manifest.EnrollmentRevision = response.GetEnrollmentRevision()
	manifest.CertificateSHA256 = enrollmentDigest(certificate)
	manifest.CASHA256 = enrollmentDigest(serverCA)
	if err := writeEnrollmentManifestExclusive(filepath.Join(generation.stageDirectory, enrollmentCommitFilename), manifest); err != nil {
		if existing, readErr := readEnrollmentGenerationManifest(filepath.Join(generation.stageDirectory, enrollmentCommitFilename)); readErr != nil || existing != manifest {
			return err
		}
	}
	if err := syncEnrollmentDirectory(generation.stageDirectory); err != nil {
		return errors.New("sync completed enrollment generation failed")
	}
	generation.files.CertificatePEM = certificate
	generation.files.ChainPEM = append([]byte(nil), serverCA...)
	generation.manifest = manifest
	return nil
}

func (generation *enrollmentGeneration) publish() error {
	if generation == nil || generation.manifest.State != enrollmentGenerationComplete {
		return errors.New("enrollment generation is incomplete")
	}
	if generation.published {
		return nil
	}
	loaded, err := loadEnrollmentGeneration(generation.outputDirectory, generation.stageDirectory, generation.manifest.AgentID, generation.manifest.TokenSHA256, nil, hostinventory.Observation{})
	if err != nil || loaded.manifest.State != enrollmentGenerationComplete {
		return errors.New("enrollment generation validation failed")
	}
	if _, err := os.Lstat(generation.outputDirectory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enrollment output path already exists")
	}
	if err := validateCompletedEnrollmentStage(generation.stageDirectory); err != nil {
		return err
	}
	for _, transitionalName := range []string{enrollmentCSRFilename, enrollmentPrepareFilename} {
		if err := os.Remove(filepath.Join(generation.stageDirectory, transitionalName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove enrollment staging file failed")
		}
	}
	if err := syncEnrollmentDirectory(generation.stageDirectory); err != nil {
		return errors.New("sync finalized enrollment generation failed")
	}
	if err := validatePublishedEnrollmentEntries(generation.stageDirectory); err != nil {
		return err
	}
	if err := os.Rename(generation.stageDirectory, generation.outputDirectory); err != nil {
		return errors.New("publish enrollment generation failed")
	}
	if err := syncEnrollmentDirectory(filepath.Dir(generation.outputDirectory)); err != nil {
		return errors.New("sync enrollment output parent failed")
	}
	generation.published = true
	return nil
}

func validateCompletedEnrollmentStage(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !isSecureEnrollmentDirectory(info) {
		return errors.New("enrollment staging directory is unsafe")
	}
	allowed := map[string]struct{}{
		agentKeyFilename: {}, enrollmentCSRFilename: {}, agentCertificateFilename: {}, agentCAFilename: {},
		enrollmentPrepareFilename: {}, enrollmentCommitFilename: {},
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

func writeEnrollmentManifestExclusive(path string, manifest enrollmentGenerationManifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeEnrollmentFileExclusive(path, data)
}

func writeEnrollmentFileResumable(path string, data []byte) error {
	if existing, err := readEnrollmentFile(path, int64(len(data))+1); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("enrollment staging file collides with different content")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("enrollment staging file is unsafe")
	}
	return writeEnrollmentFileExclusive(path, data)
}

func writeEnrollmentFileExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create enrollment staging file failed")
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("secure enrollment staging file failed")
	}
	if err := writeFull(file, data); err != nil {
		_ = file.Close()
		return errors.New("write enrollment staging file failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync enrollment staging file failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close enrollment staging file failed")
	}
	remove = false
	return nil
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
