package inspection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maximumReportBytes = 1 << 20

var (
	ErrInvalidReport  = errors.New("invalid inspection report")
	ErrUnsafeReport   = errors.New("unsafe inspection report content")
	ErrReportTooLarge = errors.New("inspection report exceeds maximum size")
)

type ReportPolicy struct {
	ID      string `json:"id,omitempty"`
	Version int64  `json:"version,omitempty"`
	Name    string `json:"name,omitempty"`
}

type ReportItem struct {
	ID       string `json:"id"`
	Version  int    `json:"version"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type ReportTarget struct {
	TargetID    string       `json:"target_id"`
	DisplayName string       `json:"display_name"`
	Host        string       `json:"host"`
	Status      TargetStatus `json:"status"`
	ErrorCode   string       `json:"error_code,omitempty"`
	CommandID   string       `json:"command_id"`
}

type ReportFinding struct {
	ID                string            `json:"id,omitempty"`
	TargetID          string            `json:"target_id"`
	ItemID            string            `json:"item_id"`
	ItemVersion       int               `json:"item_version"`
	Level             FindingLevel      `json:"level"`
	ObservedAt        time.Time         `json:"observed_at"`
	WarningThreshold  *float64          `json:"warning_threshold,omitempty"`
	CriticalThreshold *float64          `json:"critical_threshold,omitempty"`
	Evidence          map[string]string `json:"evidence"`
	Summary           string            `json:"summary,omitempty"`
	Recommendation    string            `json:"recommendation,omitempty"`
}

type ReportCommandReference struct {
	TargetID  string `json:"target_id"`
	CommandID string `json:"command_id"`
}

type ReportReferences struct {
	JobID            string                   `json:"job_id"`
	Commands         []ReportCommandReference `json:"commands"`
	AuditCorrelation string                   `json:"audit_correlation"`
}

type ReportDocument struct {
	ReportID    string           `json:"report_id"`
	RunID       string           `json:"run_id"`
	Status      RunStatus        `json:"status"`
	Summary     string           `json:"summary"`
	Policy      ReportPolicy     `json:"policy"`
	Items       []ReportItem     `json:"items"`
	Targets     []ReportTarget   `json:"targets"`
	Findings    []ReportFinding  `json:"findings"`
	References  ReportReferences `json:"references"`
	GeneratedAt time.Time        `json:"generated_at"`
}

func RenderJSON(snapshot ReportSnapshot) ([]byte, error) {
	document, err := canonicalReportDocument(snapshot)
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encode JSON", ErrInvalidReport)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumReportBytes {
		return nil, ErrReportTooLarge
	}
	return encoded, nil
}

func RenderHTML(snapshot ReportSnapshot) ([]byte, error) {
	document, err := canonicalReportDocument(snapshot)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := inspectionReportTemplate.Execute(&output, document); err != nil {
		return nil, fmt.Errorf("%w: encode HTML", ErrInvalidReport)
	}
	if output.Len() > maximumReportBytes {
		return nil, ErrReportTooLarge
	}
	return output.Bytes(), nil
}

func canonicalReportDocument(snapshot ReportSnapshot) (ReportDocument, error) {
	var document ReportDocument
	if snapshot.Document != nil {
		if len(snapshot.Document.Items) > maxSnapshotItems || len(snapshot.Document.Targets) > maxSnapshotTargets || len(snapshot.Document.Findings) > maxSnapshotObservations {
			return ReportDocument{}, ErrReportTooLarge
		}
		document = cloneReportDocument(*snapshot.Document)
	} else {
		if len(snapshot.Snapshot) == 0 || len(snapshot.Snapshot) > maximumReportBytes {
			if len(snapshot.Snapshot) > maximumReportBytes {
				return ReportDocument{}, ErrReportTooLarge
			}
			return ReportDocument{}, ErrInvalidReport
		}
		decoder := json.NewDecoder(bytes.NewReader(snapshot.Snapshot))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return ReportDocument{}, fmt.Errorf("%w: decode snapshot", ErrInvalidReport)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return ReportDocument{}, fmt.Errorf("%w: trailing snapshot data", ErrInvalidReport)
		}
	}
	if (snapshot.ID != "" && snapshot.ID != document.ReportID) || (snapshot.RunID != "" && snapshot.RunID != document.RunID) || (snapshot.PolicyID != "" && snapshot.PolicyID != document.Policy.ID) || (!snapshot.GeneratedAt.IsZero() && !snapshot.GeneratedAt.Equal(document.GeneratedAt)) {
		return ReportDocument{}, ErrInvalidReport
	}
	sort.Slice(document.Items, func(i, j int) bool {
		if document.Items[i].ID != document.Items[j].ID {
			return document.Items[i].ID < document.Items[j].ID
		}
		return document.Items[i].Version < document.Items[j].Version
	})
	sort.Slice(document.Targets, func(i, j int) bool { return document.Targets[i].TargetID < document.Targets[j].TargetID })
	sort.Slice(document.Findings, func(i, j int) bool {
		if document.Findings[i].TargetID != document.Findings[j].TargetID {
			return document.Findings[i].TargetID < document.Findings[j].TargetID
		}
		if document.Findings[i].ItemID != document.Findings[j].ItemID {
			return document.Findings[i].ItemID < document.Findings[j].ItemID
		}
		return document.Findings[i].ItemVersion < document.Findings[j].ItemVersion
	})
	sort.Slice(document.References.Commands, func(i, j int) bool {
		if document.References.Commands[i].TargetID != document.References.Commands[j].TargetID {
			return document.References.Commands[i].TargetID < document.References.Commands[j].TargetID
		}
		return document.References.Commands[i].CommandID < document.References.Commands[j].CommandID
	})
	if err := validateReportDocument(document); err != nil {
		return ReportDocument{}, err
	}
	return document, nil
}

func validateReportDocument(document ReportDocument) error {
	if !validID(document.RunID) || document.ReportID != "inspection-report-"+document.RunID || !isTerminalRunStatus(document.Status) || !isUTC(document.GeneratedAt) || !validID(document.References.JobID) || !canonicalText(document.References.AuditCorrelation) || len(document.Items) == 0 || len(document.Items) > maxSnapshotItems || len(document.Targets) == 0 || len(document.Targets) > maxSnapshotTargets || len(document.Findings) > maxSnapshotObservations {
		return ErrInvalidReport
	}
	if (document.Policy.ID == "") != (document.Policy.Version == 0) || (document.Policy.ID != "" && (!validID(document.Policy.ID) || document.Policy.Version < 1)) {
		return ErrInvalidReport
	}
	for _, value := range []string{document.Summary, document.Policy.Name, document.References.AuditCorrelation} {
		if err := validateReportText(value); err != nil {
			return err
		}
	}
	seenItems := make(map[string]struct{}, len(document.Items))
	for _, item := range document.Items {
		key := fmt.Sprintf("%s\x00%d", item.ID, item.Version)
		if !validID(item.ID) || item.Version < 1 {
			return ErrInvalidReport
		}
		if _, duplicate := seenItems[key]; duplicate {
			return ErrInvalidReport
		}
		seenItems[key] = struct{}{}
		for _, value := range []string{item.Name, item.Category} {
			if err := validateReportText(value); err != nil {
				return err
			}
		}
	}
	seenTargets := make(map[string]struct{}, len(document.Targets))
	for _, target := range document.Targets {
		if !validID(target.TargetID) || !validID(target.CommandID) || !validTerminalTargetStatus(target.Status) {
			return ErrInvalidReport
		}
		if _, duplicate := seenTargets[target.TargetID]; duplicate {
			return ErrInvalidReport
		}
		seenTargets[target.TargetID] = struct{}{}
		for _, value := range []string{target.DisplayName, target.Host, target.ErrorCode} {
			if err := validateReportText(value); err != nil {
				return err
			}
		}
	}
	for _, finding := range document.Findings {
		if _, ok := seenTargets[finding.TargetID]; !ok || (finding.ID != "" && !validID(finding.ID)) || !validID(finding.ItemID) || finding.ItemVersion < 1 || !validFindingLevel(finding.Level) || !isUTC(finding.ObservedAt) || (finding.WarningThreshold == nil) != (finding.CriticalThreshold == nil) {
			return ErrInvalidReport
		}
		for key, value := range finding.Evidence {
			if err := validateReportText(key); err != nil {
				return err
			}
			if err := validateReportText(value); err != nil {
				return err
			}
		}
		for _, value := range []string{finding.Summary, finding.Recommendation} {
			if err := validateReportText(value); err != nil {
				return err
			}
		}
	}
	if len(document.References.Commands) != len(document.Targets) {
		return ErrInvalidReport
	}
	for index, reference := range document.References.Commands {
		if reference.TargetID != document.Targets[index].TargetID || reference.CommandID != document.Targets[index].CommandID {
			return ErrInvalidReport
		}
	}
	return nil
}

func validStoredReportID(value string) bool {
	if validID(value) {
		return true
	}
	const prefix = "inspection-report-"
	return strings.HasPrefix(value, prefix) && validID(strings.TrimPrefix(value, prefix))
}

func validateReportText(value string) error {
	if len(value) > maximumReportBytes {
		return ErrReportTooLarge
	}
	normalized := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "pwd=", "authorization:", "bearer ", "connection_string", "connection uri", "raw_log", "raw log", "-----begin private key-----"} {
		if strings.Contains(normalized, marker) {
			return ErrUnsafeReport
		}
	}
	if containsCredentialBearingConnectionMaterial(value) {
		return ErrUnsafeReport
	}
	return nil
}

var reportURI = regexp.MustCompile(`(?i)(?:jdbc:)?[a-z][a-z0-9+.-]*://[^\s<>"']+`)

func containsCredentialBearingConnectionMaterial(value string) bool {
	if strings.Contains(strings.ToLower(value), "jdbc:") {
		return true
	}
	databaseSchemes := map[string]struct{}{
		"postgres": {}, "postgresql": {}, "mysql": {}, "mariadb": {}, "mongodb": {}, "mongodb+srv": {},
		"oracle": {}, "sqlserver": {}, "mssql": {}, "redis": {},
	}
	for _, candidate := range reportURI.FindAllString(value, -1) {
		candidate = strings.TrimRight(candidate, ".,;:)]}")
		if strings.HasPrefix(strings.ToLower(candidate), "jdbc:") {
			return true
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme == "" {
			continue
		}
		if _, database := databaseSchemes[strings.ToLower(parsed.Scheme)]; database {
			return true
		}
		if parsed.User != nil && parsed.User.Username() != "" {
			return true
		}
		for key := range parsed.Query() {
			if containsSecretMarker(key) {
				return true
			}
		}
	}
	return false
}

func validTerminalTargetStatus(status TargetStatus) bool {
	return status == TargetSucceeded || status == TargetFailed || status == TargetUnsupported || status == TargetCancelled
}

func isTerminalRunStatus(status RunStatus) bool {
	return status == RunCompleted || status == RunPartial || status == RunFailed || status == RunCancelled
}

func cloneReportDocument(value ReportDocument) ReportDocument {
	value.Items = append([]ReportItem(nil), value.Items...)
	value.Targets = append([]ReportTarget(nil), value.Targets...)
	value.Findings = append([]ReportFinding(nil), value.Findings...)
	for index := range value.Findings {
		source := value.Findings[index].Evidence
		value.Findings[index].Evidence = make(map[string]string, len(source))
		for key, item := range source {
			value.Findings[index].Evidence[key] = item
		}
	}
	value.References.Commands = append([]ReportCommandReference(nil), value.References.Commands...)
	return value
}

var inspectionReportTemplate = template.Must(template.New("inspection-report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inspection report {{.ReportID}}</title><style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccd1d1;padding:.45rem;text-align:left;vertical-align:top}th{background:#f4f6f7}code{overflow-wrap:anywhere}.muted{color:#566573}</style></head>
<body><h1>Inspection report {{.ReportID}}</h1><p>{{.Summary}}</p>
<dl><dt>Run</dt><dd>{{.RunID}}</dd><dt>Status</dt><dd>{{.Status}}</dd><dt>Generated</dt><dd>{{.GeneratedAt.Format "2006-01-02T15:04:05.999999999Z07:00"}}</dd><dt>Policy</dt><dd>{{.Policy.ID}} version {{.Policy.Version}} — {{.Policy.Name}}</dd><dt>Job</dt><dd>{{.References.JobID}}</dd><dt>Audit correlation</dt><dd>{{.References.AuditCorrelation}}</dd></dl>
<h2>Items</h2><table><thead><tr><th>ID</th><th>Version</th><th>Name</th><th>Category</th></tr></thead><tbody>{{range .Items}}<tr><td>{{.ID}}</td><td>version {{.Version}}</td><td>{{.Name}}</td><td>{{.Category}}</td></tr>{{end}}</tbody></table>
<h2>Targets</h2><table><thead><tr><th>Target</th><th>Host</th><th>Status</th><th>Command</th><th>Error</th></tr></thead><tbody>{{range .Targets}}<tr><td>{{.TargetID}} — {{.DisplayName}}</td><td>{{.Host}}</td><td>{{.Status}}</td><td>{{.CommandID}}</td><td>{{.ErrorCode}}</td></tr>{{end}}</tbody></table>
<h2>Findings</h2><table><thead><tr><th>Target</th><th>Item version</th><th>Level</th><th>Observed</th><th>Warning threshold</th><th>Critical threshold</th><th>Evidence</th><th>Summary</th><th>Recommendation</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.TargetID}}</td><td>{{.ItemID}} version {{.ItemVersion}}</td><td>{{.Level}}</td><td>{{.ObservedAt.Format "2006-01-02T15:04:05.999999999Z07:00"}}</td><td>{{if .WarningThreshold}}{{.WarningThreshold}}{{end}}</td><td>{{if .CriticalThreshold}}{{.CriticalThreshold}}{{end}}</td><td>{{range $key,$value := .Evidence}}<div><code>{{$key}}</code>: {{$value}}</div>{{end}}</td><td>{{.Summary}}</td><td>{{.Recommendation}}</td></tr>{{end}}</tbody></table>
<h2>Command references</h2><ul>{{range .References.Commands}}<li>{{.TargetID}} — {{.CommandID}}</li>{{end}}</ul></body></html>
`))
