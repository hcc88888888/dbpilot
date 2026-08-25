package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dbpilot.local/platform/internal/policy"
)

const (
	maximumMetricLabels      = 32
	maximumMetricLabelLength = 256
	defaultHTTPMetricTimeout = 15 * time.Second
	maximumHTTPMetricTimeout = 30 * time.Second
	defaultHTTPResponseBytes = int64(1 << 20)
	maximumHTTPResponseBytes = int64(4 << 20)
	defaultSQLMetricTimeout  = 15 * time.Second
	maximumSQLMetricTimeout  = 30 * time.Second
	defaultPluginTimeout     = 15 * time.Second
	maximumPluginTimeout     = 30 * time.Second
	defaultSQLMetricRows     = 100
	maximumSQLMetricRows     = 10_000
	defaultPluginOutputBytes = int64(1 << 20)
	maximumPluginOutputBytes = int64(4 << 20)
)

var (
	ErrUnsafeHTTPMetric       = errors.New("unsafe HTTP metric specification")
	ErrMetricResponseTooLarge = errors.New("HTTP metric response exceeds limit")
	ErrHTTPMetricRequest      = errors.New("HTTP metric request failed")
	ErrInvalidJSONMetricPath  = errors.New("invalid JSON metric path")
	ErrInvalidMetricValue     = errors.New("invalid metric value")
	ErrUnsafeSQLMetric        = errors.New("unsafe SQL metric statement")
	ErrUnknownPlugin          = errors.New("unknown metric plugin")
	ErrUnsafePluginParameter  = errors.New("unsafe metric plugin parameter")
	ErrPluginDigestMismatch   = errors.New("metric plugin digest mismatch")
	ErrPluginOutputTooLarge   = errors.New("metric plugin output exceeds limit")
	ErrPluginExecution        = errors.New("metric plugin execution failed")
	ErrInvalidMetricName      = errors.New("invalid metric name")
	ErrInvalidMetricType      = errors.New("invalid metric type")
	ErrInvalidMetricLabel     = errors.New("invalid metric label")
	ErrTooManyMetricLabels    = errors.New("too many metric labels")
)

var (
	metricNamePattern     = regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]{0,255}$`)
	metricLabelPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	parameterFlagPattern  = regexp.MustCompile(`^--[A-Za-z][A-Za-z0-9-]{0,62}$`)
	environmentKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// MetricType is kept as an alias so MetricPoint can be consumed without
// leaking an alternative type system alongside the signed policy model.
type MetricType = policy.MetricType

const (
	MetricGauge   = policy.MetricGauge
	MetricCounter = policy.MetricCounter
)

// MetricPoint is a normalized numeric metric ready for the telemetry spool.
type MetricPoint struct {
	Name      string
	Type      MetricType
	Value     float64
	Timestamp time.Time
	Labels    map[string]string
}

// ValidateMetricPoint checks whether a normalized copy of point is safe. Use
// NormalizeMetricPoint when the normalized value must be retained.
func ValidateMetricPoint(point MetricPoint) error {
	_, err := NormalizeMetricPoint(point)
	return err
}

// NormalizeMetricPoint returns a copy with trimmed names and labels, a default
// gauge type, and a UTC timestamp. It is the public boundary for decoder
// implementations before points enter the spool.
func NormalizeMetricPoint(point MetricPoint) (MetricPoint, error) {
	point.Name = strings.TrimSpace(point.Name)
	if !metricNamePattern.MatchString(point.Name) {
		return MetricPoint{}, ErrInvalidMetricName
	}
	if point.Type == "" {
		point.Type = MetricGauge
	}
	if point.Type != MetricGauge && point.Type != MetricCounter {
		return MetricPoint{}, ErrInvalidMetricType
	}
	if math.IsNaN(point.Value) || math.IsInf(point.Value, 0) {
		return MetricPoint{}, ErrInvalidMetricValue
	}
	labels, err := normalizeLabels(point.Labels)
	if err != nil {
		return MetricPoint{}, err
	}
	point.Labels = labels
	if point.Timestamp.IsZero() {
		point.Timestamp = time.Now().UTC()
	} else {
		point.Timestamp = point.Timestamp.UTC()
	}
	return point, nil
}

func normalizeLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) > maximumMetricLabels {
		return nil, ErrTooManyMetricLabels
	}
	normalized := make(map[string]string, len(labels))
	for key, value := range labels {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !metricLabelPattern.MatchString(key) || len(value) > maximumMetricLabelLength || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrInvalidMetricLabel
		}
		if _, exists := normalized[key]; exists {
			return nil, ErrInvalidMetricLabel
		}
		normalized[key] = value
	}
	return normalized, nil
}

func mergeMetricLabels(point map[string]string, additional map[string]string) (map[string]string, error) {
	merged := make(map[string]string, len(point)+len(additional))
	for key, value := range point {
		merged[key] = value
	}
	for key, value := range additional {
		merged[key] = value
	}
	return normalizeLabels(merged)
}

// HTTPCollector collects one numeric value from a bounded HTTPS JSON response.
// The client is injected for mTLS and test transports; requests still receive
// collector-owned deadline, redirect, body-size, and parsing controls.
type HTTPCollector struct{ client *http.Client }

func NewHTTPCollector(clients ...*http.Client) *HTTPCollector {
	client := http.DefaultClient
	if len(clients) > 0 && clients[0] != nil {
		client = clients[0]
	}
	return &HTTPCollector{client: client}
}

func (collector *HTTPCollector) Collect(ctx context.Context, spec policy.HTTPJSONMetricSpec) ([]MetricPoint, error) {
	endpoint, err := url.ParseRequestURI(spec.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && !(spec.AllowInsecureHTTP && endpoint.Scheme == "http")) {
		return nil, ErrUnsafeHTTPMetric
	}
	if spec.BearerToken != "" && (spec.BasicAuth.Username != "" || spec.BasicAuth.Password != "") {
		return nil, ErrUnsafeHTTPMetric
	}
	name, err := metricName(spec.MetricName)
	if err != nil {
		return nil, err
	}
	path, err := jsonObjectPath(spec.JSONPath)
	if err != nil {
		return nil, err
	}
	labels, err := normalizeLabels(spec.Labels)
	if err != nil {
		return nil, err
	}
	timeout := boundedDuration(spec.Timeout, defaultHTTPMetricTimeout, maximumHTTPMetricTimeout)
	limit := boundedInt64(spec.MaxResponseBytes, defaultHTTPResponseBytes, maximumHTTPResponseBytes)
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	approvedHosts := map[string]struct{}{endpoint.Host: {}}
	for _, host := range spec.AllowedRedirectHosts {
		host = strings.TrimSpace(host)
		if host == "" || strings.ContainsAny(host, "/\\@") {
			return nil, ErrUnsafeHTTPMetric
		}
		approvedHosts[host] = struct{}{}
	}
	baseClient := http.DefaultClient
	if collector != nil && collector.client != nil {
		baseClient = collector.client
	}
	client := *baseClient
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		if request.URL.Scheme != "https" && !(spec.AllowInsecureHTTP && request.URL.Scheme == "http") {
			return ErrUnsafeHTTPMetric
		}
		if _, approved := approvedHosts[request.URL.Host]; !approved {
			return ErrUnsafeHTTPMetric
		}
		return nil
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafeHTTPMetric, err)
	}
	for key, value := range spec.Headers {
		if key == "" || strings.EqualFold(key, "Authorization") || strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, ErrUnsafeHTTPMetric
		}
		request.Header.Set(key, value)
	}
	if spec.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+spec.BearerToken)
	}
	if spec.BasicAuth.Username != "" || spec.BasicAuth.Password != "" {
		request.SetBasicAuth(spec.BasicAuth.Username, spec.BasicAuth.Password)
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, ErrUnsafeHTTPMetric) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrHTTPMetricRequest, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrHTTPMetricRequest, response.StatusCode)
	}
	body, err := readBounded(response.Body, limit)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMetricValue, err)
	}
	value, err := jsonPathValue(document, path)
	if err != nil {
		return nil, err
	}
	number, err := metricNumber(value)
	if err != nil {
		return nil, err
	}
	point, err := NormalizeMetricPoint(MetricPoint{Name: name, Type: spec.Type, Value: number, Labels: labels})
	if err != nil {
		return nil, err
	}
	return []MetricPoint{point}, nil
}

func jsonObjectPath(raw string) ([]string, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) == 0 || len(parts) > 16 {
		return nil, ErrInvalidJSONMetricPath
	}
	for _, part := range parts {
		if !metricLabelPattern.MatchString(part) {
			return nil, ErrInvalidJSONMetricPath
		}
	}
	return parts, nil
}

func jsonPathValue(document any, path []string) (any, error) {
	current := document
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, ErrInvalidMetricValue
		}
		var exists bool
		current, exists = object[segment]
		if !exists {
			return nil, ErrInvalidMetricValue
		}
	}
	return current, nil
}

// ReadOnlyQueryer is the only database surface available to SQL metrics. The
// implementation must use a read-only connection and pass maxRows to its
// driver/query layer as a second bound.
type ReadOnlyQueryer interface {
	Query(ctx context.Context, statement string, maxRows int) ([]map[string]any, error)
}

type SQLCollector struct{}

func NewSQLCollector() *SQLCollector { return &SQLCollector{} }

func (*SQLCollector) Collect(ctx context.Context, queryer ReadOnlyQueryer, spec policy.SQLMetricSpec) ([]MetricPoint, error) {
	if queryer == nil {
		return nil, fmt.Errorf("%w: read-only queryer is required", ErrUnsafeSQLMetric)
	}
	statement, err := safeReadOnlyStatement(spec.Statement)
	if err != nil {
		return nil, err
	}
	name, err := metricName(spec.MetricName)
	if err != nil {
		return nil, err
	}
	labels, err := normalizeLabels(spec.Labels)
	if err != nil {
		return nil, err
	}
	if len(spec.LabelColumns)+len(labels) > maximumMetricLabels {
		return nil, ErrTooManyMetricLabels
	}
	valueColumn := strings.TrimSpace(spec.ValueColumn)
	if valueColumn == "" {
		valueColumn = "value"
	}
	timeout := boundedDuration(spec.Timeout, defaultSQLMetricTimeout, maximumSQLMetricTimeout)
	maxRows := boundedInt(spec.MaxRows, defaultSQLMetricRows, maximumSQLMetricRows)
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rows, err := queryer.Query(queryCtx, statement, maxRows)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxRows {
		return nil, fmt.Errorf("%w: queryer exceeded row limit", ErrUnsafeSQLMetric)
	}
	points := make([]MetricPoint, 0, len(rows))
	for _, row := range rows {
		value, exists := row[valueColumn]
		if !exists {
			return nil, ErrInvalidMetricValue
		}
		number, err := metricNumber(value)
		if err != nil {
			return nil, err
		}
		rowLabels := make(map[string]string, len(labels)+len(spec.LabelColumns))
		for key, value := range labels {
			rowLabels[key] = value
		}
		for _, column := range spec.LabelColumns {
			column = strings.TrimSpace(column)
			if !metricLabelPattern.MatchString(column) {
				return nil, ErrInvalidMetricLabel
			}
			value, exists := row[column]
			if !exists {
				return nil, ErrInvalidMetricLabel
			}
			rowLabels[column] = fmt.Sprint(value)
		}
		point, err := NormalizeMetricPoint(MetricPoint{Name: name, Type: spec.Type, Value: number, Labels: rowLabels})
		if err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, nil
}

func safeReadOnlyStatement(raw string) (string, error) {
	statement, err := stripSQLComments(raw)
	if err != nil {
		return "", ErrUnsafeSQLMetric
	}
	statement = strings.TrimSpace(statement)
	if strings.HasSuffix(statement, ";") {
		statement = strings.TrimSpace(strings.TrimSuffix(statement, ";"))
	}
	if statement == "" || strings.Contains(statement, ";") {
		return "", ErrUnsafeSQLMetric
	}
	tokens := sqlTokens(statement)
	if len(tokens) == 0 || (tokens[0] != "SELECT" && tokens[0] != "WITH") {
		return "", ErrUnsafeSQLMetric
	}
	for _, token := range tokens {
		switch token {
		case "INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "CALL", "EXEC", "EXECUTE", "DO", "SET", "BEGIN", "COMMIT", "ROLLBACK", "VACUUM", "ANALYZE", "LOCK", "INTO", "OUTFILE", "DUMPFILE":
			return "", ErrUnsafeSQLMetric
		}
	}
	return statement, nil
}

func stripSQLComments(raw string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(raw); {
		switch {
		case raw[index] == '\'' || raw[index] == '"':
			quote := raw[index]
			out.WriteByte(raw[index])
			index++
			closed := false
			for index < len(raw) {
				out.WriteByte(raw[index])
				if raw[index] == quote {
					if index+1 < len(raw) && raw[index+1] == quote {
						out.WriteByte(raw[index+1])
						index += 2
						continue
					}
					index++
					closed = true
					break
				}
				index++
			}
			if !closed {
				return "", errors.New("unterminated SQL quote")
			}
		case index+1 < len(raw) && raw[index:index+2] == "--":
			index += 2
			for index < len(raw) && raw[index] != '\n' {
				index++
			}
		case index+1 < len(raw) && raw[index:index+2] == "/*":
			end := strings.Index(raw[index+2:], "*/")
			if end < 0 {
				return "", errors.New("unterminated SQL comment")
			}
			index += end + 4
		default:
			out.WriteByte(raw[index])
			index++
		}
	}
	return out.String(), nil
}

func sqlTokens(statement string) []string {
	var tokens []string
	for index := 0; index < len(statement); {
		if statement[index] == '\'' || statement[index] == '"' {
			quote := statement[index]
			index++
			for index < len(statement) {
				if statement[index] == quote {
					if index+1 < len(statement) && statement[index+1] == quote {
						index += 2
						continue
					}
					index++
					break
				}
				index++
			}
			continue
		}
		if (statement[index] >= 'a' && statement[index] <= 'z') || (statement[index] >= 'A' && statement[index] <= 'Z') {
			start := index
			for index < len(statement) && ((statement[index] >= 'a' && statement[index] <= 'z') || (statement[index] >= 'A' && statement[index] <= 'Z')) {
				index++
			}
			tokens = append(tokens, strings.ToUpper(statement[start:index]))
			continue
		}
		index++
	}
	return tokens
}

// PluginParameter is registry-owned metadata for one declarative parameter.
// Flag is a fixed argument prefix, not a policy-controlled command fragment.
type PluginParameter struct {
	Flag         string
	MaxLength    int
	ValuePattern string
}

type PluginOutputDecoder func(output []byte) ([]MetricPoint, error)

// RegisteredPlugin is returned only by the local runtime registry. Policy can
// select an ID and provide values for AllowedParameters; it cannot select the
// executable, base arguments, decoder, environment, digest, or limits.
type RegisteredPlugin struct {
	Executable        string
	SHA256            string
	FixedArguments    []string
	AllowedParameters map[string]PluginParameter
	Environment       map[string]string
	Timeout           time.Duration
	MaxOutputBytes    int64
	Decoder           PluginOutputDecoder
}

type PluginRegistry interface {
	Resolve(pluginID string) (RegisteredPlugin, error)
}

type PluginCollector struct{}

func NewPluginCollector() *PluginCollector { return &PluginCollector{} }

func (*PluginCollector) Collect(ctx context.Context, registry PluginRegistry, spec policy.PluginMetricSpec) ([]MetricPoint, error) {
	if registry == nil || strings.TrimSpace(spec.PluginID) == "" {
		return nil, ErrUnknownPlugin
	}
	plugin, err := registry.Resolve(spec.PluginID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPlugin, err)
	}
	if err := validateRegisteredPlugin(plugin); err != nil {
		return nil, err
	}
	labels, err := normalizeLabels(spec.Labels)
	if err != nil {
		return nil, err
	}
	arguments, err := pluginArguments(plugin, spec.Params)
	if err != nil {
		return nil, err
	}
	if err := verifyPluginDigest(plugin.Executable, plugin.SHA256); err != nil {
		return nil, err
	}
	timeout := boundedDuration(plugin.Timeout, defaultPluginTimeout, maximumPluginTimeout)
	if spec.Timeout > 0 && spec.Timeout < timeout {
		timeout = spec.Timeout
	}
	limit := boundedInt64(plugin.MaxOutputBytes, defaultPluginOutputBytes, maximumPluginOutputBytes)
	if spec.MaxOutputBytes > 0 && spec.MaxOutputBytes < limit {
		limit = spec.MaxOutputBytes
	}
	if limit <= 0 {
		return nil, ErrPluginOutputTooLarge
	}
	pluginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(pluginCtx, plugin.Executable, arguments...)
	command.Env, err = pluginEnvironment(plugin.Environment)
	if err != nil {
		return nil, err
	}
	output := &boundedBuffer{limit: limit}
	command.Stdout = output
	command.Stderr = output
	err = command.Run()
	if output.exceeded {
		return nil, ErrPluginOutputTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPluginExecution, err)
	}
	points, err := plugin.Decoder(output.Bytes())
	if err != nil {
		return nil, err
	}
	for index := range points {
		points[index].Labels, err = mergeMetricLabels(points[index].Labels, labels)
		if err != nil {
			return nil, err
		}
		points[index], err = NormalizeMetricPoint(points[index])
		if err != nil {
			return nil, err
		}
	}
	return points, nil
}

func validateRegisteredPlugin(plugin RegisteredPlugin) error {
	if !filepath.IsAbs(plugin.Executable) || plugin.SHA256 == "" || plugin.Decoder == nil {
		return ErrUnknownPlugin
	}
	switch strings.ToLower(filepath.Ext(plugin.Executable)) {
	case ".bat", ".cmd", ".ps1", ".sh", ".bash", ".zsh":
		// These are command-interpreter launchers on at least one supported
		// platform. A registry entry must reference a native executable.
		return ErrUnknownPlugin
	}
	if !hasNativeExecutableHeader(plugin.Executable) {
		return ErrUnknownPlugin
	}
	if _, err := hex.DecodeString(plugin.SHA256); err != nil || len(plugin.SHA256) != sha256.Size*2 {
		return ErrPluginDigestMismatch
	}
	for _, argument := range plugin.FixedArguments {
		if strings.ContainsRune(argument, '\x00') {
			return ErrUnknownPlugin
		}
	}
	for _, parameter := range plugin.AllowedParameters {
		if !parameterFlagPattern.MatchString(parameter.Flag) || parameter.MaxLength <= 0 || parameter.MaxLength > 4096 {
			return ErrUnknownPlugin
		}
		if parameter.ValuePattern != "" {
			if _, err := regexp.Compile(parameter.ValuePattern); err != nil {
				return ErrUnknownPlugin
			}
		}
	}
	return nil
}

// hasNativeExecutableHeader rejects scripts before command construction. A
// fixed registry path is not sufficient: an extensionless Unix script can use
// a shebang, while Windows may dispatch script extensions to an interpreter.
// Accept only the native executable format for the current platform.
func hasNativeExecutableHeader(executable string) bool {
	file, err := os.Open(executable)
	if err != nil {
		return false
	}
	defer file.Close()
	header := make([]byte, 4)
	read, err := io.ReadFull(file, header)
	if err != nil && err != io.ErrUnexpectedEOF {
		return false
	}
	header = header[:read]
	if bytes.HasPrefix(header, []byte("#!")) {
		return false
	}
	switch runtime.GOOS {
	case "windows":
		return len(header) >= 2 && header[0] == 'M' && header[1] == 'Z'
	case "darwin":
		return len(header) == 4 && (bytes.Equal(header, []byte{0xce, 0xfa, 0xed, 0xfe}) ||
			bytes.Equal(header, []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
			bytes.Equal(header, []byte{0xfe, 0xed, 0xfa, 0xce}) ||
			bytes.Equal(header, []byte{0xfe, 0xed, 0xfa, 0xcf}))
	default:
		return len(header) == 4 && bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'})
	}
}

func pluginArguments(plugin RegisteredPlugin, values map[string]string) ([]string, error) {
	arguments := append([]string(nil), plugin.FixedArguments...)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parameter, allowed := plugin.AllowedParameters[key]
		value := values[key]
		if !allowed || len(value) > parameter.MaxLength || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrUnsafePluginParameter
		}
		if parameter.ValuePattern != "" {
			pattern := regexp.MustCompile(parameter.ValuePattern)
			if !pattern.MatchString(value) {
				return nil, ErrUnsafePluginParameter
			}
		}
		arguments = append(arguments, parameter.Flag+"="+value)
	}
	return arguments, nil
}

func verifyPluginDigest(executable string, expected string) error {
	binary, err := os.ReadFile(executable)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginDigestMismatch, err)
	}
	digest := sha256.Sum256(binary)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expected) {
		return ErrPluginDigestMismatch
	}
	return nil
}

func pluginEnvironment(environment map[string]string) ([]string, error) {
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		value := environment[key]
		if !environmentKeyPattern.MatchString(key) || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrUnknownPlugin
		}
		values = append(values, key+"="+value)
	}
	return values, nil
}

type boundedBuffer struct {
	data     bytes.Buffer
	limit    int64
	exceeded bool
	mu       sync.Mutex
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if int64(buffer.data.Len())+int64(len(value)) > buffer.limit {
		remaining := buffer.limit - int64(buffer.data.Len())
		if remaining > 0 {
			_, _ = buffer.data.Write(value[:remaining])
		}
		buffer.exceeded = true
		return len(value), nil
	}
	return buffer.data.Write(value)
}

func (buffer *boundedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return bytes.Clone(buffer.data.Bytes())
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrMetricResponseTooLarge
	}
	return body, nil
}

func metricNumber(value any) (float64, error) {
	var raw string
	switch converted := value.(type) {
	case json.Number:
		raw = string(converted)
	case string:
		raw = strings.TrimSpace(converted)
	case []byte:
		raw = strings.TrimSpace(string(converted))
	case int:
		return float64(converted), nil
	case int8:
		return float64(converted), nil
	case int16:
		return float64(converted), nil
	case int32:
		return float64(converted), nil
	case int64:
		return float64(converted), nil
	case uint:
		return float64(converted), nil
	case uint8:
		return float64(converted), nil
	case uint16:
		return float64(converted), nil
	case uint32:
		return float64(converted), nil
	case uint64:
		if converted > math.MaxInt64 {
			return 0, ErrInvalidMetricValue
		}
		return float64(converted), nil
	case float32:
		return checkedMetricNumber(float64(converted))
	case float64:
		return checkedMetricNumber(converted)
	default:
		return 0, ErrInvalidMetricValue
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, ErrInvalidMetricValue
	}
	return checkedMetricNumber(parsed)
}

func checkedMetricNumber(value float64) (float64, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, ErrInvalidMetricValue
	}
	return value, nil
}

func metricName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !metricNamePattern.MatchString(name) {
		return "", ErrInvalidMetricName
	}
	return name, nil
}

func boundedDuration(value, fallback, maximum time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func boundedInt(value, fallback, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func boundedInt64(value, fallback, maximum int64) int64 {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}
