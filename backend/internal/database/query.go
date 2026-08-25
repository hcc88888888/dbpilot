package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	readOnlyQueryTimeout = 30 * time.Second
	maximumMetricRows    = 10_000
	maximumMetricColumns = 32
)

var (
	ErrUnknownMetricTemplate   = errors.New("unknown metric template")
	ErrInvalidMetricTemplate   = errors.New("invalid metric template")
	ErrUnsafeReadOnlyStatement = errors.New("unsafe read-only statement")
	ErrQueryResultBounds       = errors.New("query result exceeds metric bounds")
	ErrNonNumericMetricValue   = errors.New("metric value is not numeric")

	metricTemplateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	metricColumnPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// MetricTemplate is runtime-owned SQL for one named metric. Policy can select
// its ID, but it cannot supply or alter Statement.
type MetricTemplate struct {
	ID           string
	Statement    string
	MaxRows      int
	ValueColumns []string
}

// TemplateCatalog is the closed, runtime-owned collection of approved metric
// queries for each database family.
type TemplateCatalog interface {
	Lookup(EngineFamily, string) (MetricTemplate, bool)
}

// Queryer is the minimal database/sql query surface needed by the template
// executor. Adapters pass a read-only connection behind this interface.
type Queryer interface {
	QueryContext(context.Context, string, ...any) (Rows, error)
}

// Rows is the bounded scanning surface used by ExecuteReadOnly.
type Rows interface {
	Columns() ([]string, error)
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}

// ExecuteReadOnly selects one pre-registered metric template and executes it
// with a bounded context. It never accepts a statement from policy input.
func ExecuteReadOnly(ctx context.Context, db Queryer, family EngineFamily, catalog TemplateCatalog, metricID string, args map[string]any, maxRows int) (_ []MetricRow, resultErr error) {
	if db == nil || catalog == nil {
		return nil, fmt.Errorf("%w: queryer and catalog are required", ErrInvalidMetricTemplate)
	}
	metricID = strings.TrimSpace(metricID)
	if !metricTemplateIDPattern.MatchString(metricID) {
		return nil, fmt.Errorf("%w: metric ID", ErrInvalidMetricTemplate)
	}
	template, found := catalog.Lookup(family, metricID)
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrUnknownMetricTemplate, metricID)
	}
	if err := validateTemplate(template, metricID); err != nil {
		return nil, err
	}
	rowLimit := template.MaxRows
	if maxRows > 0 && maxRows < rowLimit {
		rowLimit = maxRows
	}
	if rowLimit <= 0 || rowLimit > maximumMetricRows {
		return nil, fmt.Errorf("%w: row limit", ErrInvalidMetricTemplate)
	}

	queryCtx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	rows, err := db.QueryContext(queryCtx, template.Statement, namedArguments(args)...)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, fmt.Errorf("%w: queryer returned nil rows", ErrQueryResultBounds)
	}
	defer func() {
		if err := rows.Close(); resultErr == nil && err != nil {
			resultErr = err
		}
	}()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columns) == 0 || len(columns) > maximumMetricColumns || len(columns) != len(template.ValueColumns) {
		return nil, fmt.Errorf("%w: columns", ErrQueryResultBounds)
	}
	for index, column := range columns {
		if column != template.ValueColumns[index] {
			return nil, fmt.Errorf("%w: unexpected column %q", ErrQueryResultBounds, column)
		}
	}

	metricRows := make([]MetricRow, 0, rowLimit)
	for rows.Next() {
		if len(metricRows) == rowLimit {
			return nil, fmt.Errorf("%w: rows", ErrQueryResultBounds)
		}
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		metricRow := make(MetricRow, len(columns))
		for index, value := range values {
			number, err := metricNumber(value)
			if err != nil {
				return nil, err
			}
			metricRow[columns[index]] = number
		}
		metricRows = append(metricRows, metricRow)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return metricRows, nil
}

func validateTemplate(template MetricTemplate, requestedID string) error {
	if strings.TrimSpace(template.ID) != requestedID || !metricTemplateIDPattern.MatchString(template.ID) {
		return fmt.Errorf("%w: ID", ErrInvalidMetricTemplate)
	}
	if template.MaxRows <= 0 || template.MaxRows > maximumMetricRows {
		return fmt.Errorf("%w: max rows", ErrInvalidMetricTemplate)
	}
	if len(template.ValueColumns) == 0 || len(template.ValueColumns) > maximumMetricColumns {
		return fmt.Errorf("%w: value columns", ErrInvalidMetricTemplate)
	}
	seen := make(map[string]struct{}, len(template.ValueColumns))
	for _, column := range template.ValueColumns {
		if !metricColumnPattern.MatchString(column) {
			return fmt.Errorf("%w: value column", ErrInvalidMetricTemplate)
		}
		if _, duplicate := seen[column]; duplicate {
			return fmt.Errorf("%w: duplicate value column", ErrInvalidMetricTemplate)
		}
		seen[column] = struct{}{}
	}
	if err := validateReadOnlyStatement(template.Statement); err != nil {
		return err
	}
	return nil
}

func validateReadOnlyStatement(statement string) error {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return ErrUnsafeReadOnlyStatement
	}
	tokens, hasComment, hasSemicolon, valid := sqlAnalysisTokens(statement)
	if !valid || hasComment || hasSemicolon || len(tokens) == 0 || (tokens[0] != "SELECT" && tokens[0] != "WITH") {
		return ErrUnsafeReadOnlyStatement
	}
	for _, token := range tokens {
		switch token {
		case "INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "CALL", "EXEC", "EXECUTE", "DO", "SET", "BEGIN", "COMMIT", "ROLLBACK", "VACUUM", "ANALYZE", "LOCK", "INTO", "OUTFILE", "DUMPFILE":
			return ErrUnsafeReadOnlyStatement
		}
	}
	return nil
}

// sqlAnalysisTokens ignores quoted values while recognizing dangerous syntax
// outside them. Comments are detected (and rejected) rather than executed.
func sqlAnalysisTokens(statement string) (tokens []string, hasComment, hasSemicolon, valid bool) {
	for index := 0; index < len(statement); {
		character := statement[index]
		if character == '\'' || character == '"' {
			quote := character
			index++
			closed := false
			for index < len(statement) {
				if statement[index] == quote {
					if index+1 < len(statement) && statement[index+1] == quote {
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
				return nil, false, false, false
			}
			continue
		}
		if index+1 < len(statement) && ((statement[index] == '-' && statement[index+1] == '-') || (statement[index] == '/' && statement[index+1] == '*')) {
			hasComment = true
			index += 2
			continue
		}
		if character == ';' {
			hasSemicolon = true
			index++
			continue
		}
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') {
			start := index
			for index < len(statement) && ((statement[index] >= 'a' && statement[index] <= 'z') || (statement[index] >= 'A' && statement[index] <= 'Z')) {
				index++
			}
			tokens = append(tokens, strings.ToUpper(statement[start:index]))
			continue
		}
		index++
	}
	return tokens, hasComment, hasSemicolon, true
}

func namedArguments(values map[string]any) []any {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	arguments := make([]any, 0, len(keys))
	for _, key := range keys {
		arguments = append(arguments, sql.Named(key, values[key]))
	}
	return arguments
}

func metricNumber(value any) (float64, error) {
	var number float64
	switch converted := value.(type) {
	case int:
		number = float64(converted)
	case int8:
		number = float64(converted)
	case int16:
		number = float64(converted)
	case int32:
		number = float64(converted)
	case int64:
		number = float64(converted)
	case uint:
		number = float64(converted)
	case uint8:
		number = float64(converted)
	case uint16:
		number = float64(converted)
	case uint32:
		number = float64(converted)
	case uint64:
		if converted > math.MaxInt64 {
			return 0, ErrNonNumericMetricValue
		}
		number = float64(converted)
	case float32:
		number = float64(converted)
	case float64:
		number = converted
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(converted), 64)
		if err != nil {
			return 0, ErrNonNumericMetricValue
		}
		number = parsed
	case []byte:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(string(converted)), 64)
		if err != nil {
			return 0, ErrNonNumericMetricValue
		}
		number = parsed
	default:
		return 0, ErrNonNumericMetricValue
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, ErrNonNumericMetricValue
	}
	return number, nil
}
