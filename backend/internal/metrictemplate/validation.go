package metrictemplate

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DialectValidator is the authoritative plugin-owned AST validation boundary.
// ValidateDefinition below is intentionally only a bounded structural gate.
type DialectValidator interface {
	ValidateReadOnly(context.Context, TemplateDefinition) (ValidatedDefinition, error)
}

// DeterministicDialectValidator is a narrow Task12 fixture adapter. Production
// plugins replace it with their dialect AST validator in Task13.
type DeterministicDialectValidator struct {
	Validate func(context.Context, TemplateDefinition) error
}

func (validator DeterministicDialectValidator) ValidateReadOnly(ctx context.Context, definition TemplateDefinition) (ValidatedDefinition, error) {
	if ctx == nil || validator.Validate == nil {
		return ValidatedDefinition{}, ErrDialectRejected
	}
	if err := validator.Validate(ctx, definition); err != nil {
		return ValidatedDefinition{}, err
	}
	return ValidateDefinition(definition)
}

func ValidateDefinition(definition TemplateDefinition) (ValidatedDefinition, error) {
	if definition.TimeoutSeconds == 0 {
		definition.TimeoutSeconds = 5
	}
	if definition.MaxRows == 0 {
		definition.MaxRows = 1
	}
	definition.Variants = normalizedStrings(definition.Variants)
	if !validDefinitionShape(definition) || !structurallyReadOnlySQL(definition.ReadOnlyStatement) {
		return ValidatedDefinition{}, ErrValidationFailed
	}
	return ValidatedDefinition{
		DatabaseFamily: definition.DatabaseFamily, Variants: append([]string(nil), definition.Variants...), Name: definition.Name, Description: definition.Description,
		QueryKind: definition.QueryKind, CollectionIntervalSeconds: definition.CollectionIntervalSeconds, TimeoutSeconds: definition.TimeoutSeconds,
		MaxRows: definition.MaxRows, MaxColumns: definition.MaxColumns, ValueMappings: append([]ValueMapping(nil), definition.ValueMappings...),
		LabelMappings: append([]LabelMapping(nil), definition.LabelMappings...), DatabaseVersionRange: definition.DatabaseVersionRange,
		PluginVersionRange: definition.PluginVersionRange, CardinalityLimit: definition.CardinalityLimit, QueryDigest: DefinitionDigest(definition.ReadOnlyStatement),
	}, nil
}

func validDefinitionShape(value TemplateDefinition) bool {
	if !familyPattern.MatchString(value.DatabaseFamily) || len(value.Variants) == 0 || len(value.Variants) > MaximumVariants || !bounded(value.Name, 120, true) || !bounded(value.Description, 1000, false) || value.QueryKind != QuerySQL || value.ReadOnlyStatement == "" || value.ReadOnlyStatement != strings.TrimSpace(value.ReadOnlyStatement) || len([]byte(value.ReadOnlyStatement)) > MaximumStatementBytes || !utf8.ValidString(value.ReadOnlyStatement) || strings.ContainsRune(value.ReadOnlyStatement, 0) || value.CollectionIntervalSeconds < 10 || value.CollectionIntervalSeconds > 86400 || value.TimeoutSeconds < 1 || value.TimeoutSeconds > 30 || value.MaxRows < 1 || value.MaxRows > 100 || value.MaxColumns < 1 || value.MaxColumns > 32 || len(value.ValueMappings) == 0 || len(value.ValueMappings) > MaximumValueMappings || len(value.LabelMappings) > MaximumLabelMappings || !bounded(value.DatabaseVersionRange, 128, false) || !bounded(value.PluginVersionRange, 128, false) || value.CardinalityLimit < 1 || value.CardinalityLimit > 10000 {
		return false
	}
	for index, variant := range value.Variants {
		if !variantPattern.MatchString(variant) || index > 0 && value.Variants[index-1] == variant {
			return false
		}
	}
	metricNames, valueColumns := map[string]struct{}{}, map[string]struct{}{}
	for _, mapping := range value.ValueMappings {
		if !bounded(mapping.SourceColumn, 128, true) || !metricNamePattern.MatchString(mapping.MetricName) || !mapping.MetricType.Valid() || !validUnit(mapping.Unit) {
			return false
		}
		if _, duplicate := metricNames[mapping.MetricName]; duplicate {
			return false
		}
		if _, duplicate := valueColumns[mapping.SourceColumn]; duplicate {
			return false
		}
		metricNames[mapping.MetricName], valueColumns[mapping.SourceColumn] = struct{}{}, struct{}{}
	}
	labels := map[string]struct{}{}
	for _, mapping := range value.LabelMappings {
		if !bounded(mapping.SourceColumn, 128, true) || !validLabel(mapping.Label) {
			return false
		}
		if _, duplicate := labels[mapping.Label]; duplicate {
			return false
		}
		labels[mapping.Label] = struct{}{}
	}
	return true
}

func validLabel(value string) bool {
	if !labelPattern.MatchString(value) || strings.HasPrefix(value, "dbpilot.") || strings.HasPrefix(value, "dbpilot_") {
		return false
	}
	switch value {
	case "tenant_id", "project_id", "host_id", "agent_id", "instance_id", "plugin_id", "assignment_id", "template_id", "template_revision", "revision_id", "query", "statement":
		return false
	default:
		return true
	}
}

func validUnit(value string) bool {
	switch value {
	case "1", "By", "s", "ms", "us", "ns", "%":
		return true
	default:
		return false
	}
}

// structurallyReadOnlySQL is a conservative lexer, not an AST validator. It
// rejects obviously dangerous input before the plugin performs authoritative
// dialect parsing immediately before trial and publication.
func structurallyReadOnlySQL(statement string) bool {
	tokens, ok := sqlTokens(statement)
	if !ok || len(tokens) == 0 || tokens[0] != "select" && tokens[0] != "with" {
		return false
	}
	denied := map[string]struct{}{
		"insert": {}, "update": {}, "delete": {}, "merge": {}, "replace": {}, "upsert": {},
		"create": {}, "alter": {}, "drop": {}, "truncate": {}, "rename": {}, "grant": {}, "revoke": {},
		"commit": {}, "rollback": {}, "savepoint": {}, "begin": {}, "start": {}, "call": {}, "execute": {},
		"copy": {}, "load_file": {}, "into_outfile": {}, "into_dumpfile": {}, "pg_sleep": {}, "sleep": {},
		"benchmark": {}, "dblink": {}, "lo_export": {}, "xp_cmdshell": {}, "get_lock": {}, "release_lock": {},
	}
	for index, token := range tokens {
		if _, blocked := denied[token]; blocked {
			return false
		}
		if token == "into" && index > 0 && tokens[index-1] != "insert" {
			return false
		}
		if token == "for" && index+1 < len(tokens) && (tokens[index+1] == "update" || tokens[index+1] == "share" || tokens[index+1] == "no" || tokens[index+1] == "key") {
			return false
		}
		if token == "lock" || token == "procedure" || token == "function" {
			return false
		}
	}
	if tokens[0] == "with" {
		for _, token := range tokens {
			if token == "select" {
				return true
			}
		}
		return false
	}
	return true
}

func sqlTokens(statement string) ([]string, bool) {
	var tokens []string
	var current strings.Builder
	quote := rune(0)
	parenDepth := 0
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, strings.ToLower(current.String()))
			current.Reset()
		}
	}
	runes := []rune(statement)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if quote != 0 {
			if character == quote {
				if index+1 < len(runes) && runes[index+1] == quote {
					index++
					continue
				}
				quote = 0
			}
			continue
		}
		if character == '-' && index+1 < len(runes) && runes[index+1] == '-' || character == '/' && index+1 < len(runes) && runes[index+1] == '*' || character == '#' {
			return nil, false
		}
		switch character {
		case '\'', '"', '`':
			flush()
			quote = character
		case '(':
			flush()
			parenDepth++
		case ')':
			flush()
			parenDepth--
			if parenDepth < 0 {
				return nil, false
			}
		case ';':
			flush()
			if strings.TrimSpace(string(runes[index+1:])) != "" {
				return nil, false
			}
		case '.', '_':
			current.WriteRune(character)
		default:
			if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '$' {
				current.WriteRune(character)
			} else {
				flush()
			}
		}
	}
	flush()
	return tokens, quote == 0 && parenDepth == 0
}
