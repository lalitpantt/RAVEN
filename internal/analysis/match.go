package analysis

import (
	"reflect"
	"strings"

	"raven/internal/model"
)

type EventRuleEvaluation struct {
	Matched       bool     `json:"matched"`
	ClearMatched  bool     `json:"clear_matched"`
	MatchedFields []string `json:"matched_fields"`
	ClearFields   []string `json:"clear_fields"`
}

// EvaluateEventRule evaluates one validated event rule against normalized fields.
func EvaluateEventRule(rule AnalysisRuleResource, event *model.NormalizedEvent) EventRuleEvaluation {
	if event == nil || rule.Spec.Kind != "event" || (rule.Spec.Enabled != nil && !*rule.Spec.Enabled) {
		return EventRuleEvaluation{}
	}
	if rule.Spec.SourceCategory != "" && rule.Spec.SourceCategory != event.Raven.SourceCategory {
		return EventRuleEvaluation{}
	}
	matched, matchedFields := evaluateConditions(rule.Spec.Match.Fields, event.OCSF)
	cleared, clearFields := evaluateConditions(rule.Spec.Clear, event.OCSF)
	return EventRuleEvaluation{Matched: matched, ClearMatched: cleared, MatchedFields: matchedFields, ClearFields: clearFields}
}

// matchesRuleFields evaluates a heartbeat rule against normalized OCSF fields.
func matchesRuleFields(rule AnalysisRuleResource, fields map[string]any) bool {
	matched, _ := evaluateConditions(rule.Spec.Match.Fields, fields)
	return matched
}

func evaluateConditions(conditions []FieldCondition, fields map[string]any) (bool, []string) {
	if len(conditions) == 0 {
		return false, nil
	}
	matchedFields := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		actual, ok := lookupField(fields, condition.Path)
		if !ok || !matchesCondition(condition, actual) {
			return false, nil
		}
		matchedFields = append(matchedFields, condition.Path)
	}
	return true, matchedFields
}

func lookupField(fields map[string]any, path string) (any, bool) {
	var current any = fields
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func matchesCondition(condition FieldCondition, actual any) bool {
	switch condition.Op {
	case "eq":
		return scalarEqual(actual, condition.Value)
	case "in":
		values, _ := condition.Value.([]any)
		for _, value := range values {
			if scalarEqual(actual, value) {
				return true
			}
		}
	case "contains":
		expected, _ := condition.Value.(string)
		value, ok := actual.(string)
		return ok && strings.Contains(value, expected)
	case "regex":
		value, ok := actual.(string)
		return ok && condition.compiledRegex != nil && condition.compiledRegex.MatchString(value)
	case "gt", "gte", "lt", "lte":
		left, lok := numeric(actual)
		right, rok := numeric(condition.Value)
		if !lok || !rok {
			return false
		}
		switch condition.Op {
		case "gt":
			return left > right
		case "gte":
			return left >= right
		case "lt":
			return left < right
		default:
			return left <= right
		}
	}
	return false
}

func scalarEqual(left, right any) bool {
	if leftNumber, lok := numeric(left); lok {
		if rightNumber, rok := numeric(right); rok {
			return leftNumber == rightNumber
		}
	}
	return reflect.DeepEqual(left, right)
}

func numeric(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

func heartbeatRuleFor(snapshot *Snapshot, deviceID string) (AnalysisRuleResource, bool) {
	device, ok := snapshot.Device(deviceID)
	if !ok || device.Spec.Reporting.Mode != "heartbeat" {
		return AnalysisRuleResource{}, false
	}
	rule, ok := snapshot.Rule(device.Spec.Reporting.HeartbeatRule)
	if rule.Spec.Enabled != nil && !*rule.Spec.Enabled {
		return AnalysisRuleResource{}, false
	}
	return rule, ok
}
