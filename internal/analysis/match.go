package analysis

import (
	"reflect"
	"strings"
)

// matchesRuleFields evaluates a validated rule against normalized OCSF fields.
// It is used for the configured heartbeat signal; findings remain an A-04 concern.
func matchesRuleFields(rule AnalysisRuleResource, fields map[string]any) bool {
	for _, condition := range rule.Spec.Match.Fields {
		value, ok := lookupField(fields, condition.Path)
		if !ok || !matchesCondition(condition, value) {
			return false
		}
	}
	return true
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
