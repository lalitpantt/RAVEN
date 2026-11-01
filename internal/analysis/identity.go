package analysis

import (
	"errors"
	"fmt"
	"sort"

	"raven/internal/model"
	"raven/internal/rawstore"
)

// Device is the identity subset consumed by the A-02 worker and built from
// validated inventory resources.
type Device struct {
	ID      string
	Aliases map[string][]string
}

type Resolver struct {
	aliases map[string]map[string]map[string]struct{}
}

func NewResolver(devices []Device) (*Resolver, error) {
	r := &Resolver{aliases: make(map[string]map[string]map[string]struct{})}
	deviceIDs := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if device.ID == "" {
			return nil, errors.New("analysis device ID is required")
		}
		if _, exists := deviceIDs[device.ID]; exists {
			return nil, fmt.Errorf("duplicate analysis device ID %q", device.ID)
		}
		deviceIDs[device.ID] = struct{}{}
		for namespace, values := range device.Aliases {
			if !isAliasNamespace(namespace) {
				return nil, fmt.Errorf("unsupported analysis alias namespace %q", namespace)
			}
			for _, value := range values {
				if value == "" {
					return nil, fmt.Errorf("empty %s alias for device %q", namespace, device.ID)
				}
				if r.aliases[namespace] == nil {
					r.aliases[namespace] = make(map[string]map[string]struct{})
				}
				if r.aliases[namespace][value] == nil {
					r.aliases[namespace][value] = make(map[string]struct{})
				}
				r.aliases[namespace][value][device.ID] = struct{}{}
			}
		}
	}
	return r, nil
}

func isAliasNamespace(value string) bool {
	switch value {
	case "syslog_host", "host", "server", "source_ip":
		return true
	default:
		return false
	}
}

func (r *Resolver) Resolve(hints model.AnalysisIdentityHints) rawstore.AnalysisResolution {
	if r == nil {
		r = &Resolver{}
	}
	deviceMatches := make(map[string]map[string]struct{})
	for _, namespace := range []string{"syslog_host", "host", "server", "source_ip"} {
		value := hints[namespace]
		for deviceID := range r.aliases[namespace][value] {
			if deviceMatches[deviceID] == nil {
				deviceMatches[deviceID] = make(map[string]struct{})
			}
			deviceMatches[deviceID][namespace] = struct{}{}
		}
	}
	result := rawstore.AnalysisResolution{SourceKey: rawstore.AnalysisSourceKey(hints), Resolution: "unknown", MatchMethod: "none", Confidence: "none"}
	if len(deviceMatches) == 0 {
		return result
	}
	deviceIDs := make([]string, 0, len(deviceMatches))
	namespaces := make(map[string]struct{})
	for deviceID, matchedNamespaces := range deviceMatches {
		deviceIDs = append(deviceIDs, deviceID)
		for namespace := range matchedNamespaces {
			namespaces[namespace] = struct{}{}
		}
	}
	sort.Strings(deviceIDs)
	methods := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		methods = append(methods, namespace)
	}
	sort.Strings(methods)
	result.MatchMethod = joinMethods(methods)
	if len(deviceIDs) != 1 {
		result.Resolution = "ambiguous"
		return result
	}
	result.Resolution = "matched"
	result.DeviceID = deviceIDs[0]
	result.Confidence = "strong"
	if len(methods) == 1 && methods[0] == "source_ip" {
		result.Confidence = "weak"
	}
	return result
}

func joinMethods(methods []string) string {
	result := ""
	for i, method := range methods {
		if i > 0 {
			result += "+"
		}
		result += method
	}
	return result
}
