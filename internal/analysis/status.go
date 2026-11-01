package analysis

import (
	"strings"
	"time"

	"raven/internal/rawstore"
)

type DeviceState string

const (
	DeviceStateGreen    DeviceState = "green"
	DeviceStateYellow   DeviceState = "yellow"
	DeviceStateRed      DeviceState = "red"
	DeviceStateUnknown  DeviceState = "unknown"
	DeviceStateDisabled DeviceState = "disabled"
)

type DeviceTelemetry struct {
	DeviceID             string            `json:"device_id"`
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	DisplayName          string            `json:"display_name"`
	SourceCategory       string            `json:"source_category"`
	Labels               map[string]string `json:"labels,omitempty"`
	Enabled              bool              `json:"enabled"`
	ReportingMode        string            `json:"reporting_mode"`
	State                DeviceState       `json:"state"`
	Reason               string            `json:"reason"`
	LastReceivedAt       *time.Time        `json:"last_received_at,omitempty"`
	LastReceivedAge      *float64          `json:"last_received_age_seconds,omitempty"`
	LastNormalizedAt     *time.Time        `json:"last_normalized_at,omitempty"`
	LastNormalizedAge    *float64          `json:"last_normalized_age_seconds,omitempty"`
	LastQuarantinedAt    *time.Time        `json:"last_quarantined_at,omitempty"`
	LastQuarantinedAge   *float64          `json:"last_quarantined_age_seconds,omitempty"`
	LastHeartbeatAt      *time.Time        `json:"last_heartbeat_at,omitempty"`
	LastHeartbeatAge     *float64          `json:"last_heartbeat_age_seconds,omitempty"`
	ReceivedCount        int64             `json:"received_count"`
	NormalizedCount      int64             `json:"normalized_count"`
	QuarantinedCount     int64             `json:"quarantined_count"`
	ActiveFindingCount   int64             `json:"active_finding_count"`
	NormalizationRatio   float64           `json:"normalization_ratio"`
	HeartbeatCount       int64             `json:"heartbeat_count"`
	ReceivedPerMinute    float64           `json:"received_per_minute"`
	NormalizedPerMinute  float64           `json:"normalized_per_minute"`
	QuarantinedPerMinute float64           `json:"quarantined_per_minute"`
	IdentityConfidence   string            `json:"identity_confidence"`
	MatchMethod          string            `json:"match_method"`
	LastObservationAt    *time.Time        `json:"last_observation_at,omitempty"`
	UpdatedAt            *time.Time        `json:"updated_at,omitempty"`
	EvaluatedAt          time.Time         `json:"evaluated_at"`
	Maintenance          bool              `json:"maintenance"`
	MaintenanceUntil     *time.Time        `json:"maintenance_until,omitempty"`
}

func BuildDeviceTelemetry(device DeviceResource, stored rawstore.AnalysisDeviceTelemetry, now time.Time) DeviceTelemetry {
	now = now.UTC()
	enabled := device.Spec.Enabled == nil || *device.Spec.Enabled
	result := DeviceTelemetry{
		DeviceID: device.Metadata.Name, Name: device.Metadata.Name, Version: device.Metadata.Version,
		DisplayName: device.Spec.DisplayName, SourceCategory: device.Spec.SourceCategory,
		Labels:  device.Spec.Labels,
		Enabled: enabled, ReportingMode: device.Spec.Reporting.Mode,
		ReceivedCount: stored.ReceivedCount, NormalizedCount: stored.NormalizedCount,
		QuarantinedCount: stored.QuarantinedCount, HeartbeatCount: stored.HeartbeatCount,
		ReceivedPerMinute: stored.ReceivedPerMinute, NormalizedPerMinute: stored.NormalizedPerMinute,
		QuarantinedPerMinute: stored.QuarantinedPerMinute,
		IdentityConfidence:   stored.IdentityConfidence, MatchMethod: stored.MatchMethod,
		EvaluatedAt: now,
	}
	if result.IdentityConfidence == "" {
		result.IdentityConfidence = "none"
	}
	result.LastReceivedAt = timePtr(stored.LastReceivedAt)
	result.LastReceivedAge = agePtr(stored.LastReceivedAt, now)
	result.LastNormalizedAt = timePtr(stored.LastNormalizedAt)
	result.LastNormalizedAge = agePtr(stored.LastNormalizedAt, now)
	result.LastQuarantinedAt = timePtr(stored.LastQuarantinedAt)
	result.LastQuarantinedAge = agePtr(stored.LastQuarantinedAt, now)
	result.LastHeartbeatAt = timePtr(stored.LastHeartbeatAt)
	result.LastHeartbeatAge = agePtr(stored.LastHeartbeatAt, now)
	result.LastObservationAt = timePtr(stored.LastObservationAt)
	result.UpdatedAt = timePtr(stored.UpdatedAt)
	if result.NormalizedCount+result.QuarantinedCount > 0 {
		result.NormalizationRatio = float64(result.NormalizedCount) / float64(result.NormalizedCount+result.QuarantinedCount)
	}

	if !enabled {
		result.State, result.Reason = DeviceStateDisabled, "Device is disabled in inventory."
		return result
	}
	if device.Spec.Reporting.Mode == "heartbeat" {
		if until := maintenanceUntil(device.Spec.Maintenance, now); until != nil {
			result.State, result.Reason, result.Maintenance = DeviceStateDisabled, "Configured maintenance window is active.", true
			result.MaintenanceUntil = until
			return result
		}
		result.State, result.Reason = heartbeatState(device.Spec.Reporting, stored.LastHeartbeatAt, now)
		return result
	}
	if !stored.LastQuarantinedAt.IsZero() && (stored.LastNormalizedAt.IsZero() || !stored.LastQuarantinedAt.Before(stored.LastNormalizedAt)) {
		result.State, result.Reason = DeviceStateYellow, "The latest completed observation was quarantined."
		return result
	}
	if stored.LastNormalizedAt.IsZero() {
		result.State, result.Reason = DeviceStateUnknown, "No successfully normalized event has been observed."
		return result
	}
	if stored.LastNormalizedAt.After(now) {
		result.State, result.Reason = DeviceStateUnknown, "The latest normalized observation timestamp is in the future."
		return result
	}
	freshness := device.Spec.Reporting.FreshnessAfter.Value()
	if freshness <= 0 {
		result.State, result.Reason = DeviceStateUnknown, "No freshness boundary is configured; recent activity alone cannot establish health."
		return result
	}
	if now.Sub(stored.LastNormalizedAt) > freshness {
		result.State, result.Reason = DeviceStateUnknown, "The last normalized event is outside the configured freshness boundary."
		return result
	}
	result.State, result.Reason = DeviceStateGreen, "A normalized event is within the configured freshness boundary."
	return result
}

func heartbeatState(reporting ReportingSpec, lastHeartbeat, now time.Time) (DeviceState, string) {
	if lastHeartbeat.IsZero() {
		return DeviceStateUnknown, "No event has matched the configured heartbeat rule yet."
	}
	if lastHeartbeat.After(now) {
		return DeviceStateUnknown, "The latest heartbeat timestamp is in the future."
	}
	age := now.Sub(lastHeartbeat)
	switch {
	case age > reporting.CriticalAfter.Value():
		return DeviceStateRed, "The configured heartbeat exceeded its critical deadline."
	case age > reporting.WarningAfter.Value():
		return DeviceStateYellow, "The configured heartbeat exceeded its warning deadline."
	default:
		return DeviceStateGreen, "A matching heartbeat is within the configured warning deadline."
	}
}

func maintenanceUntil(maintenance *MaintenanceSpec, now time.Time) *time.Time {
	if maintenance == nil || len(maintenance.Windows) == 0 {
		return nil
	}
	location, err := time.LoadLocation(maintenance.TimeZone)
	if err != nil {
		return nil
	}
	local := now.In(location)
	for _, window := range maintenance.Windows {
		start, startErr := time.Parse("15:04", window.Start)
		end, endErr := time.Parse("15:04", window.End)
		if startErr != nil || endErr != nil {
			continue
		}
		startMinute, endMinute := start.Hour()*60+start.Minute(), end.Hour()*60+end.Minute()
		todayStart := time.Date(local.Year(), local.Month(), local.Day(), start.Hour(), start.Minute(), 0, 0, location)
		todayEnd := time.Date(local.Year(), local.Month(), local.Day(), end.Hour(), end.Minute(), 0, 0, location)
		for _, day := range window.Weekdays {
			if startMinute < endMinute && weekday(local.Weekday()) == day && !local.Before(todayStart) && local.Before(todayEnd) {
				return timePtr(todayEnd)
			}
			if startMinute > endMinute {
				if weekday(local.Weekday()) == day && !local.Before(todayStart) {
					return timePtr(todayEnd.AddDate(0, 0, 1))
				}
				if weekday(local.AddDate(0, 0, -1).Weekday()) == day && local.Before(todayEnd) {
					return timePtr(todayEnd)
				}
			}
		}
	}
	return nil
}

func weekday(day time.Weekday) string {
	return strings.ToLower(day.String()[:3])
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func agePtr(value, now time.Time) *float64 {
	if value.IsZero() {
		return nil
	}
	age := now.Sub(value).Seconds()
	if age < 0 {
		age = 0
	}
	return &age
}
