package analysis

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
	"raven/internal/packs"
)

const (
	ResourceAPIVersion     = "raven.io/v1"
	minimumRuleDuration    = time.Second
	maximumRuleDuration    = 30 * 24 * time.Hour
	maximumConfigFileBytes = 1 << 20
)

var (
	resourceNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	resourceVersionPattern = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	fieldPathPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,127}$`)
)

// Duration accepts only duration strings such as "30s" or "5m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("duration must be a quoted or plain duration string such as 30s")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }

type ResourceMetadata struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type DeviceResource struct {
	APIVersion string           `yaml:"apiVersion" json:"apiVersion"`
	Kind       string           `yaml:"kind" json:"kind"`
	Metadata   ResourceMetadata `yaml:"metadata" json:"metadata"`
	Spec       DeviceSpec       `yaml:"spec" json:"spec"`
}

type DeviceSpec struct {
	DisplayName    string              `yaml:"displayName" json:"displayName"`
	SourceCategory string              `yaml:"sourceCategory" json:"sourceCategory"`
	Aliases        map[string][]string `yaml:"aliases" json:"aliases"`
	Labels         map[string]string   `yaml:"labels,omitempty" json:"labels,omitempty"`
	Enabled        *bool               `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Reporting      ReportingSpec       `yaml:"reporting,omitempty" json:"reporting,omitempty"`
	Maintenance    *MaintenanceSpec    `yaml:"maintenance,omitempty" json:"maintenance,omitempty"`
}

type ReportingSpec struct {
	Mode             string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	HeartbeatRule    string   `yaml:"heartbeatRule,omitempty" json:"heartbeatRule,omitempty"`
	ExpectedInterval Duration `yaml:"expectedInterval,omitempty" json:"expectedInterval,omitempty"`
	WarningAfter     Duration `yaml:"warningAfter,omitempty" json:"warningAfter,omitempty"`
	CriticalAfter    Duration `yaml:"criticalAfter,omitempty" json:"criticalAfter,omitempty"`
	FreshnessAfter   Duration `yaml:"freshnessAfter,omitempty" json:"freshnessAfter,omitempty"`
}

type MaintenanceSpec struct {
	TimeZone string              `yaml:"timeZone" json:"timeZone"`
	Windows  []MaintenanceWindow `yaml:"windows" json:"windows"`
}

type MaintenanceWindow struct {
	Weekdays []string `yaml:"weekdays" json:"weekdays"`
	Start    string   `yaml:"start" json:"start"`
	End      string   `yaml:"end" json:"end"`
}

type AnalysisRuleResource struct {
	APIVersion string           `yaml:"apiVersion" json:"apiVersion"`
	Kind       string           `yaml:"kind" json:"kind"`
	Metadata   ResourceMetadata `yaml:"metadata" json:"metadata"`
	Spec       AnalysisRuleSpec `yaml:"spec" json:"spec"`
}

type AnalysisRuleSpec struct {
	Kind           string              `yaml:"kind" json:"kind"`
	Enabled        *bool               `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Description    string              `yaml:"description,omitempty" json:"description,omitempty"`
	SourceCategory string              `yaml:"sourceCategory,omitempty" json:"sourceCategory,omitempty"`
	Match          RuleMatch           `yaml:"match" json:"match"`
	Clear          []FieldCondition    `yaml:"clear,omitempty" json:"clear,omitempty"`
	Window         *RuleWindow         `yaml:"window,omitempty" json:"window,omitempty"`
	Finding        FindingSpec         `yaml:"finding" json:"finding"`
	compiled       []compiledCondition `yaml:"-" json:"-"`
}

type RuleMatch struct {
	Fields []FieldCondition `yaml:"fields" json:"fields"`
}

type FieldCondition struct {
	Path          string `yaml:"path" json:"path"`
	Op            string `yaml:"op" json:"op"`
	Value         any    `yaml:"value" json:"value"`
	compiledRegex *regexp.Regexp
}

type compiledCondition struct {
	Match bool
	Clear bool
	Index int
	Regex *regexp.Regexp
}

type RuleWindow struct {
	Signal       string        `yaml:"signal" json:"signal"`
	Duration     Duration      `yaml:"duration" json:"duration"`
	GroupBy      []string      `yaml:"groupBy" json:"groupBy"`
	Baseline     *BaselineSpec `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	CountAtLeast int           `yaml:"countAtLeast,omitempty" json:"countAtLeast,omitempty"`
	ClearBelow   int           `yaml:"clearBelow,omitempty" json:"clearBelow,omitempty"`
	RatioAtLeast float64       `yaml:"ratioAtLeast,omitempty" json:"ratioAtLeast,omitempty"`
	ClearRatio   float64       `yaml:"clearRatio,omitempty" json:"clearRatio,omitempty"`
	Consecutive  int           `yaml:"consecutive,omitempty" json:"consecutive,omitempty"`
}

type BaselineSpec struct {
	MinimumHistory int     `yaml:"minimumHistory" json:"minimumHistory"`
	Sensitivity    float64 `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
}

type FindingSpec struct {
	Severity   string   `yaml:"severity" json:"severity"`
	State      string   `yaml:"state" json:"state"`
	Title      string   `yaml:"title" json:"title"`
	For        Duration `yaml:"for,omitempty" json:"for,omitempty"`
	ClearAfter Duration `yaml:"clearAfter,omitempty" json:"clearAfter,omitempty"`
}

// Snapshot contains a complete, validated immutable configuration generation.
// Its mutable maps and slices remain private; accessors return copies.
type Snapshot struct {
	devices  []DeviceResource
	rules    []AnalysisRuleResource
	byRule   map[string]int
	resolver *Resolver
}

func (s *Snapshot) Enabled() bool { return s != nil && (len(s.devices) != 0 || len(s.rules) != 0) }
func (s *Snapshot) DeviceCount() int {
	if s == nil {
		return 0
	}
	return len(s.devices)
}
func (s *Snapshot) RuleCount() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}
func (s *Snapshot) Resolver() *Resolver {
	if s == nil {
		return nil
	}
	return s.resolver
}

func (s *Snapshot) Device(id string) (DeviceResource, bool) {
	if s == nil {
		return DeviceResource{}, false
	}
	for _, device := range s.devices {
		if device.Metadata.Name == id {
			return cloneDevice(device), true
		}
	}
	return DeviceResource{}, false
}

func (s *Snapshot) Devices() []DeviceResource {
	if s == nil {
		return nil
	}
	result := make([]DeviceResource, len(s.devices))
	for i, device := range s.devices {
		result[i] = cloneDevice(device)
	}
	return result
}

func (s *Snapshot) Rules() []AnalysisRuleResource {
	if s == nil {
		return nil
	}
	result := make([]AnalysisRuleResource, len(s.rules))
	for i, rule := range s.rules {
		result[i] = cloneRule(rule)
	}
	return result
}

func (s *Snapshot) Rule(name string) (AnalysisRuleResource, bool) {
	if s == nil {
		return AnalysisRuleResource{}, false
	}
	index, ok := s.byRule[name]
	if !ok {
		return AnalysisRuleResource{}, false
	}
	return cloneRule(s.rules[index]), true
}

func cloneDevice(source DeviceResource) DeviceResource {
	copy := source
	copy.Spec.Aliases = make(map[string][]string, len(source.Spec.Aliases))
	for namespace, aliases := range source.Spec.Aliases {
		copy.Spec.Aliases[namespace] = append([]string(nil), aliases...)
	}
	copy.Spec.Labels = make(map[string]string, len(source.Spec.Labels))
	for key, value := range source.Spec.Labels {
		copy.Spec.Labels[key] = value
	}
	if source.Spec.Enabled != nil {
		enabled := *source.Spec.Enabled
		copy.Spec.Enabled = &enabled
	}
	if source.Spec.Maintenance != nil {
		maintenance := *source.Spec.Maintenance
		maintenance.Windows = append([]MaintenanceWindow(nil), source.Spec.Maintenance.Windows...)
		for i := range maintenance.Windows {
			maintenance.Windows[i].Weekdays = append([]string(nil), source.Spec.Maintenance.Windows[i].Weekdays...)
		}
		copy.Spec.Maintenance = &maintenance
	}
	return copy
}

func cloneRule(source AnalysisRuleResource) AnalysisRuleResource {
	copy := source
	copy.Spec.Match.Fields = cloneConditions(source.Spec.Match.Fields)
	copy.Spec.Clear = cloneConditions(source.Spec.Clear)
	if source.Spec.Window != nil {
		window := *source.Spec.Window
		window.GroupBy = append([]string(nil), source.Spec.Window.GroupBy...)
		if source.Spec.Window.Baseline != nil {
			baseline := *source.Spec.Window.Baseline
			window.Baseline = &baseline
		}
		copy.Spec.Window = &window
	}
	if source.Spec.Enabled != nil {
		enabled := *source.Spec.Enabled
		copy.Spec.Enabled = &enabled
	}
	copy.Spec.compiled = append([]compiledCondition(nil), source.Spec.compiled...)
	return copy
}

func cloneConditions(source []FieldCondition) []FieldCondition {
	result := append([]FieldCondition(nil), source...)
	for i := range result {
		if values, ok := result[i].Value.([]any); ok {
			result[i].Value = append([]any(nil), values...)
		}
	}
	return result
}

// SnapshotStore atomically replaces a valid configuration while retaining the
// prior generation whenever a reload fails.
type SnapshotStore struct{ current atomic.Pointer[Snapshot] }

func NewSnapshotStore(snapshot *Snapshot) *SnapshotStore {
	store := &SnapshotStore{}
	if snapshot != nil {
		store.current.Store(snapshot)
	}
	return store
}

func (s *SnapshotStore) Current() *Snapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

func (s *SnapshotStore) Reload(directory string) error {
	if s == nil {
		return errors.New("analysis snapshot store is nil")
	}
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		return err
	}
	s.current.Store(snapshot)
	return nil
}

func LoadDirectory(directory string) (*Snapshot, error) {
	if strings.EqualFold(strings.TrimSpace(directory), "none") || strings.TrimSpace(directory) == "" {
		return &Snapshot{byRule: map[string]int{}}, nil
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve analysis directory: %w", err)
	}
	info, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return &Snapshot{byRule: map[string]int{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect analysis directory %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("analysis path %s is not a directory", root)
	}

	snapshot := &Snapshot{byRule: make(map[string]int)}
	deviceFiles, err := yamlFiles(filepath.Join(root, "devices"))
	if err != nil {
		return nil, err
	}
	ruleFiles, err := yamlFiles(filepath.Join(root, "rules"))
	if err != nil {
		return nil, err
	}
	deviceNames := make(map[string]string)
	aliases := make(map[string]string)
	for _, file := range deviceFiles {
		var device DeviceResource
		if err := decodeResource(file, &device); err != nil {
			return nil, err
		}
		if err := validateDevice(&device); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if previous, ok := deviceNames[device.Metadata.Name]; ok {
			return nil, fmt.Errorf("%s: duplicate device ID %q also declared in %s", file, device.Metadata.Name, previous)
		}
		deviceNames[device.Metadata.Name] = file
		for namespace, values := range device.Spec.Aliases {
			for _, value := range values {
				key := namespace + "\x00" + value
				if previous, ok := aliases[key]; ok {
					return nil, fmt.Errorf("%s: duplicate alias %s=%q also declared in %s", file, namespace, value, previous)
				}
				aliases[key] = file
			}
		}
		snapshot.devices = append(snapshot.devices, device)
	}
	for _, file := range ruleFiles {
		var rule AnalysisRuleResource
		if err := decodeResource(file, &rule); err != nil {
			return nil, err
		}
		if err := validateRule(&rule); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if previous, ok := snapshot.byRule[rule.Metadata.Name]; ok {
			return nil, fmt.Errorf("%s: duplicate rule ID %q also declared in %s", file, rule.Metadata.Name, ruleFiles[previous])
		}
		snapshot.byRule[rule.Metadata.Name] = len(snapshot.rules)
		snapshot.rules = append(snapshot.rules, rule)
	}
	if err := validateHeartbeatReferences(snapshot); err != nil {
		return nil, err
	}
	var devices []Device
	for _, device := range snapshot.devices {
		if device.Spec.Enabled != nil && !*device.Spec.Enabled {
			continue
		}
		devices = append(devices, Device{ID: device.Metadata.Name, Aliases: device.Spec.Aliases})
	}
	snapshot.resolver, err = NewResolver(devices)
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func yamlFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config directory %s: %w", directory, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if ext := strings.ToLower(filepath.Ext(name)); ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect config file %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("config file %s must be a regular non-symlink file", path)
		}
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func decodeResource(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config file %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximumConfigFileBytes+1))
	if err != nil {
		return fmt.Errorf("read config file %s: %w", path, err)
	}
	if len(data) > maximumConfigFileBytes {
		return fmt.Errorf("config file %s exceeds %d bytes", path, maximumConfigFileBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode config file %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("config file %s must contain exactly one YAML resource", path)
		}
		return fmt.Errorf("decode trailing YAML in %s: %w", path, err)
	}
	return nil
}

func validateMetadata(metadata ResourceMetadata) error {
	if !resourceNamePattern.MatchString(metadata.Name) {
		return fmt.Errorf("metadata.name %q must be lower kebab-case", metadata.Name)
	}
	if !resourceVersionPattern.MatchString(metadata.Version) {
		return fmt.Errorf("metadata.version %q must be SemVer (for example 1.0.0)", metadata.Version)
	}
	if len(metadata.Description) > 1024 {
		return errors.New("metadata.description exceeds 1024 bytes")
	}
	return nil
}

func validateDevice(device *DeviceResource) error {
	if device.APIVersion != ResourceAPIVersion {
		return fmt.Errorf("apiVersion %q must be %q", device.APIVersion, ResourceAPIVersion)
	}
	if device.Kind != "Device" {
		return fmt.Errorf("kind %q must be Device", device.Kind)
	}
	if err := validateMetadata(device.Metadata); err != nil {
		return err
	}
	if strings.TrimSpace(device.Spec.DisplayName) == "" || len(device.Spec.DisplayName) > 256 {
		return errors.New("spec.displayName is required and must be at most 256 bytes")
	}
	if !packs.KnownSourceCategories[device.Spec.SourceCategory] {
		return fmt.Errorf("unsupported spec.sourceCategory %q", device.Spec.SourceCategory)
	}
	if len(device.Spec.Aliases) == 0 {
		return errors.New("spec.aliases must define at least one supported identity alias")
	}
	for namespace, values := range device.Spec.Aliases {
		if !isAliasNamespace(namespace) {
			return fmt.Errorf("unsupported spec.aliases namespace %q", namespace)
		}
		if len(values) == 0 || len(values) > 32 {
			return fmt.Errorf("spec.aliases.%s must contain 1 to 32 values", namespace)
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
				return fmt.Errorf("spec.aliases.%s values must be trimmed, non-empty, and at most 256 bytes", namespace)
			}
			if _, ok := seen[value]; ok {
				return fmt.Errorf("duplicate spec.aliases.%s value %q", namespace, value)
			}
			seen[value] = struct{}{}
		}
	}
	if len(device.Spec.Labels) > 64 {
		return errors.New("spec.labels may contain at most 64 entries")
	}
	for key, value := range device.Spec.Labels {
		if !resourceNamePattern.MatchString(key) || value == "" || len(value) > 128 {
			return fmt.Errorf("invalid label %q: key must be lower kebab-case and value must be 1 to 128 bytes", key)
		}
	}
	if device.Spec.Maintenance != nil {
		if device.Spec.Maintenance.TimeZone == "" {
			return errors.New("spec.maintenance.timeZone is required")
		}
		if _, err := time.LoadLocation(device.Spec.Maintenance.TimeZone); err != nil {
			return fmt.Errorf("invalid spec.maintenance.timeZone: %w", err)
		}
		if len(device.Spec.Maintenance.Windows) > 64 {
			return errors.New("spec.maintenance.windows may contain at most 64 entries")
		}
		for i, window := range device.Spec.Maintenance.Windows {
			if len(window.Weekdays) == 0 {
				return fmt.Errorf("spec.maintenance.windows[%d].weekdays is required", i)
			}
			for _, day := range window.Weekdays {
				if !validWeekday(day) {
					return fmt.Errorf("spec.maintenance.windows[%d] has invalid weekday %q", i, day)
				}
			}
			if _, err := time.Parse("15:04", window.Start); err != nil {
				return fmt.Errorf("spec.maintenance.windows[%d].start must use HH:MM", i)
			}
			if _, err := time.Parse("15:04", window.End); err != nil {
				return fmt.Errorf("spec.maintenance.windows[%d].end must use HH:MM", i)
			}
		}
	}
	if err := validateReporting(&device.Spec.Reporting); err != nil {
		return err
	}
	return nil
}

func validWeekday(day string) bool {
	switch day {
	case "mon", "tue", "wed", "thu", "fri", "sat", "sun":
		return true
	default:
		return false
	}
}

func validateReporting(reporting *ReportingSpec) error {
	if reporting.Mode == "" {
		reporting.Mode = "event"
	}
	switch reporting.Mode {
	case "event":
		if reporting.HeartbeatRule != "" || reporting.ExpectedInterval != 0 || reporting.WarningAfter != 0 || reporting.CriticalAfter != 0 {
			return errors.New("event reporting cannot configure heartbeatRule or heartbeat intervals")
		}
		if reporting.FreshnessAfter != 0 {
			if err := validateDuration("spec.reporting.freshnessAfter", reporting.FreshnessAfter, false); err != nil {
				return err
			}
		}
	case "heartbeat":
		if reporting.HeartbeatRule == "" {
			return errors.New("heartbeat reporting requires heartbeatRule")
		}
		for field, duration := range map[string]Duration{"expectedInterval": reporting.ExpectedInterval, "warningAfter": reporting.WarningAfter, "criticalAfter": reporting.CriticalAfter} {
			if err := validateDuration("spec.reporting."+field, duration, true); err != nil {
				return err
			}
		}
		if reporting.WarningAfter <= reporting.ExpectedInterval || reporting.CriticalAfter <= reporting.WarningAfter {
			return errors.New("heartbeat timeouts must satisfy criticalAfter > warningAfter > expectedInterval")
		}
	default:
		return fmt.Errorf("unsupported spec.reporting.mode %q", reporting.Mode)
	}
	return nil
}

func validateRule(rule *AnalysisRuleResource) error {
	if rule.APIVersion != ResourceAPIVersion {
		return fmt.Errorf("apiVersion %q must be %q", rule.APIVersion, ResourceAPIVersion)
	}
	if rule.Kind != "AnalysisRule" {
		return fmt.Errorf("kind %q must be AnalysisRule", rule.Kind)
	}
	if err := validateMetadata(rule.Metadata); err != nil {
		return err
	}
	switch rule.Spec.Kind {
	case "event", "heartbeat":
		if rule.Spec.Window != nil {
			return errors.New("event and heartbeat rules cannot define spec.window")
		}
	case "window", "quality", "baseline":
		if rule.Spec.Window == nil {
			return fmt.Errorf("%s rules require spec.window", rule.Spec.Kind)
		}
	default:
		return fmt.Errorf("unsupported spec.kind %q", rule.Spec.Kind)
	}
	if rule.Spec.SourceCategory != "" && !packs.KnownSourceCategories[rule.Spec.SourceCategory] {
		return fmt.Errorf("unsupported spec.sourceCategory %q", rule.Spec.SourceCategory)
	}
	if rule.Spec.Kind != "quality" || len(rule.Spec.Match.Fields) > 0 {
		if err := validateConditions(rule.Spec.Match.Fields, "spec.match.fields", &rule.Spec.compiled, false); err != nil {
			return err
		}
	}
	if len(rule.Spec.Clear) > 0 {
		if err := validateConditions(rule.Spec.Clear, "spec.clear", &rule.Spec.compiled, true); err != nil {
			return err
		}
	}
	if rule.Spec.Kind == "event" && len(rule.Spec.Clear) == 0 {
		return errors.New("event rules require an explicit spec.clear condition")
	}
	if (rule.Spec.Kind == "window" || rule.Spec.Kind == "quality" || rule.Spec.Kind == "baseline") && len(rule.Spec.Clear) != 0 {
		return errors.New("window, quality, and baseline rules use spec.window thresholds instead of spec.clear")
	}
	if rule.Spec.Kind != "heartbeat" && rule.Spec.Finding.ClearAfter == 0 {
		return errors.New("non-heartbeat rules require spec.finding.clearAfter")
	}
	if rule.Spec.Window != nil {
		if err := validateDuration("spec.window.duration", rule.Spec.Window.Duration, true); err != nil {
			return err
		}
		if len(rule.Spec.Window.GroupBy) > 16 {
			return errors.New("spec.window.groupBy may contain at most 16 fields")
		}
		for _, path := range rule.Spec.Window.GroupBy {
			if !validFieldPath(path) {
				return fmt.Errorf("invalid spec.window.groupBy path %q", path)
			}
		}
		window := rule.Spec.Window
		if window.Consecutive == 0 {
			window.Consecutive = 1
		}
		if window.Consecutive < 1 || window.Consecutive > 1000 {
			return errors.New("spec.window.consecutive must be between 1 and 1000")
		}
		switch rule.Spec.Kind {
		case "window":
			if window.Signal != "event_count" {
				return errors.New("window rules require signal event_count")
			}
			if len(rule.Spec.Match.Fields) == 0 {
				return errors.New("window rules require spec.match.fields")
			}
			if window.CountAtLeast < 1 || window.CountAtLeast > 5000 {
				return errors.New("spec.window.countAtLeast must be between 1 and 5000")
			}
			if window.ClearBelow < 0 || window.ClearBelow >= window.CountAtLeast {
				return errors.New("spec.window.clearBelow must be less than countAtLeast")
			}
			if window.RatioAtLeast != 0 || window.ClearRatio != 0 {
				return errors.New("event_count rules cannot configure ratio thresholds")
			}
		case "quality":
			if window.Signal != "quarantine_ratio" {
				return errors.New("quality rules require signal quarantine_ratio")
			}
			if rule.Spec.SourceCategory != "" {
				return errors.New("quality rules cannot filter sourceCategory because quarantined records have no normalized category")
			}
			if len(window.GroupBy) != 0 {
				return errors.New("quality rules group by resolved source identity and do not accept groupBy")
			}
			if window.RatioAtLeast <= 0 || window.RatioAtLeast > 1 || window.ClearRatio < 0 || window.ClearRatio >= window.RatioAtLeast {
				return errors.New("quality thresholds require 0 <= clearRatio < ratioAtLeast <= 1")
			}
			if window.CountAtLeast != 0 || window.ClearBelow != 0 {
				return errors.New("quality rules cannot configure count thresholds")
			}
		case "baseline":
			if window.Signal != "event_count" || len(rule.Spec.Match.Fields) == 0 {
				return errors.New("baseline rules require event_count and spec.match.fields")
			}
			if window.Baseline == nil {
				return errors.New("baseline rules require spec.window.baseline")
			}
			if window.Baseline.MinimumHistory < 4 || window.Baseline.MinimumHistory > 28 {
				return errors.New("spec.window.baseline.minimumHistory must be between 4 and 28 completed intervals")
			}
			if window.Baseline.Sensitivity == 0 {
				window.Baseline.Sensitivity = 3
			}
			if math.IsNaN(window.Baseline.Sensitivity) || math.IsInf(window.Baseline.Sensitivity, 0) || window.Baseline.Sensitivity < 2 || window.Baseline.Sensitivity > 6 {
				return errors.New("spec.window.baseline.sensitivity must be between 2 and 6")
			}
			if window.Duration.Value() < time.Minute || window.Duration.Value() > 24*time.Hour || window.Duration.Value()%time.Second != 0 {
				return errors.New("baseline duration must be a whole-second interval between 1m and 24h")
			}
			if window.CountAtLeast != 0 || window.ClearBelow != 0 || window.RatioAtLeast != 0 || window.ClearRatio != 0 {
				return errors.New("baseline rules cannot configure fixed count or ratio thresholds")
			}
		}
		if rule.Spec.Kind != "baseline" && window.Baseline != nil {
			return errors.New("spec.window.baseline is only supported by baseline rules")
		}
	}
	if rule.Spec.Finding.Severity != "low" && rule.Spec.Finding.Severity != "medium" && rule.Spec.Finding.Severity != "high" && rule.Spec.Finding.Severity != "critical" {
		return fmt.Errorf("unsupported spec.finding.severity %q", rule.Spec.Finding.Severity)
	}
	if rule.Spec.Finding.State != "yellow" && rule.Spec.Finding.State != "red" {
		return fmt.Errorf("spec.finding.state must be yellow or red, got %q", rule.Spec.Finding.State)
	}
	if strings.TrimSpace(rule.Spec.Finding.Title) == "" || len(rule.Spec.Finding.Title) > 256 {
		return errors.New("spec.finding.title is required and must be at most 256 bytes")
	}
	if rule.Spec.Finding.For != 0 {
		if err := validateDuration("spec.finding.for", rule.Spec.Finding.For, false); err != nil {
			return err
		}
	}
	if rule.Spec.Finding.ClearAfter != 0 {
		if err := validateDuration("spec.finding.clearAfter", rule.Spec.Finding.ClearAfter, true); err != nil {
			return err
		}
	}
	return nil
}

func validateConditions(conditions []FieldCondition, path string, compiled *[]compiledCondition, clear bool) error {
	if len(conditions) == 0 || len(conditions) > 64 {
		return fmt.Errorf("%s must contain 1 to 64 conditions", path)
	}
	for i := range conditions {
		condition := &conditions[i]
		if !validFieldPath(condition.Path) {
			return fmt.Errorf("%s[%d].path %q is invalid", path, i, condition.Path)
		}
		if strings.HasPrefix(condition.Path, "raw.") || condition.Path == "raw" || condition.Path == "payload" || condition.Path == "raw_payload" {
			return fmt.Errorf("%s[%d].path cannot reference raw payload fields", path, i)
		}
		if err := validateConditionValue(condition.Op, condition.Value); err != nil {
			return fmt.Errorf("%s[%d]: %w", path, i, err)
		}
		if condition.Op == "regex" {
			pattern, _ := condition.Value.(string)
			compiledRegex, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("%s[%d].value has invalid Go RE2 regex: %w", path, i, err)
			}
			condition.compiledRegex = compiledRegex
		}
		*compiled = append(*compiled, compiledCondition{Match: !clear, Clear: clear, Index: i, Regex: condition.compiledRegex})
	}
	return nil
}

func validFieldPath(value string) bool { return fieldPathPattern.MatchString(value) }

func validateConditionValue(op string, value any) error {
	switch op {
	case "eq":
		if !isScalar(value) {
			return errors.New("eq value must be a string, boolean, or number")
		}
	case "in":
		values, ok := value.([]any)
		if !ok || len(values) == 0 || len(values) > 64 {
			return errors.New("in value must be a list of 1 to 64 scalars")
		}
		for _, item := range values {
			if !isScalar(item) {
				return errors.New("in values must be scalars")
			}
		}
	case "gt", "gte", "lt", "lte":
		if !isNumber(value) {
			return fmt.Errorf("%s value must be numeric", op)
		}
	case "contains", "regex":
		text, ok := value.(string)
		if !ok || text == "" || len(text) > 256 {
			return fmt.Errorf("%s value must be a non-empty string up to 256 bytes", op)
		}
	default:
		return fmt.Errorf("unsupported operator %q", op)
	}
	return nil
}

func isScalar(value any) bool {
	return isNumber(value) || func() bool { _, ok := value.(string); return ok }() || func() bool { _, ok := value.(bool); return ok }()
}
func isNumber(value any) bool {
	switch value.(type) {
	case int, int64, uint64, float32, float64:
		return true
	default:
		return false
	}
}

func validateDuration(field string, duration Duration, required bool) error {
	value := duration.Value()
	if value == 0 && !required {
		return nil
	}
	if value < minimumRuleDuration || value > maximumRuleDuration {
		return fmt.Errorf("%s must be between %s and %s", field, minimumRuleDuration, maximumRuleDuration)
	}
	return nil
}

func validateHeartbeatReferences(snapshot *Snapshot) error {
	for _, device := range snapshot.devices {
		reporting := device.Spec.Reporting
		if reporting.Mode != "heartbeat" {
			continue
		}
		index, ok := snapshot.byRule[reporting.HeartbeatRule]
		if !ok {
			return fmt.Errorf("device %q references unknown heartbeatRule %q", device.Metadata.Name, reporting.HeartbeatRule)
		}
		rule := snapshot.rules[index]
		if rule.Spec.Kind != "heartbeat" {
			return fmt.Errorf("device %q heartbeatRule %q is a %s rule, expected heartbeat", device.Metadata.Name, reporting.HeartbeatRule, rule.Spec.Kind)
		}
		if rule.Spec.Enabled != nil && !*rule.Spec.Enabled {
			return fmt.Errorf("device %q references disabled heartbeatRule %q", device.Metadata.Name, reporting.HeartbeatRule)
		}
		if rule.Spec.SourceCategory != "" && rule.Spec.SourceCategory != device.Spec.SourceCategory {
			return fmt.Errorf("device %q sourceCategory %q does not match heartbeat rule %q category %q", device.Metadata.Name, device.Spec.SourceCategory, reporting.HeartbeatRule, rule.Spec.SourceCategory)
		}
	}
	return nil
}
