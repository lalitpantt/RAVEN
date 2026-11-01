export type DeviceState = 'green' | 'yellow' | 'red' | 'unknown' | 'disabled';
export type FindingStatus = 'open' | 'clearing' | 'resolved';

export interface AnalysisStatus {
  state: 'disabled' | 'running' | 'delayed' | 'degraded' | 'invalid_configuration';
  reason: string;
  enabled: boolean;
  worker_running: boolean;
  device_count: number;
  rule_count: number;
  pending_count: number;
  oldest_pending_at?: string | null;
  oldest_pending_age_seconds: number;
  checkpoint_id: number;
  last_error?: string;
  configuration_error?: string;
  evaluated_at: string;
}

export interface AnalysisDevice {
  device_id: string;
  name: string;
  version: string;
  display_name: string;
  source_category: string;
  labels?: Record<string, string>;
  enabled: boolean;
  reporting_mode: string;
  state: DeviceState;
  reason: string;
  last_received_at?: string;
  last_normalized_at?: string;
  last_quarantined_at?: string;
  last_heartbeat_at?: string;
  received_count: number;
  normalized_count: number;
  quarantined_count: number;
  active_finding_count: number;
  normalization_ratio: number;
  heartbeat_count: number;
  received_per_minute: number;
  normalized_per_minute: number;
  quarantined_per_minute: number;
  identity_confidence: string;
  match_method: string;
  last_observation_at?: string;
  updated_at?: string;
  evaluated_at: string;
  maintenance: boolean;
  maintenance_until?: string;
}

export interface AnalysisSource {
  source_key: string;
  identity_hints: Record<string, string>;
  resolution: 'unknown' | 'ambiguous' | 'matched';
  device_id?: string;
  match_method: string;
  confidence: string;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  last_observation_id: number;
}

export interface AnalysisFinding {
  id: string;
  owner_type: 'device' | 'source';
  owner_id: string;
  device_id?: string;
  source_key: string;
  rule_id: string;
  instance_key?: string;
  rule_version: string;
  status: FindingStatus;
  severity: 'low' | 'medium' | 'high' | 'critical';
  state: 'yellow' | 'red';
  title: string;
  first_seen_at: string;
  last_seen_at: string;
  last_event_id: string;
  last_raw_id: string;
  record_ordinal: number;
  occurrence_count: number;
  clear_since?: string;
  clear_deadline?: string;
  resolved_at?: string;
  updated_at: string;
}

export interface AnalysisEvidenceLinks {
  event?: string;
  trace?: string;
  verify?: string;
  raw?: string;
}

export interface AnalysisFindingHistory {
  history: {
    id: number;
    finding_id: string;
    observation_id: number;
    action: string;
    occurred_at: string;
    event_id: string;
    raw_id: string;
    record_ordinal: number;
    rule_version: string;
    severity: string;
    state: string;
    title: string;
  };
  evidence: AnalysisEvidenceLinks;
}

export interface AnalysisFindingDetail {
  finding: AnalysisFinding;
  evidence: AnalysisEvidenceLinks;
  history: AnalysisFindingHistory[];
  history_total: number;
  limit: number;
  offset: number;
}

export interface AnalysisPage<T> {
  total: number;
  limit: number;
  offset: number;
  [key: string]: T[] | number;
}
