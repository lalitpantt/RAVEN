import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Activity, AlertTriangle, Clock3, ExternalLink, RefreshCw, Search, ShieldCheck } from 'lucide-react';
import { AnalysisDevice, AnalysisFinding, AnalysisFindingDetail, AnalysisSource, AnalysisStatus, DeviceState } from '../types/analysis';
import { apiService } from '../services/api';
import { Badge } from '../components/Badge';
import { MetricCard } from '../components/MetricCard';

interface AnalysisProps {
  onNavigate: (tab: string, param?: string) => void;
}

const pageSize = 25;
const pollInterval = 10_000;
const staleAfter = 30_000;
const categories = ['network_device', 'server', 'os', 'endpoint', 'application', 'database', 'cloud', 'container', 'iam', 'iot', 'other'];

const stateVariant: Record<DeviceState, 'green' | 'amber' | 'red' | 'gray'> = {
  green: 'green', yellow: 'amber', red: 'red', unknown: 'gray', disabled: 'gray',
};

function dateLabel(value?: string | null): string {
  return value ? new Date(value).toLocaleString() : 'Never observed';
}

function timeAgo(value?: string | null): string {
  if (!value) return 'Never';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function SelectField({ id, label, value, onChange, options }: {
  id: string; label: string; value: string; onChange: (value: string) => void; options: Array<[string, string]>;
}) {
  return (
    <label htmlFor={id} className="flex flex-col gap-1 text-[11px] font-mono text-[#8b949e]">
      {label}
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className="min-w-28 rounded-md border border-[#30363d] bg-[#0d1117] px-2.5 py-2 text-xs text-[#c9d1d9] focus:border-[#58a6ff] focus:outline-none">
        {options.map(([optionValue, name]) => <option key={optionValue} value={optionValue}>{name}</option>)}
      </select>
    </label>
  );
}

function TextField({ id, label, value, onChange, placeholder }: {
  id: string; label: string; value: string; onChange: (value: string) => void; placeholder: string;
}) {
  return (
    <label htmlFor={id} className="flex min-w-40 flex-col gap-1 text-[11px] font-mono text-[#8b949e]">
      {label}
      <input id={id} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="rounded-md border border-[#30363d] bg-[#0d1117] px-2.5 py-2 text-xs text-[#c9d1d9] placeholder:text-[#6e7681] focus:border-[#58a6ff] focus:outline-none" />
    </label>
  );
}

function Pager({ total, offset, onChange }: { total: number; offset: number; onChange: (offset: number) => void }) {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-[#21262d] px-4 py-3 text-xs font-mono text-[#8b949e]">
      <span>{total === 0 ? 'No rows' : `${offset + 1}–${Math.min(total, offset + pageSize)} of ${total.toLocaleString()}`}</span>
      <div className="flex gap-2">
        <button type="button" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))} className="rounded border border-[#30363d] px-3 py-1.5 text-[#c9d1d9] hover:bg-[#21262d] disabled:opacity-40">Previous</button>
        <button type="button" disabled={offset + pageSize >= total} onClick={() => onChange(offset + pageSize)} className="rounded border border-[#30363d] px-3 py-1.5 text-[#c9d1d9] hover:bg-[#21262d] disabled:opacity-40">Next</button>
      </div>
    </div>
  );
}

export const Analysis: React.FC<AnalysisProps> = ({ onNavigate }) => {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [devices, setDevices] = useState<AnalysisDevice[]>([]);
  const [deviceTotal, setDeviceTotal] = useState(0);
  const [sources, setSources] = useState<AnalysisSource[]>([]);
  const [sourceTotal, setSourceTotal] = useState(0);
  const [findings, setFindings] = useState<AnalysisFinding[]>([]);
  const [findingTotal, setFindingTotal] = useState(0);
  const [deviceState, setDeviceState] = useState('');
  const [category, setCategory] = useState('');
  const [site, setSite] = useState('');
  const [deviceSearch, setDeviceSearch] = useState('');
  const [deviceWindow, setDeviceWindow] = useState('');
  const [deviceOffset, setDeviceOffset] = useState(0);
  const [findingStatus, setFindingStatus] = useState('open');
  const [ruleID, setRuleID] = useState('');
  const [findingDevice, setFindingDevice] = useState('');
  const [findingWindow, setFindingWindow] = useState('');
  const [findingOffset, setFindingOffset] = useState(0);
  const [sourceOffset, setSourceOffset] = useState(0);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [findingDetail, setFindingDetail] = useState<AnalysisFindingDetail | null>(null);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshError, setRefreshError] = useState('');
  const [lastSuccess, setLastSuccess] = useState<number | null>(null);
  const [clock, setClock] = useState(Date.now());
  const requestID = useRef(0);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    const currentRequest = ++requestID.current;
    setLoading(true);
    try {
      const [statusResponse, deviceResponse, sourceResponse, findingResponse] = await Promise.all([
        apiService.getAnalysisStatus(),
        apiService.listAnalysisDevices({ state: deviceState, category, site, device: deviceSearch, window: deviceWindow, limit: pageSize, offset: deviceOffset }),
        apiService.listAnalysisSources({ resolution: 'unassigned', limit: pageSize, offset: sourceOffset }),
        apiService.listAnalysisFindings({ status: findingStatus, rule_id: ruleID, device: findingDevice, window: findingWindow, limit: pageSize, offset: findingOffset }),
      ]);
      if (currentRequest === requestID.current) {
        setStatus(statusResponse);
        setDevices(deviceResponse.devices);
        setDeviceTotal(deviceResponse.total);
        setSources(sourceResponse.sources);
        setSourceTotal(sourceResponse.total);
        setFindings(findingResponse.findings);
        setFindingTotal(findingResponse.total);
        setLastSuccess(Date.now());
        setRefreshError('');
      }
    } catch (error) {
      if (currentRequest === requestID.current) setRefreshError(error instanceof Error ? error.message : 'Analysis data could not be refreshed.');
    } finally {
      inFlight.current = false;
      if (currentRequest === requestID.current) setLoading(false);
    }
  }, [category, deviceOffset, deviceSearch, deviceState, deviceWindow, findingDevice, findingOffset, findingStatus, findingWindow, ruleID, site, sourceOffset]);

  useEffect(() => {
    void refresh();
    const poll = window.setInterval(() => void refresh(), pollInterval);
    const clockTick = window.setInterval(() => setClock(Date.now()), 5_000);
    return () => { window.clearInterval(poll); window.clearInterval(clockTick); };
  }, [refresh]);

  useEffect(() => {
    if (!selectedFinding) { setFindingDetail(null); return; }
    let current = true;
    apiService.getAnalysisFinding(selectedFinding, 50, historyOffset).then((detail) => {
      if (current) { setFindingDetail(detail); setVerifyResult(null); }
    }).catch((error) => {
      if (current) setRefreshError(error instanceof Error ? error.message : 'Finding details could not be loaded.');
    });
    return () => { current = false; };
  }, [historyOffset, selectedFinding]);

  const isStale = Boolean(refreshError) || lastSuccess === null || clock - lastSuccess > staleAfter;
  const stateCounts = devices.reduce<Record<DeviceState, number>>((counts, device) => {
    counts[device.state] += 1;
    return counts;
  }, { green: 0, yellow: 0, red: 0, unknown: 0, disabled: 0 });
  const statusVariant = status?.state === 'running' ? 'green' : status?.state === 'delayed' ? 'amber' : status?.state === 'disabled' ? 'gray' : 'red';

  const setDeviceFilter = (setter: (value: string) => void, value: string) => {
    setter(value);
    setDeviceOffset(0);
  };
  const setFindingFilter = (setter: (value: string) => void, value: string) => {
    setter(value);
    setFindingOffset(0);
  };

  const verifyEvidence = async () => {
    const eventID = findingDetail?.finding.last_event_id;
    if (!eventID) return;
    setVerifyResult('Checking…');
    try {
      const result = await apiService.verifyEvent(eventID);
      setVerifyResult(result.passed ? 'Evidence verification passed.' : `Evidence verification failed: ${result.failure_reason || result.status}`);
    } catch (error) {
      setVerifyResult(error instanceof Error ? error.message : 'Verification request failed.');
    }
  };

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-3 border-b border-[#21262d] pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-mono font-bold text-[#f0f6fc]"><Activity className="h-5 w-5 text-[#58a6ff]" />Analysis</h1>
          <p className="mt-1 text-xs font-mono text-[#8b949e]">Live device reporting, log quality, and rule findings with links back to evidence.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={isStale ? 'amber' : statusVariant}>
            {isStale ? 'STALE DATA' : `${status?.state.replace(/_/g, ' ').toUpperCase() || 'LOADING'}`}
          </Badge>
          <span className="text-xs font-mono text-[#8b949e]" aria-live="polite">
            {lastSuccess ? `Updated ${new Date(lastSuccess).toLocaleTimeString()}` : 'Waiting for API'}
          </span>
          <button type="button" onClick={() => void refresh()} disabled={loading} className="inline-flex items-center gap-1.5 rounded-md border border-[#30363d] bg-[#21262d] px-3 py-2 text-xs font-mono text-[#c9d1d9] hover:bg-[#30363d] disabled:opacity-50" aria-label="Refresh Analysis data">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>
      </header>

      {refreshError && <div role="alert" className="rounded-md border border-rose-900 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">Refresh failed: {refreshError}{isStale ? ' Showing the last successful data, marked stale.' : ''}</div>}

      <section aria-label="Analysis service status" className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#8b949e]">Analysis worker</h2>
            <p className="mt-1 text-sm text-[#c9d1d9]">{status?.reason || 'Loading service status…'}</p>
            {status?.configuration_error && <p className="mt-1 text-xs text-rose-300">{status.configuration_error}</p>}
          </div>
          <div className="flex flex-wrap gap-2 text-xs font-mono">
            <Badge variant={statusVariant}>{status?.state.replace(/_/g, ' ').toUpperCase() || 'LOADING'}</Badge>
            <Badge variant={status && status.pending_count > 0 ? 'amber' : 'gray'}>{status?.pending_count.toLocaleString() || '0'} pending</Badge>
            <Badge variant="gray">{status?.device_count || 0} devices · {status?.rule_count || 0} rules</Badge>
          </div>
        </div>
        {status?.pending_count ? <p className="mt-3 flex items-center gap-1.5 text-xs text-amber-300"><Clock3 className="h-3.5 w-3.5" />Oldest queued observation {timeAgo(status.oldest_pending_at)} · {Math.floor(status.oldest_pending_age_seconds)}s old</p> : null}
      </section>

      <section aria-label="Analysis summary" className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Configured devices" value={deviceTotal} subValue="matching current device filters" status="normal" icon={<Activity className="h-4 w-4 text-[#58a6ff]" />} />
        <MetricCard label="Unassigned sources" value={sourceTotal} subValue="unknown or ambiguous identity" status={sourceTotal ? 'warning' : 'good'} icon={<AlertTriangle className="h-4 w-4 text-amber-400" />} />
        <MetricCard label={`Findings · ${findingStatus}`} value={findingTotal} subValue="matching current finding filters" status={findingTotal ? 'error' : 'good'} icon={<ShieldCheck className="h-4 w-4 text-rose-400" />} />
        <MetricCard label="Health on this page" value={`${stateCounts.green} green · ${stateCounts.yellow + stateCounts.red} attention`} subValue={`${stateCounts.unknown} unknown · ${stateCounts.disabled} disabled`} status={stateCounts.red ? 'error' : stateCounts.yellow ? 'warning' : 'normal'} />
      </section>

      <section aria-labelledby="devices-heading" className="overflow-hidden rounded-lg border border-[#30363d] bg-[#161b22]">
        <div className="border-b border-[#21262d] p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div><h2 id="devices-heading" className="text-sm font-mono font-bold text-[#f0f6fc]">Configured devices</h2><p className="mt-1 text-xs text-[#8b949e]">Last activity, normalization quality, rates, and active findings.</p></div>
            <span className="text-xs font-mono text-[#8b949e]">{devices.length} shown · {deviceTotal.toLocaleString()} total</span>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <SelectField id="analysis-state" label="State" value={deviceState} onChange={(value) => setDeviceFilter(setDeviceState, value)} options={[[ '', 'All states'], ['green', 'Green'], ['yellow', 'Yellow'], ['red', 'Red'], ['unknown', 'Unknown'], ['disabled', 'Disabled']]} />
            <SelectField id="analysis-category" label="Category" value={category} onChange={(value) => setDeviceFilter(setCategory, value)} options={[[ '', 'All categories'], ...categories.map((value) => [value, value.replace(/_/g, ' ')] as [string, string])]} />
            <TextField id="analysis-site" label="Site" value={site} onChange={(value) => setDeviceFilter(setSite, value)} placeholder="e.g. hq" />
            <TextField id="analysis-device" label="Device" value={deviceSearch} onChange={(value) => setDeviceFilter(setDeviceSearch, value)} placeholder="ID or display name" />
            <SelectField id="analysis-device-window" label="Last activity" value={deviceWindow} onChange={(value) => setDeviceFilter(setDeviceWindow, value)} options={[[ '', 'Any time'], ['1h', 'Past hour'], ['24h', 'Past 24 hours'], ['7d', 'Past 7 days']]} />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1050px] text-left text-xs font-mono">
            <caption className="sr-only">Configured device health and recent log processing</caption>
            <thead className="bg-[#0d1117] text-[#8b949e]"><tr>
              <th className="px-4 py-3 font-medium">Device</th><th className="px-4 py-3 font-medium">State / reason</th><th className="px-4 py-3 font-medium">Last received</th><th className="px-4 py-3 font-medium">Normalized / quarantine</th><th className="px-4 py-3 font-medium">Rate / quality</th><th className="px-4 py-3 text-right font-medium">Active findings</th>
            </tr></thead>
            <tbody className="divide-y divide-[#21262d]">
              {devices.length === 0 ? <tr><td colSpan={6} className="px-4 py-12 text-center text-[#8b949e]">{loading ? 'Loading device telemetry…' : 'No devices match these filters. Clear a filter or add devices under analysis/devices/.'}</td></tr> : devices.map((device) => (
                <tr key={device.device_id} className="align-top hover:bg-[#21262d]/40">
                  <td className="px-4 py-3"><div className="font-semibold text-[#f0f6fc]">{device.display_name}</div><div className="mt-1 text-[11px] text-[#8b949e]">{device.device_id} · {device.source_category}</div><div className="mt-1 text-[11px] text-[#8b949e]">Site: {device.labels?.site || 'Unspecified'} · {device.reporting_mode || 'event'} reporting</div></td>
                  <td className="max-w-xs px-4 py-3"><Badge variant={stateVariant[device.state]}>{device.state.toUpperCase()}</Badge><p className="mt-2 whitespace-normal text-[11px] leading-relaxed text-[#8b949e]">{device.reason}</p>{device.maintenance && <p className="mt-1 text-[11px] text-amber-300">Maintenance until {dateLabel(device.maintenance_until)}</p>}</td>
                  <td className="px-4 py-3 text-[#c9d1d9]">{dateLabel(device.last_received_at)}<div className="mt-1 text-[11px] text-[#8b949e]">{timeAgo(device.last_received_at)}</div></td>
                  <td className="px-4 py-3 text-[#c9d1d9]">{dateLabel(device.last_normalized_at)}<div className="mt-1 text-[11px] text-[#8b949e]">Quarantine: {timeAgo(device.last_quarantined_at)}</div>{device.last_quarantined_at && <button type="button" onClick={() => onNavigate('quarantine')} className="mt-2 text-[11px] text-[#58a6ff] underline underline-offset-2">Open quarantine queue</button>}</td>
                  <td className="px-4 py-3 text-[#c9d1d9]">{device.received_per_minute.toFixed(1)} received/min<div className="mt-1 text-[11px] text-[#8b949e]">{device.normalized_per_minute.toFixed(1)} normalized/min · {device.quarantined_per_minute.toFixed(1)} quarantined/min</div><div className="mt-1 text-[11px] text-[#8b949e]">Quality {Math.round(device.normalization_ratio * 100)}%</div></td>
                  <td className="px-4 py-3 text-right"><Badge variant={device.active_finding_count ? 'red' : 'green'}>{device.active_finding_count} active</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager total={deviceTotal} offset={deviceOffset} onChange={setDeviceOffset} />
      </section>

      <section aria-labelledby="findings-heading" className="overflow-hidden rounded-lg border border-[#30363d] bg-[#161b22]">
        <div className="border-b border-[#21262d] p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><div><h2 id="findings-heading" className="text-sm font-mono font-bold text-[#f0f6fc]">Rule findings</h2><p className="mt-1 text-xs text-[#8b949e]">Select a finding to inspect its lifecycle and linked evidence.</p></div><span className="text-xs font-mono text-[#8b949e]">{findingTotal.toLocaleString()} matches</span></div>
          <div className="flex flex-wrap items-end gap-3">
            <SelectField id="finding-status" label="Finding status" value={findingStatus} onChange={(value) => setFindingFilter(setFindingStatus, value)} options={[[ 'open', 'Open'], ['clearing', 'Clearing'], ['resolved', 'Resolved'], ['all', 'All statuses']]} />
            <TextField id="finding-rule" label="Finding type / rule" value={ruleID} onChange={(value) => setFindingFilter(setRuleID, value)} placeholder="e.g. interface-down" />
            <TextField id="finding-device" label="Device ID" value={findingDevice} onChange={(value) => setFindingFilter(setFindingDevice, value)} placeholder="Exact device ID" />
            <SelectField id="finding-window" label="Updated within" value={findingWindow} onChange={(value) => setFindingFilter(setFindingWindow, value)} options={[[ '', 'Any time'], ['1h', 'Past hour'], ['24h', 'Past 24 hours'], ['7d', 'Past 7 days']]} />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-xs font-mono">
            <caption className="sr-only">Analysis findings and evidence links</caption>
            <thead className="bg-[#0d1117] text-[#8b949e]"><tr><th className="px-4 py-3 font-medium">State</th><th className="px-4 py-3 font-medium">Finding</th><th className="px-4 py-3 font-medium">Rule / device</th><th className="px-4 py-3 font-medium">Last seen</th><th className="px-4 py-3 text-right font-medium">Evidence</th></tr></thead>
            <tbody className="divide-y divide-[#21262d]">
              {findings.length === 0 ? <tr><td colSpan={5} className="px-4 py-12 text-center text-[#8b949e]">{loading ? 'Loading findings…' : 'No findings match these filters.'}</td></tr> : findings.map((finding) => (
                <tr key={finding.id} className="hover:bg-[#21262d]/40">
                  <td className="px-4 py-3"><div className="flex flex-wrap gap-1.5"><Badge variant={finding.state === 'red' ? 'red' : 'amber'}>{finding.state.toUpperCase()}</Badge><Badge variant={finding.status === 'resolved' ? 'gray' : 'blue'}>{finding.status.toUpperCase()}</Badge></div></td>
                  <td className="px-4 py-3"><div className="font-semibold text-[#f0f6fc]">{finding.title}</div><div className="mt-1 text-[11px] text-[#8b949e]">{finding.severity} · {finding.occurrence_count} occurrence(s)</div></td>
                  <td className="px-4 py-3 text-[#c9d1d9]">{finding.rule_id}<div className="mt-1 text-[11px] text-[#8b949e]">{finding.device_id || finding.owner_id}</div></td>
                  <td className="px-4 py-3 text-[#c9d1d9]">{dateLabel(finding.last_seen_at)}<div className="mt-1 text-[11px] text-[#8b949e]">{timeAgo(finding.last_seen_at)}</div></td>
                  <td className="px-4 py-3 text-right"><button type="button" onClick={() => { setHistoryOffset(0); setSelectedFinding(finding.id); }} className="rounded-md border border-[#30363d] px-2.5 py-1.5 text-[#58a6ff] hover:bg-[#21262d]">Inspect evidence</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager total={findingTotal} offset={findingOffset} onChange={setFindingOffset} />
        {findingDetail && <div className="border-t border-[#30363d] bg-[#0d1117] p-4 sm:p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div><h3 className="text-sm font-mono font-bold text-[#f0f6fc]">{findingDetail.finding.title}</h3><p className="mt-1 text-xs text-[#8b949e]">{findingDetail.finding.id} · rule {findingDetail.finding.rule_id} v{findingDetail.finding.rule_version}</p></div>
            <button type="button" onClick={() => { setSelectedFinding(null); setFindingDetail(null); }} className="rounded border border-[#30363d] px-2.5 py-1 text-xs text-[#c9d1d9] hover:bg-[#21262d]">Close details</button>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {findingDetail.finding.last_event_id && <button type="button" onClick={() => onNavigate('events', findingDetail.finding.last_event_id)} className="rounded border border-[#30363d] px-3 py-1.5 text-xs text-[#58a6ff] hover:bg-[#21262d]">Open event and trace</button>}
            {findingDetail.finding.last_event_id && <button type="button" onClick={() => void verifyEvidence()} className="rounded border border-[#30363d] px-3 py-1.5 text-xs text-emerald-300 hover:bg-[#21262d]">Verify event evidence</button>}
            {findingDetail.evidence.raw && <a href={findingDetail.evidence.raw} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded border border-[#30363d] px-3 py-1.5 text-xs text-[#c9d1d9] hover:bg-[#21262d]">Open raw evidence <ExternalLink className="h-3 w-3" /></a>}
            {!findingDetail.finding.last_event_id && <button type="button" onClick={() => onNavigate('quarantine')} className="rounded border border-[#30363d] px-3 py-1.5 text-xs text-[#58a6ff] hover:bg-[#21262d]">Open quarantine queue</button>}
          </div>
          {verifyResult && <p role="status" className="mt-3 text-xs text-[#c9d1d9]">{verifyResult}</p>}
          <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[600px] text-left text-xs font-mono"><caption className="sr-only">Finding transition history and evidence</caption><thead className="text-[#8b949e]"><tr><th className="py-2 pr-3">Transition</th><th className="py-2 pr-3">Time</th><th className="py-2 pr-3">Evidence</th></tr></thead><tbody className="divide-y divide-[#21262d]">{findingDetail.history.map((item) => <tr key={item.history.id}><td className="py-2 pr-3 text-[#c9d1d9]">{item.history.action.replace(/_/g, ' ')}</td><td className="py-2 pr-3 text-[#8b949e]">{dateLabel(item.history.occurred_at)}</td><td className="py-2 pr-3">{item.history.event_id ? <button type="button" onClick={() => onNavigate('events', item.history.event_id)} className="text-[#58a6ff] underline">Open event</button> : <button type="button" onClick={() => onNavigate('quarantine')} className="text-[#58a6ff] underline">Open quarantine</button>}{item.evidence.raw && <> · <a href={item.evidence.raw} target="_blank" rel="noreferrer" className="text-[#c9d1d9] underline">raw</a></>}</td></tr>)}</tbody></table></div>
          <div className="mt-3 flex items-center justify-between text-xs font-mono text-[#8b949e]"><span>History {findingDetail.history_total ? `${historyOffset + 1}–${Math.min(findingDetail.history_total, historyOffset + findingDetail.history.length)} of ${findingDetail.history_total}` : 'is empty'}</span><div className="flex gap-2"><button type="button" disabled={historyOffset === 0} onClick={() => setHistoryOffset(Math.max(0, historyOffset - 50))} className="rounded border border-[#30363d] px-2.5 py-1 text-[#c9d1d9] disabled:opacity-40">Previous</button><button type="button" disabled={historyOffset + 50 >= findingDetail.history_total} onClick={() => setHistoryOffset(historyOffset + 50)} className="rounded border border-[#30363d] px-2.5 py-1 text-[#c9d1d9] disabled:opacity-40">Next</button></div></div>
        </div>}
      </section>

      <section aria-labelledby="sources-heading" className="overflow-hidden rounded-lg border border-[#30363d] bg-[#161b22]">
        <div className="border-b border-[#21262d] p-4"><h2 id="sources-heading" className="text-sm font-mono font-bold text-[#f0f6fc]">Unknown and ambiguous sources</h2><p className="mt-1 text-xs text-[#8b949e]">Sources that need an inventory alias before RAVEN can assign them to a device.</p></div>
        <div className="overflow-x-auto"><table className="w-full min-w-[700px] text-left text-xs font-mono"><caption className="sr-only">Unassigned analysis sources</caption><thead className="bg-[#0d1117] text-[#8b949e]"><tr><th className="px-4 py-3 font-medium">Source identity</th><th className="px-4 py-3 font-medium">Resolution</th><th className="px-4 py-3 font-medium">Match confidence</th><th className="px-4 py-3 font-medium">Observations</th><th className="px-4 py-3 font-medium">Last seen</th></tr></thead><tbody className="divide-y divide-[#21262d]">{sources.length === 0 ? <tr><td colSpan={5} className="px-4 py-8 text-center text-[#8b949e]">{loading ? 'Loading sources…' : 'All observed sources are assigned, or none have been seen.'}</td></tr> : sources.map((source) => <tr key={source.source_key}><td className="px-4 py-3 text-[#c9d1d9]">{source.source_key.slice(0, 20)}…<div className="mt-1 text-[11px] text-[#8b949e]">{Object.entries(source.identity_hints || {}).map(([key, value]) => `${key}: ${value}`).join(' · ') || 'No identity hints'}</div></td><td className="px-4 py-3"><Badge variant={source.resolution === 'ambiguous' ? 'amber' : 'gray'}>{source.resolution.toUpperCase()}</Badge></td><td className="px-4 py-3 text-[#c9d1d9]">{source.confidence || 'none'} · {source.match_method || 'no alias match'}</td><td className="px-4 py-3 text-[#c9d1d9]">{source.observation_count.toLocaleString()}</td><td className="px-4 py-3 text-[#8b949e]">{dateLabel(source.last_seen_at)}</td></tr>)}</tbody></table></div>
        <Pager total={sourceTotal} offset={sourceOffset} onChange={setSourceOffset} />
      </section>
      <p className="flex items-center gap-1.5 text-[11px] font-mono text-[#8b949e]"><Search className="h-3 w-3" />Filters use server-side pagination. Data becomes stale after {Math.round(staleAfter / 1000)} seconds without a successful refresh.</p>
    </div>
  );
};

export default Analysis;
