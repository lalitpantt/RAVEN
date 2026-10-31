import React, { useCallback, useEffect, useState } from 'react';
import { apiService } from '../services/api';

export const Integrity: React.FC = () => {
  const [token,setToken]=useState('');
  const [status,setStatus]=useState<any>(null);
  const [run,setRun]=useState<any>(null);
  const [proofSeq,setProofSeq]=useState('');
  const [proof,setProof]=useState<any>(null);
  const [error,setError]=useState('');
  const refresh=useCallback(async()=>{try{setError('');setStatus(await apiService.integrityStatus())}catch(e){setError((e as Error).message)}},[]);
  useEffect(()=>{void refresh()},[refresh]);
  useEffect(()=>{
    if(!run?.run_id || run.state==='completed' || run.state==='failed') return;
    const timer=window.setInterval(()=>apiService.getIntegrityAudit(run.run_id).then(setRun).catch(e=>setError(e.message)),1000);
    return ()=>window.clearInterval(timer);
  },[run]);
  const start=async(type:'fast'|'deep'|'ledger')=>{try{apiService.setAdminToken(token);setError('');setRun(await apiService.startIntegrityAudit(type))}catch(e){setError((e as Error).message)}};
  const loadProof=async(e:React.FormEvent)=>{e.preventDefault();try{apiService.setAdminToken(token);setError('');setProof(await apiService.getIntegrityProof(proofSeq))}catch(e){setError((e as Error).message)}};
  return <section className="space-y-6" aria-labelledby="integrity-title">
    <div><h1 id="integrity-title" className="text-2xl font-semibold text-white">Evidence integrity</h1><p className="mt-1 text-sm text-[#8b949e]">Local journal, witness, ledger audit, and inclusion proofs.</p></div>
    <label className="block max-w-xl text-sm">RAVEN admin token
      <input type="password" autoComplete="current-password" value={token} onChange={e=>setToken(e.target.value)} className="mt-1 block w-full rounded border border-[#30363d] bg-[#0d1117] px-3 py-2 text-white" aria-describedby="token-note" />
      <span id="token-note" className="text-xs text-[#8b949e]">Used in memory for this page session only.</span>
    </label>
    {error&&<p role="alert" className="rounded border border-red-700 p-3 text-red-300">{error}</p>}
    <section className="rounded-lg border border-[#30363d] bg-[#161b22] p-4" aria-label="Integrity status">
      <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-medium text-white">Status</h2><button onClick={()=>{apiService.setAdminToken(token);void refresh()}} className="rounded border border-[#30363d] px-3 py-2 text-sm hover:bg-[#21262d]">Refresh status</button></div>
      {status?<dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[['Mode',status.enabled?'Enabled':'Disabled'],['Local head',status.local_head?.entry_seq??0],['Witness backlog',status.backlog_count??'Unavailable'],['Unsealed entries',status.unsealed_entry_count??0],['Last audit',status.latest_attempt?.result??'Not run'],['Last successful audit',status.last_success?.completed_at??'Not run'],['Witness head',status.witness_head?.entry_seq??0],['Chain head',status.chain_head?.entry_seq??0]].map(([label,value])=><div key={String(label)} className="rounded bg-[#0d1117] p-3"><dt className="text-xs text-[#8b949e]">{label}</dt><dd className="mt-1 break-all font-mono text-sm text-white">{value}</dd></div>)}</dl>:<p className="mt-3 text-sm text-[#8b949e]">Enter the admin token and refresh to load operator status.</p>}
    </section>
    <section className="rounded-lg border border-[#30363d] bg-[#161b22] p-4"><h2 className="text-lg font-medium text-white">Run an audit</h2><div className="mt-3 flex flex-wrap gap-2">{(['fast','deep','ledger'] as const).map(type=><button key={type} onClick={()=>void start(type)} className="rounded bg-[#1f6feb] px-3 py-2 text-sm font-medium text-white hover:bg-[#388bfd]">Start {type} audit</button>)}</div>{run&&<pre role="status" className="mt-3 overflow-auto rounded bg-[#0d1117] p-3 text-xs text-[#c9d1d9]">{JSON.stringify(run,null,2)}</pre>}</section>
    <section className="rounded-lg border border-[#30363d] bg-[#161b22] p-4"><h2 className="text-lg font-medium text-white">Inspect proof</h2><form onSubmit={loadProof} className="mt-3 flex flex-wrap gap-2"><label htmlFor="entry-seq" className="sr-only">Evidence entry sequence</label><input id="entry-seq" inputMode="numeric" pattern="[0-9]+" required min="1" value={proofSeq} onChange={e=>setProofSeq(e.target.value)} placeholder="Entry sequence" className="rounded border border-[#30363d] bg-[#0d1117] px-3 py-2 text-white"/><button className="rounded border border-[#30363d] px-3 py-2 text-sm hover:bg-[#21262d]">Inspect proof</button></form>{proof&&<pre className="mt-3 max-h-96 overflow-auto rounded bg-[#0d1117] p-3 text-xs text-[#c9d1d9]">{JSON.stringify(proof,null,2)}</pre>}</section>
  </section>;
};
