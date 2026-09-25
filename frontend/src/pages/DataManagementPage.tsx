import {useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {ArchiveRestore,Ban,DatabaseZap,RefreshCw,Trash2,X} from 'lucide-react'
import {api} from '../api'
import {useAuth} from '../auth'
import DestructiveConfirmDialog from '../components/DestructiveConfirmDialog'
import BackupPanel from '../components/BackupPanel'
import ReportImportPanel from '../components/ReportImportPanel'
import StatusBadge from '../components/StatusBadge'
import ArchiveSource from '../components/ArchiveSource'
import {errorMessage} from '../errors'
import type {ImageArchive,RemovedImage,ScanJob} from '../types'

type DeleteIntent={kind:'scans';jobs:ScanJob[]}|{kind:'image';image:ImageArchive}
const activeScan=(job:ScanJob)=>['queued','running'].includes(job.status)

export default function DataManagementPage(){
  const auth=useAuth(),qc=useQueryClient(),admin=auth.user?.role==='admin',[selected,setSelected]=useState<number[]>([]),[intent,setIntent]=useState<DeleteIntent|null>(null)
  const images=useQuery({queryKey:['images'],queryFn:()=>api.get<ImageArchive[]>('/api/images'),enabled:admin})
  const jobs=useQuery({queryKey:['jobs','cleanup'],queryFn:()=>api.get<ScanJob[]>('/api/jobs?limit=500'),enabled:admin})
  const removed=useQuery({queryKey:['removed-images'],queryFn:()=>api.get<RemovedImage[]>('/api/images/removed'),enabled:admin})
  const refresh=()=>{void qc.invalidateQueries({queryKey:['images']});void qc.invalidateQueries({queryKey:['image']});void qc.invalidateQueries({queryKey:['overview']});void qc.invalidateQueries({queryKey:['jobs']});void qc.invalidateQueries({queryKey:['removed-images']});void qc.invalidateQueries({queryKey:['packages']});void qc.invalidateQueries({queryKey:['comparison']})}
  const completed=()=>{setSelected([]);setIntent(null);refresh()}
  const removeScan=useMutation({mutationFn:(id:number)=>api.delete(`/api/scans/${id}`),onSuccess:completed})
  const removeScans=useMutation({mutationFn:(ids:number[])=>api.post('/api/scans/bulk-delete',{scan_ids:ids}),onSuccess:completed})
  const removeImage=useMutation({mutationFn:(id:number)=>api.delete(`/api/images/${id}`),onSuccess:completed})
  const restore=useMutation({mutationFn:(id:number)=>api.post(`/api/images/${id}/restore`),onSuccess:refresh})
  const busy=removeScan.isPending||removeScans.isPending||removeImage.isPending||restore.isPending
  const error=images.error||jobs.error||removed.error||removeScan.error||removeScans.error||removeImage.error||restore.error
  const terminalJobs=(jobs.data||[]).filter(job=>!activeScan(job)),selectedJobs=terminalJobs.filter(job=>selected.includes(job.id)),allSelected=terminalJobs.length>0&&selectedJobs.length===terminalJobs.length

  if(!admin)return <div className="card border-rose-200 p-8 text-center text-rose-700"><Ban className="mx-auto mb-3"/><h1 className="text-xl font-bold">Administrator access required</h1><p className="mt-1 text-sm">Only administrators can permanently remove saved data.</p></div>

  function toggle(id:number){setSelected(value=>value.includes(id)?value.filter(item=>item!==id):[...value,id])}
  function confirmDelete(){if(!intent)return;if(intent.kind==='image'){removeImage.mutate(intent.image.id);return}const ids=intent.jobs.map(job=>job.id);if(ids.length===1)removeScan.mutate(ids[0]);else removeScans.mutate(ids)}
  const dialogError=intent?errorMessage(removeScan.error||removeScans.error||removeImage.error,''):''

  return <div className="space-y-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div className="max-w-5xl"><p className="text-sm font-medium text-blue-700">Protected backup and data controls</p><h1 className="flex items-center gap-3 text-3xl font-bold"><DatabaseZap size={30}/>Data management</h1><p className="mt-1 text-slate-500">Create encrypted portable backups, restore validated data, or remove stored scans and archives. Every action is administrator-only, CSRF-protected, and audited.</p></div><button className="btn-secondary shrink-0" disabled={images.isFetching||jobs.isFetching||removed.isFetching} onClick={()=>{images.refetch();jobs.refetch();removed.refetch()}}><RefreshCw className={images.isFetching||jobs.isFetching||removed.isFetching?'animate-spin':''} size={16}/>Refresh</button></div>
    {error&&!intent&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(error,'Unable to update stored data')}</p>}

    <BackupPanel/>
    <ReportImportPanel/>

    <section className="card overflow-hidden"><div className="border-b p-5"><h2 className="font-semibold">Images and report-only entries</h2><p className="text-sm text-slate-500">Removing an uploaded image deletes its TAR file. A read-only mounted image is hidden. An imported report is removed permanently because it contains no archive.</p></div><div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="p-4">Image or report</th><th className="p-4">Latest status</th><th className="p-4">Saved findings</th><th className="p-4 text-right">Action</th></tr></thead><tbody>{(images.data||[]).map(image=>{const active=image.latest_scan&&['queued','running'].includes(image.latest_scan.status);return <tr className="border-t" key={image.id}><td className="p-4"><div className="font-semibold">{image.name}</div><div className="mt-1"><ArchiveSource source={image.source} compact/></div></td><td className="p-4"><StatusBadge status={image.latest_scan?.status}/></td><td className="p-4 font-semibold tabular-nums">{image.latest_scan?.total||0}</td><td className="p-4 text-right"><button className="btn-secondary text-rose-700" disabled={busy||!!active} title={active?'Cancel the active scan first':'Remove image and all scan history'} onClick={()=>setIntent({kind:'image',image})}><Trash2 size={15}/>Remove image</button></td></tr>})}</tbody></table></div>{!images.data?.length&&<p className="p-8 text-center text-slate-500">No visible images or imported reports.</p>}</section>

    <section className="card overflow-hidden">
      <div className="flex min-h-[86px] flex-wrap items-center justify-between gap-4 border-b p-5"><div><h2 className="font-semibold">Saved scans and jobs</h2><p className="text-sm text-slate-500">Select any completed, failed, or cancelled scans to remove them together. Active work must be cancelled first.</p></div>{selectedJobs.length>0&&<div className="flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 p-2 pl-3"><span className="text-sm font-semibold text-rose-700">{selectedJobs.length} selected</span><button className="btn-secondary px-2 py-1.5" disabled={busy} onClick={()=>setSelected([])} title="Clear selection"><X size={15}/></button><button className="btn bg-rose-700 px-3 py-1.5 text-white hover:bg-rose-800" disabled={busy} onClick={()=>setIntent({kind:'scans',jobs:selectedJobs})}><Trash2 size={15}/>Delete selected</button></div>}</div>
      <div className="max-h-[520px] overflow-auto"><table className="w-full min-w-[820px] text-left text-sm"><thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="w-12 p-4"><input type="checkbox" className="h-4 w-4 cursor-pointer accent-rose-700" aria-label="Select all removable scans" checked={allSelected} disabled={!terminalJobs.length||busy} onChange={()=>setSelected(allSelected?[]:terminalJobs.map(job=>job.id))}/></th><th className="p-4">Scan</th><th className="p-4">Image</th><th className="p-4">Status</th><th className="p-4">Queued</th><th className="p-4 text-right">Action</th></tr></thead><tbody>{(jobs.data||[]).map(job=>{const active=activeScan(job),checked=selected.includes(job.id);return <tr className={`border-t transition ${checked?'bg-rose-50/70':''}`} key={job.id}><td className="p-4"><input type="checkbox" className="h-4 w-4 cursor-pointer accent-rose-700" aria-label={`Select scan ${job.id}`} checked={checked} disabled={busy||active} onChange={()=>toggle(job.id)}/></td><td className="p-4 font-semibold">#{job.id}</td><td className="p-4">{job.image_name}</td><td className="p-4"><StatusBadge status={job.status}/></td><td className="p-4 text-slate-500">{new Date(job.queued_at).toLocaleString()}</td><td className="p-4 text-right"><button className="btn-secondary text-rose-700" disabled={busy||active} title={active?'Cancel the active scan first':'Permanently remove this scan'} onClick={()=>setIntent({kind:'scans',jobs:[job]})}><Trash2 size={15}/>Remove scan</button></td></tr>})}</tbody></table></div>{!jobs.data?.length&&<p className="p-8 text-center text-slate-500">No saved scans.</p>}
    </section>

    <section className="card overflow-hidden"><div className="border-b p-5"><h2 className="font-semibold">Hidden mounted images</h2><p className="text-sm text-slate-500">The original read-only files were not deleted. Restore them to the dashboard while they remain under a configured scan root.</p></div><div>{(removed.data||[]).map(image=><div key={image.id} className="flex flex-wrap items-center justify-between gap-3 border-t p-4 text-sm"><div><div className="font-semibold">{image.name}</div><div className="mt-1"><ArchiveSource source={image.source} compact/></div></div><button className="btn-secondary text-emerald-700" disabled={busy} onClick={()=>restore.mutate(image.id)}><ArchiveRestore size={15}/>Restore</button></div>)}</div>{!removed.data?.length&&<p className="p-8 text-center text-slate-500">No hidden mounted images.</p>}</section>

    {intent?.kind==='scans'&&<DestructiveConfirmDialog title={intent.jobs.length===1?`Delete scan #${intent.jobs[0].id}?`:`Delete ${intent.jobs.length} selected scans?`} description={intent.jobs.length===1?'Review the scan below before permanently removing its stored evidence.':'Review the selection below. The server validates the entire batch before deleting any record.'} confirmation={intent.jobs.length===1?String(intent.jobs[0].id):`DELETE ${intent.jobs.length} SCANS`} items={intent.jobs.map(job=>`#${job.id} · ${job.image_name} · ${job.status}`)} summaries={[{label:'Selected scans',value:String(intent.jobs.length)},{label:'Stored data',value:'Findings, packages, raw JSON'}]} busy={busy} error={dialogError} confirmLabel={intent.jobs.length===1?'Delete scan':'Delete selected scans'} onCancel={()=>setIntent(null)} onConfirm={confirmDelete}/>}
    {intent?.kind==='image'&&<DestructiveConfirmDialog title={`Remove ${intent.image.name}?`} description={intent.image.source==='report'?'This report-only entry and its imported history will be permanently removed.':"Uploaded archives are permanently deleted. Read-only mounted archives are hidden and can be restored later."} confirmation={intent.image.name} items={[intent.image.name]} summaries={[{label:'Source',value:intent.image.source==='upload'?'Dashboard upload':intent.image.source==='report'?'Imported report':'Mounted archive'},{label:'Scan history',value:'All saved scans and normalized evidence'}]} warning={intent.image.source==='report'?"Keep the exported JSON file if you may want to import this report again later.":"Removing this image also removes all of its saved scans, normalized findings, package records, and raw JSON. An uploaded TAR file cannot be restored."} busy={busy} error={dialogError} confirmLabel="Remove image" onCancel={()=>setIntent(null)} onConfirm={confirmDelete}/>}
  </div>
}
