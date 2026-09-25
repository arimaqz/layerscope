import {useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {Activity,Ban,BriefcaseBusiness,HardDrive,Radio,RefreshCw,RotateCcw,Upload,UsersRound} from 'lucide-react'
import {Link} from 'react-router-dom'
import {api} from '../api'
import type {ScanJob,ServiceStatus,UploadJob} from '../types'
import ProgressBar from '../components/ProgressBar'
import {stageLabel} from '../jobUtils'
import {errorMessage} from '../errors'
import StatusBadge from '../components/StatusBadge'

const filters=['all','queued','running','completed','failed','cancelled'] as const

export default function JobsPage(){
  const [filter,setFilter]=useState<(typeof filters)[number]>('all')
  const qc=useQueryClient()
  const suffix=filter==='all'?'':`?status=${filter}`
  const scans=useQuery({queryKey:['jobs',filter],queryFn:()=>api.get<ScanJob[]>(`/api/jobs${suffix}`),refetchInterval:query=>(query.state.data as ScanJob[]|undefined)?.some(active)?10000:30000,refetchIntervalInBackground:false})
  const uploads=useQuery({queryKey:['upload-jobs',filter],queryFn:()=>api.get<UploadJob[]>(`/api/upload-jobs${suffix}`),refetchInterval:query=>(query.state.data as UploadJob[]|undefined)?.some(active)?3000:30000,refetchIntervalInBackground:false})
  const service=useQuery({queryKey:['service-status'],queryFn:()=>api.get<ServiceStatus>('/api/service-status'),refetchInterval:query=>{const data=query.state.data as ServiceStatus|undefined;return data?.queue.active?10000:30000},refetchIntervalInBackground:false})
  const cancel=useMutation({mutationFn:(id:number)=>api.post(`/api/jobs/${id}/cancel`),onSuccess:()=>invalidate(qc)})
  const retry=useMutation({mutationFn:(id:number)=>api.post(`/api/jobs/${id}/retry`),onSuccess:()=>invalidate(qc)})
  const entries=[...(scans.data||[]).map(job=>({kind:'scan' as const,job})),...(uploads.data||[]).map(job=>({kind:'upload' as const,job}))].sort((left,right)=>new Date(right.job.queued_at).getTime()-new Date(left.job.queued_at).getTime())
  const fetching=scans.isFetching||uploads.isFetching||service.isFetching
  const error=scans.error||uploads.error
  return <div className="space-y-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-600">Persistent work history</p><h1 className="flex items-center gap-3 text-3xl font-bold"><BriefcaseBusiness size={30}/>Jobs</h1><p className="mt-1 text-slate-500">Monitor archive uploads and vulnerability scans, including active progress and completed or failed work.</p></div><button className="btn-secondary" disabled={fetching} onClick={()=>{scans.refetch();uploads.refetch();service.refetch()}}><RefreshCw className={fetching?'animate-spin':''} size={16}/>Refresh</button></div>
    {service.data&&<ServiceCapacity value={service.data}/>}
    {service.isError&&<p className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">Capacity metrics are temporarily unavailable. Job polling continues normally.</p>}
    <div className="flex flex-wrap gap-2">{filters.map(item=><button key={item} className={item===filter?'btn-primary':'btn-secondary'} onClick={()=>setFilter(item)}>{item.charAt(0).toUpperCase()+item.slice(1)}</button>)}</div>
    {(scans.isLoading||uploads.isLoading)?<div className="card p-10"><ProgressBar indeterminate label="Loading jobs"/></div>:error?<div className="card p-5 text-rose-700">{errorMessage(error,'Unable to load jobs')}</div>:!entries.length?<div className="card p-12 text-center text-slate-500">No {filter==='all'?'':filter} jobs yet.</div>:<div className="space-y-3">{entries.map(entry=>entry.kind==='scan'?<ScanJobCard key={`scan-${entry.job.id}`} job={entry.job} busy={cancel.isPending||retry.isPending} onCancel={()=>cancel.mutate(entry.job.id)} onRetry={()=>retry.mutate(entry.job.id)}/>:<UploadJobCard key={`upload-${entry.job.id}`} job={entry.job}/>)}</div>}
    {(cancel.isError||retry.isError)&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(cancel.error||retry.error,'Unable to update the scan job')}</p>}
  </div>
}

function active(job:{status:string}){return job.status==='queued'||job.status==='running'}

function ServiceCapacity({value}:{value:ServiceStatus}){
  return <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
    <CapacityCard icon={<Activity/>} label="Scan queue capacity" value={`${value.queue.active} / ${value.queue.capacity}`} detail={`${value.queue.running} running · ${value.queue.queued} queued`}><ProgressBar className="mt-3" compact value={value.queue.utilization} label="Utilization"/></CapacityCard>
    <CapacityCard icon={<UsersRound/>} label="Scan workers" value={`${value.workers.available} / ${value.workers.configured}`} detail="Available / configured"/>
    <CapacityCard icon={<HardDrive/>} label="Storage headroom" value={formatBytes(value.storage.free_bytes)} detail={`${value.storage.limiting_source==='host_probe'?'Host drive':'Docker volume'} limit · ${formatBytes(value.storage.reserve_bytes)} reserve`} tone={value.storage.status}/>
    <CapacityCard icon={<Radio/>} label="Live progress" value={`${value.events.clients} / ${value.events.capacity}`} detail={value.events.dropped?`${value.events.dropped} event(s) dropped; polling recovered`:'No delivery drops'}/>
  </section>
}

function CapacityCard({icon,label,value,detail,tone='ok',children}:{icon:React.ReactNode;label:string;value:string;detail:string;tone?:'ok'|'warning'|'critical';children?:React.ReactNode}){const style=tone==='critical'?'bg-rose-50 text-rose-700':tone==='warning'?'bg-amber-50 text-amber-700':'bg-blue-50 text-blue-700';return <article className="card p-4"><div className="flex items-start gap-3"><span className={`rounded-xl p-2.5 ${style}`}>{icon}</span><div className="min-w-0"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p><p className="mt-0.5 text-xl font-bold tabular-nums">{value}</p><p className="mt-1 truncate text-xs text-slate-500" title={detail}>{detail}</p></div></div>{children}</article>}

function formatBytes(value:number){const units=['B','KiB','MiB','GiB','TiB'];let amount=value,index=0;while(amount>=1024&&index<units.length-1){amount/=1024;index++}return `${amount.toFixed(index?1:0)} ${units[index]}`}

function ScanJobCard({job,busy,onCancel,onRetry}:{job:ScanJob;busy:boolean;onCancel:()=>void;onRetry:()=>void}){
  const isActive=active(job)
  return <article className="card p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full bg-violet-50 px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-violet-700">Scan</span><Link to={`/images/${job.image_id}`} className="truncate font-semibold text-blue-700 hover:underline">{job.image_name}</Link><StatusBadge status={job.status}/><span className="text-xs text-slate-500">Job #{job.id}</span></div><p className="mt-1 text-xs text-slate-500">Queued {new Date(job.queued_at).toLocaleString()}{job.queue_position?` · position ${job.queue_position}`:''}</p></div><div className="flex gap-2">{isActive&&<button className="btn-secondary text-rose-700" disabled={busy} onClick={onCancel}><Ban size={15}/>Cancel</button>}{(job.status==='failed'||job.status==='cancelled')&&<button className="btn-primary" disabled={busy} onClick={onRetry}><RotateCcw size={15}/>Retry</button>}</div></div><ProgressBar className="mt-4" value={job.progress} label={stageLabel(job.stage)} detail={job.message}/>{job.coverage_warning&&<p className="mt-3 rounded-lg bg-amber-50 p-3 text-xs font-medium text-amber-800">{job.coverage_warning}</p>}{job.error&&<FailureDetails error={job.error} fallback="The scan failed without readable details"/>}</article>
}

function UploadJobCard({job}:{job:UploadJob}){
  const archive=job.image_id?<Link to={`/images/${job.image_id}`} className="truncate font-semibold text-blue-700 hover:underline">{job.archive_name}</Link>:<span className="truncate font-semibold">{job.archive_name}</span>
  const transfer=job.total_bytes?`${formatBytes(job.bytes_received)} / ${formatBytes(job.total_bytes)}`:job.bytes_received?`${formatBytes(job.bytes_received)} received`:''
  return <article className="card p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="inline-flex items-center gap-1 rounded-full bg-cyan-50 px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-cyan-700"><Upload size={12}/>Upload</span>{archive}<StatusBadge status={job.status}/><span className="text-xs text-slate-500">Job #{job.id}</span></div><p className="mt-1 text-xs text-slate-500">Started {new Date(job.queued_at).toLocaleString()}{job.image_count>1?` · ${job.image_count} archives`:''}</p></div></div><ProgressBar className="mt-4" value={job.progress} label={stageLabel(job.stage)} detail={[job.message,transfer].filter(Boolean).join(' · ')}/>{job.error&&<FailureDetails error={job.error} fallback="The upload failed without readable details"/>}</article>
}

function FailureDetails({error,fallback}:{error:string;fallback:string}){return <details className="mt-3 rounded-lg bg-rose-50 p-3 text-xs text-rose-700"><summary className="cursor-pointer font-semibold">Failure details</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap">{errorMessage(error,fallback)}</pre></details>}

function invalidate(qc:ReturnType<typeof useQueryClient>){void qc.invalidateQueries({queryKey:['jobs']});void qc.invalidateQueries({queryKey:['images']});void qc.invalidateQueries({queryKey:['overview']});void qc.invalidateQueries({queryKey:['image']})}
