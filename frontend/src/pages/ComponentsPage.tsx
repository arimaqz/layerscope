import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {Ban,CheckCircle2,CloudDownload,Database,PackageCheck,RefreshCw,ServerCog,ShieldCheck} from 'lucide-react'
import {api} from '../api'
import type {ComponentInfo,MaintenanceJob} from '../types'
import ProgressBar from '../components/ProgressBar'
import {stageLabel} from '../jobUtils'
import {errorMessage} from '../errors'
import StatusBadge from '../components/StatusBadge'

export default function ComponentsPage(){
  const qc=useQueryClient()
  const components=useQuery({queryKey:['components'],queryFn:()=>api.get<ComponentInfo[]>('/api/components'),refetchInterval:query=>(query.state.data as ComponentInfo[]|undefined)?.some(item=>item.latest_job&&['queued','running'].includes(item.latest_job.status))?8000:30000,refetchIntervalInBackground:false,retry:false})
  const check=useMutation({mutationFn:()=>api.post('/api/components/check'),onSuccess:()=>refresh(qc)})
  const update=useMutation({mutationFn:(id:string)=>api.post(`/api/components/${id}/update`),onSuccess:()=>refresh(qc)})
  const cancel=useMutation({mutationFn:(id:number)=>api.post(`/api/component-jobs/${id}/cancel`),onSuccess:()=>refresh(qc)})
  const busy=check.isPending||update.isPending||cancel.isPending
  return <div className="space-y-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-600">Offline-ready security data</p><h1 className="flex items-center gap-3 text-3xl font-bold"><ServerCog size={30}/>Components and updates</h1><p className="mt-1 max-w-3xl text-slate-500">Review bundled scanner data, check update windows and registry access, and install updates without rerunning saved scans.</p></div><button className="btn-primary" disabled={busy} onClick={()=>check.mutate()}><RefreshCw className={check.isPending?'animate-spin':''} size={16}/>Check for updates</button></div>
    <div className="flex gap-3 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800"><ShieldCheck className="mt-0.5 shrink-0" size={19}/><p><b>Normal OS-package scans are offline-safe.</b> The required vulnerability database is bundled into the backend image and copied into persistent storage on first start. The much larger Java index is optional and can be installed here when you need JAR scanning. Internet access is used only when you explicitly check or update.</p></div>
    {components.isLoading?<div className="card p-10"><ProgressBar indeterminate label="Inspecting installed components"/></div>:components.isError?<div className="card border-rose-200 p-5 text-rose-700">Unable to load components: {errorMessage(components.error)}</div>:<div className="grid gap-4 xl:grid-cols-2">{components.data!.map(component=><ComponentCard key={component.id} component={component} busy={busy} onUpdate={()=>update.mutate(component.id)} onCancel={id=>cancel.mutate(id)}/>)}</div>}
    {(check.isError||update.isError||cancel.isError)&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(check.error||update.error||cancel.error,'Unable to update components')}</p>}
  </div>
}

function ComponentCard({component,busy,onUpdate,onCancel}:{component:ComponentInfo;busy:boolean;onUpdate:()=>void;onCancel:(id:number)=>void}){
  const job=component.latest_job,active=job&&(job.status==='queued'||job.status==='running')
  const managed=component.id==='vulnerability_db'||component.id==='java_db'
  return <article className="card p-5"><div className="flex items-start justify-between gap-4"><div className="flex min-w-0 gap-3"><span className="rounded-lg bg-blue-50 p-3 text-blue-600">{icon(component.id)}</span><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h2 className="font-semibold">{component.name}</h2>{component.required&&<span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-slate-600">Required</span>}{component.bundled&&<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-700">Bundled</span>}</div><p className="mt-1 text-sm text-slate-500">{component.description}</p></div></div>{managed&&!active&&<button className="btn-secondary shrink-0" disabled={busy} onClick={onUpdate}><CloudDownload size={15}/>{component.installed?'Update now':'Install'}</button>}{active&&<button className="btn-secondary shrink-0 text-rose-700" disabled={busy} onClick={()=>onCancel(job!.id)}><Ban size={15}/>Cancel</button>}</div>
    <div className="mt-4 grid gap-2 text-xs sm:grid-cols-2"><Fact label="Status" value={component.installed?'Installed':'Not installed'}/>{component.version&&<Fact label="Version" value={component.version}/>}<Fact label="Last data update" value={formatDate(component.updated_at)}/><Fact label="Next update window" value={formatDate(component.next_update)}/>{component.size_bytes!==undefined&&<Fact label="Disk usage" value={formatBytes(component.size_bytes)}/>}<Fact label="Update state" value={component.update_available?'Update recommended':'Current'}/></div>
    {component.repositories?.length&&<details className="mt-3 text-xs text-slate-500"><summary className="cursor-pointer font-medium">Configured download sources</summary><ul className="mt-2 space-y-1">{component.repositories.map(item=><li key={item}><code>{item}</code></li>)}</ul></details>}
    {component.update_method&&<p className="mt-3 rounded-lg bg-slate-50 p-3 text-xs text-slate-500">{component.update_method}</p>}
    {job&&<Job job={job}/>}
  </article>
}

function Job({job}:{job:MaintenanceJob}){const active=job.status==='queued'||job.status==='running';return <div className="mt-4 border-t pt-4"><div className="mb-2 flex flex-wrap items-center justify-between gap-3 text-xs"><div className="flex items-center gap-2"><span className="font-semibold capitalize">Latest {job.action}</span><StatusBadge status={job.status}/></div>{job.finished_at&&<span className="text-slate-500">{new Date(job.finished_at).toLocaleString()}</span>}</div>{active?<ProgressBar value={job.progress} label={stageLabel(job.stage)} detail={job.message}/>:<div className={`rounded-lg p-3 text-xs ${job.status==='failed'?'bg-rose-50 text-rose-700':'bg-slate-50 text-slate-600'}`}>{job.error?errorMessage(job.error,'Component maintenance failed without readable details'):job.message}</div>}</div>}
function Fact({label,value}:{label:string;value:string}){return <div className="rounded-lg bg-slate-50 p-3"><div className="text-slate-500">{label}</div><div className="mt-0.5 font-semibold">{value}</div></div>}
function formatDate(value?:string){return value?new Date(value).toLocaleString():'Not available'}
function formatBytes(value:number){if(!value)return '0 MB';return `${(value/1024/1024).toFixed(1)} MB`}
function icon(id:string){return id==='vulnerability_db'?<Database/>:id==='java_db'?<PackageCheck/>:id==='trivy_engine'?<ShieldCheck/>:id==='checks_bundle'?<CheckCircle2/>:<CloudDownload/>}
function refresh(qc:ReturnType<typeof useQueryClient>){void qc.invalidateQueries({queryKey:['components']});void qc.invalidateQueries({queryKey:['diagnostics']})}
