import {Link} from 'react-router-dom'
import {useQuery} from '@tanstack/react-query'
import {Activity,ChevronRight,Upload} from 'lucide-react'
import {api} from '../api'
import type {ScanJob,UploadJob} from '../types'
import ProgressBar from './ProgressBar'
import StatusBadge from './StatusBadge'
import {stageLabel} from '../jobUtils'

export default function JobActivity(){
  const scans=useQuery({queryKey:['jobs','active'],queryFn:()=>api.get<ScanJob[]>('/api/jobs?status=queued&status=running&limit=50'),refetchInterval:query=>(query.state.data as ScanJob[]|undefined)?.length?15000:30000,refetchIntervalInBackground:false})
  const uploads=useQuery({queryKey:['upload-jobs','active'],queryFn:()=>api.get<UploadJob[]>('/api/upload-jobs?status=queued&status=running&limit=20'),refetchInterval:query=>(query.state.data as UploadJob[]|undefined)?.length?3000:30000,refetchIntervalInBackground:false})
  const activeScans=scans.data||[],activeUploads=uploads.data||[],total=activeScans.length+activeUploads.length
  if(!total)return null
  return <section className="card mb-5 border-blue-200 p-4" aria-label="Active jobs">
    <div className="mb-3 flex items-center justify-between gap-3"><div className="flex items-center gap-2 text-sm font-semibold"><Activity className="text-blue-600" size={18}/>{total} active job{total===1?'':'s'}</div><Link to="/jobs" className="flex items-center text-xs font-medium text-blue-700 hover:underline">Open job manager<ChevronRight size={15}/></Link></div>
    <div className="grid gap-3 lg:grid-cols-2">
      {activeUploads.slice(0,4).map(job=><div key={`upload-${job.id}`} className="rounded-xl border bg-slate-50 p-3"><div className="mb-2 flex items-center justify-between gap-3 text-xs"><span className="flex min-w-0 items-center gap-1.5 truncate font-semibold"><Upload size={14} className="shrink-0 text-cyan-700"/>{job.archive_name}</span><StatusBadge status={job.status}/></div><ProgressBar value={job.progress} label={stageLabel(job.stage)} detail={job.message} compact/></div>)}
      {activeScans.slice(0,Math.max(0,4-activeUploads.length)).map(job=><div key={`scan-${job.id}`} className="rounded-xl border bg-slate-50 p-3"><div className="mb-2 flex items-center justify-between gap-3 text-xs"><Link to={`/images/${job.image_id}`} className="truncate font-semibold hover:text-blue-700">{job.image_name}</Link><div className="flex shrink-0 items-center gap-2"><StatusBadge status={job.status}/>{job.queue_position&&<span className="text-slate-500">#{job.queue_position}</span>}</div></div><ProgressBar value={job.progress} label={stageLabel(job.stage)} detail={job.message} compact/></div>)}
    </div>
  </section>
}
