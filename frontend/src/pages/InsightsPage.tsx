import {useMemo,useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {Download,GitCompare,PackageSearch,Search} from 'lucide-react'
import {api} from '../api'
import type {ImageArchive,PackageItem,ScanComparison} from '../types'
import SeverityBadge from '../components/SeverityBadge'
import ReportExportControls from '../components/ReportExportControls'
import {errorMessage} from '../errors'
import useDebouncedValue from '../hooks/useDebouncedValue'

export default function InsightsPage(){
  const images=useQuery({queryKey:['images'],queryFn:()=>api.get<ImageArchive[]>('/api/images')})
  const scanned=useMemo(()=>(images.data||[]).filter(image=>image.latest_scan?.status==='completed'),[images.data])
  const [imageId,setImageId]=useState<number|undefined>()
  const activeId=imageId||scanned[0]?.id
  const active=scanned.find(image=>image.id===activeId)
  const [search,setSearch]=useState('')
  const debouncedSearch=useDebouncedValue(search)
  const packages=useQuery({queryKey:['packages',active?.latest_scan?.id,debouncedSearch],queryFn:()=>api.get<PackageItem[]>(`/api/scans/${active!.latest_scan!.id}/packages?search=${encodeURIComponent(debouncedSearch)}`),enabled:!!active?.latest_scan?.id})
  const comparison=useQuery({queryKey:['comparison',activeId],queryFn:()=>api.get<ScanComparison>(`/api/images/${activeId}/compare`),enabled:!!activeId,retry:false})
  const [exportIds,setExportIds]=useState<number[]>([])
  const toggle=(scanId:number)=>setExportIds(ids=>ids.includes(scanId)?ids.filter(id=>id!==scanId):[...ids,scanId])
  const exportUrl=(format:string)=>`/api/exports?${exportIds.map(id=>`scan_ids=${id}`).join('&')}&format=${format}`

  return <div className="space-y-6">
    <div><p className="text-sm font-medium text-blue-600">Saved evidence and reporting</p><h1 className="text-3xl font-bold">Insights and reporting</h1><p className="mt-1 text-slate-500">Compare scans, inspect packages, and export one or many saved reports.</p></div>
    {(images.isError||packages.isError)&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(images.error||packages.error,'Unable to load insights')}</p>}
    {!scanned.length?<div className="card p-10 text-center text-slate-500">Complete at least one scan to unlock insights.</div>:<>
      <section className="card p-5">
        <div className="mb-4"><h2 className="flex items-center gap-2 font-semibold"><Download size={18}/>Report exports</h2><p className="mb-4 text-sm text-slate-500">Exports use stored results and never rerun Trivy.</p><ReportExportControls disabled={!exportIds.length} urlFor={exportUrl}/></div>
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{scanned.map(image=><label key={image.id} className={`flex cursor-pointer items-center gap-3 rounded-xl border p-3 transition hover:bg-slate-50 ${exportIds.includes(image.latest_scan!.id)?'bg-blue-50/70 ring-1 ring-blue-200':''}`}><input type="checkbox" aria-label={`Select ${image.name} for export`} checked={exportIds.includes(image.latest_scan!.id)} onChange={()=>toggle(image.latest_scan!.id)}/><span className="min-w-0"><span className="block truncate font-medium">{image.name}</span><span className="text-xs text-slate-500">Scan #{image.latest_scan!.id} · {image.latest_scan!.total.toLocaleString()} findings</span></span></label>)}</div>
      </section>
      <div className="card p-5"><label className="text-sm font-medium">Image for package and comparison insights</label><select className="input mt-2 max-w-xl" value={activeId} onChange={event=>setImageId(Number(event.target.value))}>{scanned.map(image=><option key={image.id} value={image.id}>{image.name}</option>)}</select></div>
      <section className="card p-5"><h2 className="mb-4 flex items-center gap-2 font-semibold"><GitCompare size={18}/>Changes since the previous scan</h2>{comparison.data?<><div className="mb-5 grid gap-3 sm:grid-cols-4"><Metric label="New" value={comparison.data.summary.new} tone="text-rose-600"/><Metric label="Resolved" value={comparison.data.summary.resolved} tone="text-emerald-600"/><Metric label="Unchanged" value={comparison.data.summary.unchanged}/><Metric label="Net change" value={comparison.data.summary.net}/></div><div className="grid gap-5 xl:grid-cols-2"><ChangeList title="New findings" items={comparison.data.new}/><ChangeList title="Resolved findings" items={comparison.data.resolved}/></div></>:<p className="text-sm text-slate-500">Run this image at least twice to compare completed scans.</p>}</section>
      <section className="card overflow-hidden"><div className="flex flex-wrap items-center justify-between gap-3 border-b p-5"><div><h2 className="flex items-center gap-2 font-semibold"><PackageSearch size={18}/>Package inventory</h2><p className="text-sm text-slate-500">Packages observed in scan #{active?.latest_scan?.id}.</p></div><div className="relative w-full sm:w-auto"><Search className="absolute left-3 top-2.5 text-slate-400" size={16}/><input className="input pl-9" placeholder="Search packages" value={search} onChange={event=>setSearch(event.target.value)}/></div></div><div className="max-h-[520px] overflow-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="sticky top-0 bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="p-3">Package</th><th className="p-3">Version</th><th className="p-3">Target</th><th className="p-3">Licenses</th><th className="p-3">Vulnerabilities</th></tr></thead><tbody>{(packages.data||[]).map((item,index)=><tr key={`${item.name}-${item.version}-${index}`} className="border-t"><td className="p-3 font-medium">{item.name}</td><td className="p-3">{item.version}</td><td className="p-3">{item.target}</td><td className="p-3">{item.licenses||'Not reported'}</td><td className="p-3">{item.vulnerabilities===undefined?<span className="text-slate-500">Included in findings</span>:<span className="inline-flex rounded-full bg-blue-100 px-2.5 py-1 text-xs font-semibold text-blue-700">{item.vulnerabilities.toLocaleString()}</span>}</td></tr>)}</tbody></table></div></section>
    </>}
  </div>
}

function Metric({label,value,tone=''}:{label:string;value:number;tone?:string}){return <div className="rounded-lg bg-slate-50 p-4"><div className={`text-2xl font-bold ${tone}`}>{value}</div><div className="text-sm text-slate-500">{label}</div></div>}
function ChangeList({title,items}:{title:string;items:ScanComparison['new']}){return <div><h3 className="mb-2 text-sm font-semibold">{title} ({items.length})</h3><div className="max-h-72 space-y-2 overflow-auto">{items.length?items.map((item,index)=><div key={`${item.vulnerability_id}-${item.package_name}-${index}`} className="flex items-center gap-3 rounded-lg bg-slate-50 p-3 text-sm"><SeverityBadge value={item.severity}/><div className="min-w-0"><div className="font-semibold">{item.vulnerability_id}</div><div className="truncate text-slate-500">{item.package_name} {item.installed_version}</div></div></div>):<p className="p-3 text-sm text-slate-500">None</p>}</div></div>}
