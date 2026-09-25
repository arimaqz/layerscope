import {useMemo,useRef,useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {Link,useParams} from 'react-router-dom'
import {ArrowLeft,ChevronDown,ChevronUp,Download,FilterX,History,Play,Search} from 'lucide-react'
import {ColumnDef,flexRender,getCoreRowModel,getSortedRowModel,SortingState,useReactTable} from '@tanstack/react-table'
import {useVirtualizer} from '@tanstack/react-virtual'
import {api} from '../api'
import {useAuth} from '../auth'
import type {Finding,FindingFilterOptions,ImageDetail} from '../types'
import SeverityBadge from '../components/SeverityBadge'
import VulnerabilityDrawer from '../components/VulnerabilityDrawer'
import ProgressBar from '../components/ProgressBar'
import {SEVERITIES,severityStyle} from '../severity'
import {errorMessage} from '../errors'
import StatusBadge from '../components/StatusBadge'
import ArchiveSource from '../components/ArchiveSource'
import useDebouncedValue from '../hooks/useDebouncedValue'

const severities=[...SEVERITIES]

export default function ImagePage(){
  const auth=useAuth(),canManage=auth.user?.role==='operator'||auth.user?.role==='admin',admin=auth.user?.role==='admin'
  const {id}=useParams(),imageId=Number(id),qc=useQueryClient()
  const [search,setSearch]=useState(''),[enabled,setEnabled]=useState<string[]>(severities),[packageName,setPackageName]=useState(''),[target,setTarget]=useState(''),[fixStatus,setFixStatus]=useState(''),[sorting,setSorting]=useState<SortingState>([]),[active,setActive]=useState<Finding|null>(null)
  const debouncedSearch=useDebouncedValue(search)
  const image=useQuery({queryKey:['image',imageId],queryFn:()=>api.get<ImageDetail>(`/api/images/${imageId}`)})
  const scanId=image.data?.latest_scan?.id
  const filters=useQuery({queryKey:['finding-filters',scanId],queryFn:()=>api.get<FindingFilterOptions>(`/api/scans/${scanId}/finding-filters`),enabled:!!scanId&&image.data?.latest_scan?.status==='completed'})
  const query=new URLSearchParams();enabled.forEach(severity=>query.append('severity',severity));if(debouncedSearch)query.set('search',debouncedSearch);if(packageName)query.set('package_name',packageName);if(target)query.set('target',target);if(fixStatus)query.set('fix_status',fixStatus)
  const findings=useQuery({queryKey:['findings',scanId,enabled,debouncedSearch,packageName,target,fixStatus],queryFn:()=>api.get<Finding[]>(`/api/scans/${scanId}/findings?${query}`),enabled:!!scanId&&image.data?.latest_scan?.status==='completed'})
  const rescan=useMutation({mutationFn:()=>api.post('/api/scans',{image_ids:[imageId]}),onSuccess:()=>{void qc.invalidateQueries({queryKey:['image',imageId]});void qc.invalidateQueries({queryKey:['jobs']})}})
  const columns=useMemo<ColumnDef<Finding>[]>(()=>[
    {accessorKey:'severity',header:'Severity',size:120,cell:cell=><SeverityBadge value={cell.getValue() as string}/>},
    {accessorKey:'vulnerability_id',header:'Vulnerability',size:170,cell:cell=><button className="font-semibold text-blue-700 hover:underline" onClick={()=>setActive(cell.row.original)}>{cell.getValue() as string}</button>},
    {accessorKey:'package_name',header:'Package',size:180},{accessorKey:'installed_version',header:'Installed',size:150},
    {accessorKey:'fixed_version',header:'Fixed version',size:160,cell:cell=><span>{cell.getValue() as string||'Not listed'}</span>},
    {accessorKey:'target',header:'Target',size:220},
    {accessorKey:'title',header:'Title',size:420,cell:cell=><button title={cell.getValue() as string} className="block w-full truncate text-left hover:text-blue-700" onClick={()=>setActive(cell.row.original)}>{cell.getValue() as string||'View details'}</button>},
  ],[])
  const table=useReactTable({data:findings.data||[],columns,state:{sorting},onSortingChange:setSorting,getCoreRowModel:getCoreRowModel(),getSortedRowModel:getSortedRowModel(),columnResizeMode:'onChange'}),rows=table.getRowModel().rows,parentRef=useRef<HTMLDivElement>(null),virtual=useVirtualizer({count:rows.length,getScrollElement:()=>parentRef.current,estimateSize:()=>49,overscan:10})
  const resetFilters=()=>{setSearch('');setEnabled(severities);setPackageName('');setTarget('');setFixStatus('')},filterCount=(enabled.length===severities.length?0:1)+(packageName?1:0)+(target?1:0)+(fixStatus?1:0)+(search?1:0)
  if(image.isLoading)return <div className="card p-10"><ProgressBar indeterminate label="Loading image details" detail="Retrieving the latest saved scan, history, and filter options"/></div>
  if(image.isError)return <div className="card border-rose-200 p-6 text-rose-700">{errorMessage(image.error,'Unable to load image details')}</div>
  const detail=image.data!,jobActive=detail.latest_scan&&(detail.latest_scan.status==='queued'||detail.latest_scan.status==='running'),reportOnly=detail.source==='report'
  return <div className="space-y-6">
    <div><Link to="/" className="mb-4 inline-flex items-center gap-2 text-sm text-slate-600 hover:text-slate-950"><ArrowLeft size={16}/>Back to overview</Link><div className="flex flex-wrap items-start justify-between gap-4"><div><h1 className="break-all text-3xl font-bold">{detail.name}</h1><div className="mt-2 flex flex-wrap items-center gap-3"><ArchiveSource source={detail.source}/><span className="text-sm text-slate-500">{reportOnly?'Original TAR not retained':`${(detail.size/1024/1024).toFixed(1)} MB`}</span></div></div><div className="flex flex-wrap gap-2">{canManage&&!reportOnly&&<a className="btn-secondary" href={`/api/images/${imageId}/archive`} download><Download size={16}/>Download TAR</a>}{admin&&!reportOnly&&scanId&&detail.latest_scan?.status==='completed'&&<a className="btn-secondary" href={`/api/scans/${scanId}/raw`}><Download size={16}/>Raw JSON</a>}{canManage&&!reportOnly&&<button className="btn-primary" disabled={rescan.isPending||!!jobActive} onClick={()=>rescan.mutate()}><Play size={16}/>{jobActive?'Scan active':'Rescan'}</button>}</div></div></div>
    {reportOnly&&<p className="rounded-xl border border-violet-200 bg-violet-50 p-4 text-sm text-violet-800">This entry was restored from a normalized JSON report. Findings, packages, comparisons, and exports are available; rescanning and archive/raw-evidence downloads require the original image TAR and raw Trivy result.</p>}
    <div className="grid gap-4 md:grid-cols-3"><Metric label="Latest status" value={<StatusBadge status={detail.latest_scan?.status}/>}/><Metric label="Total findings" value={(detail.latest_scan?.total??0).toLocaleString()}/><Metric label="Last completed" value={detail.latest_scan?.finished_at?new Date(detail.latest_scan.finished_at).toLocaleString():'Never'}/></div>
    {jobActive&&<section className="card border-blue-200 p-5"><ProgressBar value={detail.latest_scan!.progress} label={detail.latest_scan!.stage.replace(/_/g,' ')} detail={detail.latest_scan!.message}/></section>}
    {(rescan.isError||findings.isError||filters.isError)&&<p className="rounded-lg bg-rose-50 p-4 text-sm text-rose-700">{errorMessage(rescan.error||findings.error||filters.error,'Unable to load findings or start the rescan')}</p>}
    {detail.latest_scan?.error&&<p className="rounded-lg bg-rose-50 p-4 text-sm text-rose-700">{errorMessage(detail.latest_scan.error,'The latest scan failed')}</p>}
    <section className="card overflow-hidden">
      <div className="space-y-4 border-b p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold">Vulnerabilities ({rows.length.toLocaleString()})</h2><p className="text-xs text-slate-500">Filter the saved result without rescanning the image.</p></div><div className="relative w-full max-w-sm"><Search className="absolute left-3 top-2.5 text-slate-400" size={16}/><input className="input pl-9" placeholder="Search CVE, package, title, or text" value={search} onChange={event=>setSearch(event.target.value)}/></div></div>
        <div className="flex flex-wrap gap-2">{severities.map(severity=>{const style=severityStyle(severity),selected=enabled.includes(severity),count=detail.latest_scan?.counts[severity]||0;return <button key={severity} aria-pressed={selected} onClick={()=>setEnabled(value=>value.includes(severity)?value.filter(item=>item!==severity):[...value,severity])} className={`rounded-md px-2.5 py-1.5 text-xs font-semibold ring-1 transition ${selected?style.active:style.inactive}`}>{severity} <span className="ml-1 opacity-75">{count}</span></button>})}</div>
        <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-[1fr_1fr_220px_auto]"><select className="input" value={packageName} onChange={event=>setPackageName(event.target.value)}><option value="">All packages</option>{filters.data?.packages.map(value=><option key={value} value={value}>{value}</option>)}</select><select className="input" value={target} onChange={event=>setTarget(event.target.value)}><option value="">All targets</option>{filters.data?.targets.map(value=><option key={value} value={value}>{value}</option>)}</select><select className="input" value={fixStatus} onChange={event=>setFixStatus(event.target.value)}><option value="">Any fix status</option><option value="fixed">Fix available</option><option value="unfixed">No fix listed</option></select><button className="btn-secondary" disabled={!filterCount} onClick={resetFilters}><FilterX size={15}/>Reset {filterCount?`(${filterCount})`:''}</button></div>
      </div>
      <div className="overflow-x-auto"><div style={{width:table.getTotalSize(),minWidth:'100%'}}><div className="flex bg-slate-50 text-xs font-semibold uppercase text-slate-500">{table.getHeaderGroups()[0].headers.map(header=><div key={header.id} className="relative flex-none px-3 py-3" style={{width:header.getSize()}}><button className="inline-flex items-center gap-1" onClick={header.column.getToggleSortingHandler()}>{flexRender(header.column.columnDef.header,header.getContext())}{header.column.getIsSorted()==='asc'?<ChevronUp size={13}/>:header.column.getIsSorted()==='desc'?<ChevronDown size={13}/>:null}</button><div onMouseDown={header.getResizeHandler()} onTouchStart={header.getResizeHandler()} className="absolute right-0 top-0 h-full w-1 cursor-col-resize bg-transparent hover:bg-blue-400"/></div>)}</div><div ref={parentRef} className="relative h-[560px] overflow-auto" style={{contain:'strict'}}><div style={{height:virtual.getTotalSize(),position:'relative'}}>{virtual.getVirtualItems().map(item=>{const row=rows[item.index];return <div key={row.id} className="absolute left-0 top-0 flex border-b text-sm hover:bg-slate-50" style={{height:item.size,transform:`translateY(${item.start}px)`}}>{row.getVisibleCells().map(cell=><div key={cell.id} className="flex-none truncate px-3 py-3" style={{width:cell.column.getSize()}}>{flexRender(cell.column.columnDef.cell,cell.getContext())}</div>)}</div>})}</div></div></div></div>
      {!scanId&&<div className="p-12 text-center text-slate-500">Run a scan to populate findings.</div>}{scanId&&detail.latest_scan?.status==='completed'&&!findings.isLoading&&!rows.length&&<div className="p-12 text-center text-slate-500">No findings match the selected filters.</div>}
    </section>
    <section className="card p-5"><h2 className="mb-4 flex items-center gap-2 font-semibold"><History size={18}/>Scan history</h2><div className="space-y-2">{detail.history.map(history=><div key={history.id} className="rounded-xl border bg-slate-50 p-3 text-sm"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-semibold">{history.stage==='imported_report'?'Imported report':`Scan #${history.id}`}</span><StatusBadge status={history.status}/><span className="text-slate-500">{new Date(history.finished_at||history.queued_at).toLocaleString()}</span></div>{(history.status==='queued'||history.status==='running')&&<ProgressBar className="mt-2" compact value={history.progress} label={history.stage.replace(/_/g,' ')} detail={history.message}/>}</div>)}</div></section>
    <VulnerabilityDrawer finding={active} onClose={()=>setActive(null)}/>
  </div>
}

function Metric({label,value}:{label:string;value:React.ReactNode}){return <div className="card p-5"><div className="text-sm text-slate-500">{label}</div><div className="mt-2 text-xl font-bold">{value}</div></div>}
