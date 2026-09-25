import {ChangeEvent,useRef,useState} from 'react'
import {FileJson,LoaderCircle,Upload} from 'lucide-react'
import {useQueryClient} from '@tanstack/react-query'
import {getCsrfToken} from '../api'
import {errorMessage} from '../errors'
import ProgressBar from './ProgressBar'

type ImportResult={imported_reports:number;skipped_duplicates:number;image_count:number;findings:number;packages:number}

function uploadReport(file:File,onProgress:(value:number)=>void){
  return new Promise<ImportResult>((resolve,reject)=>{
    const request=new XMLHttpRequest()
    request.open('POST','/api/reports/import')
    request.withCredentials=true
    request.setRequestHeader('Content-Type','application/json; charset=utf-8')
    const csrf=getCsrfToken();if(csrf)request.setRequestHeader('X-CSRF-Token',csrf)
    request.upload.onprogress=event=>{if(event.lengthComputable)onProgress(Math.round(event.loaded/event.total*100))}
    request.onload=()=>{let payload:unknown=request.responseText;try{payload=JSON.parse(request.responseText)}catch{/* readable fallback */}if(request.status>=200&&request.status<300)resolve(payload as ImportResult);else reject(new Error(errorMessage(payload,`Import failed (HTTP ${request.status})`)))}
    request.onerror=()=>reject(new Error('Network error while importing the report'))
    request.onabort=()=>reject(new Error('Report import was cancelled'))
    request.send(file)
  })
}

export default function ReportImportPanel(){
  const input=useRef<HTMLInputElement>(null),qc=useQueryClient()
  const [file,setFile]=useState<File|null>(null),[progress,setProgress]=useState(0),[busy,setBusy]=useState(false),[result,setResult]=useState<ImportResult|null>(null),[error,setError]=useState('')
  function choose(event:ChangeEvent<HTMLInputElement>){setFile(event.target.files?.[0]||null);setResult(null);setError('');setProgress(0)}
  async function run(){
    if(!file||busy)return
    setBusy(true);setResult(null);setError('');setProgress(0)
    try{
      const value=await uploadReport(file,setProgress)
      setResult(value);setProgress(100);setFile(null);if(input.current)input.current.value=''
      await Promise.all(['images','overview','jobs','packages','comparison','groups'].map(queryKey=>qc.invalidateQueries({queryKey:[queryKey]})))
    }catch(value){setError(errorMessage(value,'Unable to import the report'))}finally{setBusy(false)}
  }
  return <section className="card overflow-hidden">
    <div className="border-b bg-gradient-to-r from-violet-50 to-blue-50 p-5"><div className="flex items-start gap-3"><span className="rounded-xl bg-violet-600 p-2.5 text-white"><FileJson size={22}/></span><div><p className="text-xs font-bold uppercase tracking-[.14em] text-violet-700">Portable report history</p><h2 className="mt-1 text-lg font-semibold">Import LayerScope JSON reports</h2><p className="mt-1 max-w-4xl text-sm leading-6 text-slate-600">Restore normalized findings and package inventory without restoring the original image TAR. Imported entries remain searchable, comparable, exportable, and clearly marked as report-only.</p></div></div></div>
    <div className="p-5"><label className="block text-sm font-medium text-slate-700">JSON report export<input ref={input} className="input mt-1 file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-2 file:py-1 file:text-xs file:font-semibold" type="file" accept=".json,application/json" disabled={busy} onChange={choose}/></label>
      <div className="mt-3 flex flex-wrap items-center gap-3"><button className="btn-primary" disabled={!file||busy} onClick={run}>{busy?<LoaderCircle className="animate-spin" size={16}/>:<Upload size={16}/>} {busy?'Importing report':'Import report'}</button>{file&&<span className="text-sm text-slate-500">{file.name} · {formatBytes(file.size)}</span>}</div>
      {busy&&<ProgressBar className="mt-3" value={progress} indeterminate={progress>=100} label={progress>=100?'Validating and saving':'Uploading report'} detail="The original TAR and raw Trivy JSON are not imported"/>}
      {error&&<p className="mt-3 rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{error}</p>}
      {result&&!busy&&<p className="mt-3 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-700"><b>Import complete.</b> {result.imported_reports} report{result.imported_reports===1?'':'s'} added across {result.image_count} image entr{result.image_count===1?'y':'ies'}, with {result.findings.toLocaleString()} findings and {result.packages.toLocaleString()} packages. {result.skipped_duplicates>0&&`${result.skipped_duplicates} duplicate report${result.skipped_duplicates===1?' was':'s were'} skipped.`}</p>}
      <p className="mt-3 text-xs leading-5 text-slate-500">Only JSON files exported by LayerScope are accepted. HTML and PDF exports remain presentation formats. Importing the same JSON report again does not duplicate it.</p>
    </div>
  </section>
}

function formatBytes(value:number){return value<1024*1024?`${(value/1024).toFixed(1)} KB`:`${(value/1024/1024).toFixed(1)} MB`}
