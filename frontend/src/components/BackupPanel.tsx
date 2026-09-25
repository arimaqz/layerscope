import {useEffect,useRef,useState} from 'react'
import {createPortal} from 'react-dom'
import {AlertTriangle,ArchiveRestore,DatabaseBackup,Download,LoaderCircle,LockKeyhole,ShieldCheck,Upload,X} from 'lucide-react'
import {api,getCsrfToken,setCsrfToken} from '../api'
import {errorMessage} from '../errors'
import ProgressBar from './ProgressBar'

type BackupSummary={users:number;images:number;scans:number;findings:number;groups:number;raw_results:number;uploaded_archives:number;payload_bytes:number}
type BackupTicket={token:string;filename:string;expires_at:string;size:number;summary:BackupSummary}
type BackupPreview={token:string;created_at:string;app_version:string;summary:BackupSummary;excluded:string[]}

export default function BackupPanel(){
  const [exportPassword,setExportPassword]=useState(''),[exportConfirm,setExportConfirm]=useState(''),[exporting,setExporting]=useState(false),[exportError,setExportError]=useState(''),[exported,setExported]=useState<BackupTicket|null>(null)
  const [importPassword,setImportPassword]=useState(''),[file,setFile]=useState<File|null>(null),[importing,setImporting]=useState(false),[progress,setProgress]=useState(0),[processing,setProcessing]=useState(false),[importError,setImportError]=useState(''),[preview,setPreview]=useState<BackupPreview|null>(null)
  const input=useRef<HTMLInputElement>(null)
  const exportValid=exportPassword.length>=12&&exportPassword===exportConfirm

  async function exportBackup(){
    if(!exportValid||exporting)return
    setExporting(true);setExportError('');setExported(null)
    try{
      const ticket=await api.post<BackupTicket>('/api/backups/export',{password:exportPassword})
      setExported(ticket);setExportPassword('');setExportConfirm('')
      const link=document.createElement('a');link.href=`/api/backups/download/${ticket.token}`;link.download=ticket.filename;document.body.appendChild(link);link.click();link.remove()
    }catch(value){setExportError(errorMessage(value,'Unable to create the backup'))}
    finally{setExporting(false)}
  }

  async function importBackup(){
    if(!file||importPassword.length<12||importing)return
    setImporting(true);setProgress(0);setProcessing(false);setImportError('')
    try{
      const result=await uploadBackup(file,importPassword,value=>{setProgress(value);if(value>=100)setProcessing(true)})
      setPreview(result);setImportPassword('');setFile(null);if(input.current)input.current.value=''
    }catch(value){setImportError(errorMessage(value,'Unable to validate the backup'))}
    finally{setImporting(false);setProcessing(false)}
  }

  return <>
    <section className="card overflow-hidden">
      <div className="border-b bg-gradient-to-r from-blue-50 to-cyan-50 p-5"><div className="flex items-start gap-3"><span className="rounded-xl bg-blue-600 p-2.5 text-white"><DatabaseBackup size={22}/></span><div><p className="text-xs font-bold uppercase tracking-[.14em] text-blue-700">Portable encrypted backup</p><h2 className="mt-1 text-lg font-semibold">Export or restore application data</h2><p className="mt-1 max-w-4xl text-sm leading-6 text-slate-600">Backups contain SQLite data, accounts and 2FA encryption material, raw Trivy evidence, and dashboard-uploaded TAR archives. They are protected with your backup password using AES-256-GCM.</p></div></div></div>
      <div className="grid gap-0 lg:grid-cols-2">
        <div className="border-b p-5 lg:border-b-0 lg:border-r">
          <div className="mb-4 flex items-center gap-3"><span className="rounded-lg bg-emerald-50 p-2 text-emerald-700"><Download size={19}/></span><div><h3 className="font-semibold">Export backup</h3><p className="text-xs text-slate-500">The password is never stored by the app.</p></div></div>
          <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm font-medium text-slate-700">Backup password<input className="input mt-1" type="password" autoComplete="new-password" minLength={12} value={exportPassword} disabled={exporting} onChange={event=>setExportPassword(event.target.value)} placeholder="At least 12 characters"/></label><label className="text-sm font-medium text-slate-700">Confirm password<input className="input mt-1" type="password" autoComplete="new-password" value={exportConfirm} disabled={exporting} onChange={event=>setExportConfirm(event.target.value)} placeholder="Repeat password"/></label></div>
          {exportConfirm&&exportPassword!==exportConfirm&&<p className="mt-2 text-xs text-rose-700">Passwords do not match.</p>}
          <button className="btn-primary mt-4" disabled={!exportValid||exporting} onClick={exportBackup}>{exporting?<LoaderCircle className="animate-spin" size={16}/>:<LockKeyhole size={16}/>} {exporting?'Creating encrypted backup':'Export encrypted backup'}</button>
          {exporting&&<ProgressBar className="mt-3" indeterminate label="Preparing backup" detail="Waiting for active file operations, snapshotting SQLite, and encrypting stored evidence"/>}
          {exportError&&<p className="mt-3 rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{exportError}</p>}
          {exported&&!exporting&&<div className="mt-3 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-700"><b>Backup ready.</b> {exported.filename} ({formatBytes(exported.size)}) was sent to your browser.</div>}
        </div>
        <div className="p-5">
          <div className="mb-4 flex items-center gap-3"><span className="rounded-lg bg-amber-50 p-2 text-amber-700"><ArchiveRestore size={19}/></span><div><h3 className="font-semibold">Import and restore</h3><p className="text-xs text-slate-500">Validation never changes live data.</p></div></div>
          <label className="block text-sm font-medium text-slate-700">Encrypted backup file<input ref={input} className="input mt-1 file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-2 file:py-1 file:text-xs file:font-semibold" type="file" accept=".tdbackup,application/octet-stream" disabled={importing} onChange={event=>setFile(event.target.files?.[0]||null)}/></label>
          <label className="mt-3 block text-sm font-medium text-slate-700">Backup password<input className="input mt-1" type="password" autoComplete="off" minLength={12} value={importPassword} disabled={importing} onChange={event=>setImportPassword(event.target.value)} placeholder="Password used during export"/></label>
          <button className="btn-secondary mt-4" disabled={!file||importPassword.length<12||importing} onClick={importBackup}>{importing?<LoaderCircle className="animate-spin" size={16}/>:<Upload size={16}/>} {processing?'Validating integrity':importing?'Uploading backup':'Validate backup'}</button>
          {importing&&<ProgressBar className="mt-3" value={progress} indeterminate={processing} label={processing?'Decrypting and validating':'Uploading backup'} detail={processing?'Checking encryption, manifest, file hashes, SQLite integrity, and authentication key':file?.name}/>}
          {importError&&<p className="mt-3 rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{importError}</p>}
        </div>
      </div>
      <div className="flex gap-3 border-t bg-slate-50 p-4 text-xs leading-5 text-slate-600"><ShieldCheck className="mt-0.5 shrink-0 text-blue-600" size={17}/><p>Trivy vulnerability and Java database caches are excluded because they are large, versioned downloads and can be restored from <b>Components</b>. Keep the backup password separately; a lost password cannot be recovered.</p></div>
    </section>
    {preview&&<RestoreDialog preview={preview} onCancel={async()=>{try{await api.delete(`/api/backups/${preview.token}`);setPreview(null)}catch(value){setImportError(errorMessage(value,'Unable to discard the staged backup'));setPreview(null)}}}/>}
  </>
}

function RestoreDialog({preview,onCancel}:{preview:BackupPreview;onCancel:()=>void}){
  const [typed,setTyped]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[restarting,setRestarting]=useState(false),confirmation='RESTORE BACKUP',matches=typed===confirmation
  useEffect(()=>{const previous=document.body.style.overflow;document.body.style.overflow='hidden';return()=>{document.body.style.overflow=previous}},[])
  async function restore(){
    if(!matches||busy)return
    setBusy(true);setError('')
    try{await api.post(`/api/backups/${preview.token}/restore`,{confirmation});setRestarting(true);setCsrfToken('');void waitForRestart()}
    catch(value){setError(errorMessage(value,'Unable to restore the backup'));setBusy(false)}
  }
  if(restarting)return createPortal(<RestartOverlay/>,document.body)
  const summary=preview.summary
  return createPortal(<div className="fixed inset-0 z-[100] overflow-y-auto bg-slate-950/75 backdrop-blur-sm"><div className="flex min-h-full items-center justify-center p-3 sm:p-6" onMouseDown={event=>{if(event.target===event.currentTarget&&!busy)onCancel()}}><section role="dialog" aria-modal="true" className="card relative w-full max-w-2xl overflow-hidden border-amber-200 shadow-2xl">
    <button className="absolute right-4 top-4 z-10 rounded-lg p-2 text-slate-400 hover:bg-slate-100 disabled:opacity-40" disabled={busy} onClick={onCancel} aria-label="Close restore confirmation"><X size={19}/></button>
    <div className="bg-gradient-to-r from-amber-50 to-orange-50 p-6 pr-14"><div className="flex items-start gap-4"><span className="rounded-2xl bg-amber-100 p-3 text-amber-700 ring-1 ring-amber-200"><ArchiveRestore size={25}/></span><div><p className="text-xs font-bold uppercase tracking-[.16em] text-amber-700">Validated restore point</p><h2 className="mt-1 text-xl font-bold text-slate-950">Replace current application data?</h2><p className="mt-2 text-sm leading-6 text-slate-600">The backup decrypted successfully and passed manifest, hash, SQLite, and authentication-key checks. Restoring it will restart the app and sign everyone out.</p></div></div></div>
    <div className="p-6"><div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><Fact label="Created" value={new Date(preview.created_at).toLocaleString()}/><Fact label="App version" value={preview.app_version}/><Fact label="Images / scans" value={`${summary.images} / ${summary.scans}`}/><Fact label="Findings" value={summary.findings.toLocaleString()}/><Fact label="Users" value={String(summary.users)}/><Fact label="Groups" value={String(summary.groups)}/><Fact label="Raw results" value={String(summary.raw_results)}/><Fact label="Uploaded TARs" value={String(summary.uploaded_archives)}/></div>
      <div className="mt-4 flex gap-3 rounded-xl border border-rose-200 bg-rose-50 p-3 text-rose-800"><AlertTriangle className="mt-0.5 shrink-0" size={19}/><p className="text-sm leading-5"><b>Current data will be replaced.</b> Current accounts, scans, groups, raw results, and uploaded TAR files are replaced by this restore point. Mounted host archives are not stored in the backup and require the same Compose mounts.</p></div>
      <label className="mt-5 block"><span className="text-sm font-medium text-slate-700">Type <code className="select-all font-bold text-rose-700">{confirmation}</code> to continue</span><input className="input mt-2 font-mono" autoFocus value={typed} disabled={busy} autoComplete="off" spellCheck={false} onChange={event=>setTyped(event.target.value)} onKeyDown={event=>{if(event.key==='Enter'&&matches&&!busy)void restore()}} placeholder={confirmation}/></label>
      {error&&<p className="mt-3 rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{error}</p>}
      <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end"><button className="btn-secondary sm:min-w-28" disabled={busy} onClick={onCancel}>Cancel</button><button className="btn bg-rose-700 text-white hover:bg-rose-800 sm:min-w-48" disabled={!matches||busy} onClick={restore}>{busy?<LoaderCircle className="animate-spin" size={17}/>:<ArchiveRestore size={17}/>} {busy?'Scheduling restore':'Restore and restart'}</button></div>
    </div>
  </section></div></div>,document.body)
}

function RestartOverlay(){return <div className="fixed inset-0 z-[110] flex items-center justify-center bg-slate-950/90 p-6 text-white"><div className="w-full max-w-md text-center"><span className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-blue-600 shadow-2xl shadow-blue-500/30"><LoaderCircle className="animate-spin" size={30}/></span><h2 className="mt-6 text-2xl font-bold">Restoring application data</h2><p className="mt-2 text-sm leading-6 text-slate-300">The backend is atomically applying the validated backup and restarting. You will return to sign-in when it is healthy.</p><ProgressBar className="mt-6" indeterminate label="Restarting services"/></div></div>}

function Fact({label,value}:{label:string;value:string}){return <div className="rounded-xl border bg-slate-50 p-3"><p className="text-xs text-slate-500">{label}</p><p className="mt-1 truncate text-sm font-semibold" title={value}>{value}</p></div>}

function uploadBackup(file:File,password:string,onProgress:(value:number)=>void){return new Promise<BackupPreview>((resolve,reject)=>{const request=new XMLHttpRequest(),form=new FormData();form.append('file',file);form.append('password',password);request.open('POST','/api/backups/import');request.withCredentials=true;const csrf=getCsrfToken();if(csrf)request.setRequestHeader('X-CSRF-Token',csrf);request.upload.onprogress=event=>{if(event.lengthComputable)onProgress(Math.round(event.loaded/event.total*100))};request.onload=()=>{let payload:unknown=request.responseText;try{payload=JSON.parse(request.responseText)}catch{/* readable fallback */}if(request.status>=200&&request.status<300)resolve(payload as BackupPreview);else reject(new Error(errorMessage(payload,`Import failed (HTTP ${request.status})`)))};request.onerror=()=>reject(new Error('Network error while uploading the backup'));request.onabort=()=>reject(new Error('Backup upload was cancelled'));request.send(form)})}

async function waitForRestart(){let offline=false;for(let attempt=0;attempt<120;attempt++){await new Promise(resolve=>setTimeout(resolve,1000));try{const response=await fetch('/api/health',{cache:'no-store'});if(response.ok&&(offline||attempt>8)){window.location.assign('/');return}}catch{offline=true}}window.location.assign('/')}
function formatBytes(value:number){if(!Number.isFinite(value)||value<=0)return '0 B';const units=['B','KB','MB','GB','TB'],index=Math.min(Math.floor(Math.log(value)/Math.log(1024)),units.length-1);return `${(value/1024**index).toFixed(index?1:0)} ${units[index]}`}
