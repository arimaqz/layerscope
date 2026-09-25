import {useEffect,useRef,useState} from 'react'
import {createPortal} from 'react-dom'
import {AlertTriangle,DatabaseZap,KeyRound,LoaderCircle,RotateCcw,ShieldAlert,Trash2,X} from 'lucide-react'

type Summary={label:string;value:string}
type Tone='danger'|'warning'|'security'
const tones={danger:{eyebrow:'text-rose-700',icon:'bg-rose-100 text-rose-700 ring-rose-200',button:'bg-rose-700 hover:bg-rose-800 shadow-rose-900/15'},warning:{eyebrow:'text-amber-700',icon:'bg-amber-100 text-amber-700 ring-amber-200',button:'bg-amber-600 hover:bg-amber-700 shadow-amber-900/15'},security:{eyebrow:'text-blue-700',icon:'bg-blue-100 text-blue-700 ring-blue-200',button:'bg-blue-700 hover:bg-blue-800 shadow-blue-900/15'}}

export default function DestructiveConfirmDialog({title,description,confirmation,items,summaries,warning,eyebrow='Permanent deletion',tone='danger',action='delete',confirmLabel='Delete permanently',busy=false,error='',onCancel,onConfirm}:{title:string;description:string;confirmation:string;items:string[];summaries:Summary[];warning?:string;eyebrow?:string;tone?:Tone;action?:'delete'|'reissue'|'verify';confirmLabel?:string;busy?:boolean;error?:string;onCancel:()=>void;onConfirm:()=>void}){
  const [typed,setTyped]=useState(''),input=useRef<HTMLInputElement>(null),matches=typed===confirmation,style=tones[tone]
  const ActionIcon=action==='delete'?Trash2:action==='reissue'?RotateCcw:KeyRound
  useEffect(()=>{input.current?.focus();const previous=document.body.style.overflow;document.body.style.overflow='hidden';const close=(event:KeyboardEvent)=>{if(event.key==='Escape'&&!busy)onCancel()};window.addEventListener('keydown',close);return()=>{document.body.style.overflow=previous;window.removeEventListener('keydown',close)}},[busy,onCancel])
  return createPortal(<div className="fixed inset-0 z-[100] overflow-y-auto bg-slate-950/70 backdrop-blur-sm" role="presentation"><div className="flex min-h-full items-center justify-center p-3 sm:p-6" onMouseDown={event=>{if(event.target===event.currentTarget&&!busy)onCancel()}}>
    <section role="dialog" aria-modal="true" aria-labelledby="destructive-dialog-title" aria-describedby="destructive-dialog-description" className="card relative w-full max-w-xl overflow-hidden border-rose-200 shadow-2xl">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-28 bg-gradient-to-b from-rose-500/10 to-transparent"/>
      <div className="relative p-6 sm:p-7">
        <button className="absolute right-4 top-4 rounded-lg p-2 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700 disabled:opacity-40" disabled={busy} aria-label="Close confirmation" onClick={onCancel}><X size={19}/></button>
        <div className="flex items-start gap-4 pr-10"><span className={`rounded-2xl p-3 ring-1 ${style.icon}`}><ShieldAlert size={24}/></span><div><p className={`text-xs font-bold uppercase tracking-[0.16em] ${style.eyebrow}`}>{eyebrow}</p><h2 id="destructive-dialog-title" className="mt-1 text-xl font-bold text-slate-950">{title}</h2><p id="destructive-dialog-description" className="mt-2 text-sm leading-6 text-slate-600">{description}</p></div></div>

        <div className="mt-5 grid grid-cols-2 gap-3">{summaries.map(summary=><div key={summary.label} className="rounded-xl border bg-slate-50 p-3"><p className="text-xs font-medium text-slate-500">{summary.label}</p><p className="mt-1 text-sm font-semibold text-slate-900">{summary.value}</p></div>)}</div>

        <div className="mt-4 max-h-32 overflow-auto rounded-xl border bg-white p-2">{items.slice(0,8).map(item=><div key={item} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-slate-700"><DatabaseZap className={`shrink-0 ${style.eyebrow}`} size={15}/><span className="truncate" title={item}>{item}</span></div>)}{items.length>8&&<p className="px-2 py-1.5 text-xs font-medium text-slate-500">And {items.length-8} more selected scans</p>}</div>

        <div className="mt-4 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-3 text-amber-800"><AlertTriangle className="mt-0.5 shrink-0" size={18}/><p className="text-sm leading-5">{warning||`This cannot be undone. Saved findings, package records, job history, and retained raw JSON for the selected scan${items.length===1?'':'s'} will be removed.`}</p></div>

        <label className="mt-5 block"><span className="text-sm font-medium text-slate-700">Type <code className="select-all font-bold text-rose-700">{confirmation}</code> to confirm</span><input ref={input} className="input mt-2 font-mono" value={typed} disabled={busy} autoComplete="off" spellCheck={false} aria-label={`Type ${confirmation} to confirm deletion`} onChange={event=>setTyped(event.target.value)} onKeyDown={event=>{if(event.key==='Enter'&&matches&&!busy)onConfirm()}} placeholder={confirmation}/></label>
        {error&&<p className="mt-3 rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{error}</p>}

        <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end"><button className="btn-secondary sm:min-w-28" disabled={busy} onClick={onCancel}>Cancel</button><button className={`btn text-white shadow-lg sm:min-w-44 ${style.button}`} disabled={!matches||busy} onClick={onConfirm}>{busy?<LoaderCircle className="animate-spin" size={17}/>:<ActionIcon size={17}/>} {busy?'Applying...':confirmLabel}</button></div>
      </div>
    </section>
  </div></div>,document.body)
}
