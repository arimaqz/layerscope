import {CircleCheck,Clock3,LoaderCircle,MinusCircle,OctagonAlert,XCircle} from 'lucide-react'

const styles:Record<string,string>={
  queued:'bg-slate-100 text-slate-700 ring-slate-200',
  running:'bg-blue-100 text-blue-700 ring-blue-200',
  completed:'bg-emerald-100 text-emerald-700 ring-emerald-200',
  active:'bg-emerald-100 text-emerald-700 ring-emerald-200',
  failed:'bg-rose-100 text-rose-700 ring-rose-200',
  cancelled:'bg-amber-100 text-amber-700 ring-amber-200',
  disabled:'bg-slate-100 text-slate-600 ring-slate-200',
  'not scanned':'bg-slate-100 text-slate-600 ring-slate-200',
  pending_activation:'bg-blue-100 text-blue-700 ring-blue-200',
  activation_expired:'bg-amber-100 text-amber-700 ring-amber-200',
}

export default function StatusBadge({status,className=''}:{status?:string|null;className?:string}){
  const normalized=(status||'not scanned').toLowerCase(),label=normalized.replace(/_/g,' ')
  const Icon=normalized==='running'?LoaderCircle:normalized==='completed'||normalized==='active'?CircleCheck:normalized==='failed'?OctagonAlert:normalized==='cancelled'||normalized==='activation_expired'?XCircle:normalized==='queued'||normalized==='pending_activation'?Clock3:MinusCircle
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-semibold capitalize ring-1 ring-inset ${styles[normalized]||styles['not scanned']} ${className}`}><Icon className={normalized==='running'?'animate-spin':''} size={12}/>{label}</span>
}
