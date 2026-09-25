import {useRef,useState} from 'react'
import {ImagePlus,X} from 'lucide-react'
import ExportButton from './ExportButton'

const FORMATS=['json','html','pdf','elastic','defectdojo']
const MAX_LOGO_BYTES=2*1024*1024
const LOGO_TYPES=new Set(['image/png','image/jpeg'])

export default function ReportExportControls({disabled,urlFor}:{disabled:boolean;urlFor:(format:string)=>string}){
  const [logo,setLogo]=useState<File|null>(null),[error,setError]=useState('')
  const input=useRef<HTMLInputElement>(null)
  function choose(file?:File){
    setError('')
    if(!file){setLogo(null);return}
    if(!LOGO_TYPES.has(file.type)){setLogo(null);setError('Choose a PNG or JPEG logo.');return}
    if(file.size>MAX_LOGO_BYTES){setLogo(null);setError('The logo must be 2 MiB or smaller.');return}
    setLogo(file)
  }
  function clear(){setLogo(null);setError('');if(input.current)input.current.value=''}
  return <div className="space-y-3">
    <div className="flex flex-wrap items-center gap-3 rounded-xl border bg-slate-50 p-3">
      <span className="rounded-lg bg-white p-2 text-blue-600 ring-1 ring-slate-200"><ImagePlus size={18}/></span>
      <div className="min-w-48 flex-1"><p className="text-sm font-semibold">Optional report logo</p><p className="text-xs text-slate-500">Used once in the next HTML or PDF export. PNG/JPEG, up to 2 MiB; never saved.</p></div>
      <label className="btn-secondary cursor-pointer"><ImagePlus size={15}/>{logo?'Replace logo':'Choose logo'}<input ref={input} className="sr-only" type="file" accept="image/png,image/jpeg" onChange={event=>choose(event.target.files?.[0])}/></label>
      {logo&&<button type="button" className="btn-secondary" onClick={clear} aria-label="Remove report logo"><X size={15}/>Remove</button>}
    </div>
    {logo&&<p className="text-xs font-medium text-emerald-700">Logo ready: {logo.name} ({(logo.size/1024).toFixed(1)} KiB). JSON, Elastic, and DefectDojo remain unbranded.</p>}
    {error&&<p className="text-xs font-medium text-rose-700">{error}</p>}
    <div className="flex flex-wrap items-start gap-2">{FORMATS.map(format=><ExportButton key={format} format={format} disabled={disabled} url={urlFor(format)} logo={logo}/>)}</div>
  </div>
}
