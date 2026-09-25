type Props={value?:number;label?:string;detail?:string;indeterminate?:boolean;compact?:boolean;className?:string}

export default function ProgressBar({value=0,label,detail,indeterminate=false,compact=false,className=''}:Props){
  const percent=Math.max(0,Math.min(100,Math.round(value)))
  return <div className={className} role="progressbar" aria-label={label||'Progress'} aria-valuemin={0} aria-valuemax={100} aria-valuenow={indeterminate?undefined:percent}>
    {(label||detail)&&<div className={`mb-1 flex items-center justify-between gap-3 ${compact?'text-[11px]':'text-xs'}`}><span className="min-w-0 truncate text-slate-500">{label}</span><span className="shrink-0 font-semibold tabular-nums">{indeterminate?'Working':`${percent}%`}</span></div>}
    <div className={`${compact?'h-1.5':'h-2.5'} overflow-hidden rounded-full bg-slate-200`}>
      <div className={`h-full rounded-full bg-gradient-to-r from-blue-600 to-cyan-500 transition-[width] duration-500 ${indeterminate?'progress-indeterminate':''}`} style={indeterminate?undefined:{width:`${percent}%`}}/>
    </div>
    {detail&&!compact&&<p className="mt-1 truncate text-xs text-slate-500" title={detail}>{detail}</p>}
  </div>
}
