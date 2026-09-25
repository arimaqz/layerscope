import {useState} from 'react'
import {Download} from 'lucide-react'
import ProgressBar from './ProgressBar'
import {errorFromResponse,errorMessage} from '../errors'
import {getCsrfToken} from '../api'

export default function ExportButton({format,url,disabled,logo}:{format:string;url:string;disabled:boolean;logo?:File|null}){
  const [busy,setBusy]=useState(false),[progress,setProgress]=useState(0),[determinate,setDeterminate]=useState(false),[error,setError]=useState('')
  async function download(){
    if(disabled||busy)return
    setBusy(true);setProgress(0);setDeterminate(false);setError('')
    try{
      const branded=!!logo&&(format==='html'||format==='pdf')
      const endpoint=branded?url.replace('/api/exports?','/api/exports/branded?'):url
      const headers=new Headers()
      if(branded){headers.set('Content-Type',logo!.type);const csrf=getCsrfToken();if(csrf)headers.set('X-CSRF-Token',csrf)}
      const response=await fetch(endpoint,{method:branded?'POST':'GET',headers,body:branded?logo:undefined,credentials:'include'})
      if(!response.ok)throw await errorFromResponse(response,'Export failed')
      const total=Number(response.headers.get('content-length')||0)
      setDeterminate(total>0)
      const parts:ArrayBuffer[]=[]
      if(response.body){
        const reader=response.body.getReader();let received=0
        while(true){const {done,value}=await reader.read();if(done)break;if(value){parts.push(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength) as ArrayBuffer);received+=value.byteLength;if(total)setProgress(received/total*100)}}
      }else parts.push(await response.arrayBuffer())
      const blob=new Blob(parts,{type:response.headers.get('content-type')||'application/octet-stream'})
      const disposition=response.headers.get('content-disposition')||''
      const filename=disposition.match(/filename="?([^";]+)"?/i)?.[1]||`trivy-report.${format}`
      const objectUrl=URL.createObjectURL(blob),link=document.createElement('a')
      link.href=objectUrl;link.download=filename;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(objectUrl)
      setProgress(100)
    }catch(value){setError(errorMessage(value,'Export failed'))}
    finally{setBusy(false)}
  }
  return <div className="min-w-20"><button className="btn-secondary w-full" disabled={disabled||busy} onClick={download}><Download size={14}/>{busy?'Working':format==='defectdojo'?'DefectDojo':format==='elastic'?'Elastic':format.toUpperCase()}</button>{busy&&<ProgressBar className="mt-1" compact value={progress} indeterminate={!determinate} label="Export"/>}{error&&<span className="mt-1 block max-w-32 truncate text-[10px] text-rose-600" title={error}>{error}</span>}</div>
}
