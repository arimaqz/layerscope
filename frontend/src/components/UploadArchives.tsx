import {ChangeEvent,useRef,useState} from 'react'
import {Upload,X} from 'lucide-react'
import {useQueryClient} from '@tanstack/react-query'
import {getCsrfToken} from '../api'
import {errorMessage} from '../errors'
import ProgressBar from './ProgressBar'

function uploadArchive(file:File,onProgress:(loaded:number)=>void,onProcessing:()=>void){
  return new Promise<void>((resolve,reject)=>{
    const body=new FormData()
    body.append('files',file)
    const request=new XMLHttpRequest()
    request.open('POST','/api/uploads')
    request.withCredentials=true
    request.setRequestHeader('X-CSRF-Token',getCsrfToken())
    request.upload.onprogress=value=>{if(value.lengthComputable)onProgress(Math.min(value.loaded,file.size))}
    request.upload.onload=onProcessing
    request.onload=()=>{
      if(request.status>=200&&request.status<300){resolve();return}
      let payload:unknown=request.responseText
      try{payload=JSON.parse(request.responseText)}catch{/* Plain-text proxy or network response. */}
      reject(new Error(errorMessage(payload,request.statusText||'Upload failed')))
    }
    request.onerror=()=>reject(new Error('Upload connection was interrupted. The incomplete archive was discarded; check backend health and storage, then try again.'))
    request.onabort=()=>reject(new Error('Upload was cancelled. The incomplete archive was discarded.'))
    request.ontimeout=()=>reject(new Error('Upload timed out before the server finished receiving it.'))
    request.send(body)
  })
}

export default function UploadArchives(){
  const input=useRef<HTMLInputElement>(null)
  const qc=useQueryClient()
  const [busy,setBusy]=useState(false)
  const [progress,setProgress]=useState(0)
  const [processing,setProcessing]=useState(false)
  const [position,setPosition]=useState({current:0,total:0})
  const [error,setError]=useState('')

  async function upload(event:ChangeEvent<HTMLInputElement>){
    const files=Array.from(event.target.files||[])
    if(!files.length)return
    const totalBytes=files.reduce((total,file)=>total+file.size,0)
    let completedBytes=0,uploaded=0
    const failures:string[]=[]
    setBusy(true);setError('');setProgress(0);setProcessing(false);setPosition({current:1,total:files.length})
    try{
      for(const [index,file] of files.entries()){
        setPosition({current:index+1,total:files.length});setProcessing(false)
        try{
          await uploadArchive(file,loaded=>setProgress(totalBytes?Math.round((completedBytes+loaded)/totalBytes*100):0),()=>setProcessing(true))
          uploaded+=1
        }catch(value){
          failures.push(errorMessage(value,`Archive ${index+1} failed`))
        }finally{
          completedBytes+=file.size
          setProgress(totalBytes?Math.round(completedBytes/totalBytes*100):100)
        }
      }
      await qc.invalidateQueries({queryKey:['upload-jobs']})
      if(uploaded)await Promise.all([qc.invalidateQueries({queryKey:['images']}),qc.invalidateQueries({queryKey:['overview']})])
      if(failures.length)setError(`${uploaded} of ${files.length} archives uploaded. ${failures.length} failed. ${failures[0]}`)
    }catch(value){
      setError(errorMessage(value,'The uploaded archives were saved, but the page could not refresh'))
    }finally{
      setBusy(false);setProcessing(false);setPosition({current:0,total:0});event.target.value=''
    }
  }

  return <div className="relative flex items-center">
    <input ref={input} className="hidden" type="file" accept=".tar,application/x-tar" multiple onChange={upload}/>
    <button className="btn bg-blue-600 text-white" disabled={busy} onClick={()=>input.current?.click()} title="Upload Docker or OCI image archives" aria-describedby={busy||error?'archive-upload-status':undefined}>
      <Upload size={16}/><span className="hidden sm:inline">{busy?'Uploading...':'Upload .tar files'}</span>
    </button>
    {(busy||error)&&<div id="archive-upload-status" className="card absolute right-0 top-full z-50 mt-3 w-72 p-3 text-slate-700 shadow-xl" role={error?'alert':'status'}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold">{busy?`${processing?'Processing':'Uploading'} archive ${position.current} of ${position.total}`:'Upload summary'}</p>
          {busy&&<ProgressBar
            className="mt-2 w-full"
            compact
            value={progress}
            indeterminate={processing}
            label={`${processing?'Processing':'Uploading'} ${position.current}/${position.total}`}
          />}
          {error&&<p className="mt-1 text-xs leading-5 text-rose-700">{error}</p>}
        </div>
        {!busy&&<button type="button" className="rounded-md p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700" onClick={()=>setError('')} aria-label="Dismiss upload summary"><X size={15}/></button>}
      </div>
    </div>}
  </div>
}
