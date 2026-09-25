import {FormEvent,useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {Check,Clock3,Copy,KeyRound,LoaderCircle,RefreshCw,ShieldCheck,Trash2,X} from 'lucide-react'
import {api} from '../api'
import DestructiveConfirmDialog from '../components/DestructiveConfirmDialog'
import {errorMessage} from '../errors'
import type {ApiToken,IssuedApiToken} from '../types'

const date=(value?:string)=>value?new Date(value).toLocaleString():'Never'

export default function ApiTokensPage(){
  const qc=useQueryClient(),[issued,setIssued]=useState<IssuedApiToken|null>(null),[revoke,setRevoke]=useState<ApiToken|null>(null)
  const tokens=useQuery({queryKey:['api-tokens'],queryFn:()=>api.get<ApiToken[]>('/api/api-tokens')})
  const refresh=()=>void qc.invalidateQueries({queryKey:['api-tokens']})
  const create=useMutation({mutationFn:(body:{name:string;expires_in_days:number})=>api.post<IssuedApiToken>('/api/api-tokens',body),onSuccess:value=>{setIssued(value);refresh()}})
  const remove=useMutation({mutationFn:(id:number)=>api.delete<ApiToken>(`/api/api-tokens/${id}`),onSuccess:()=>{setRevoke(null);refresh()}})
  const error=create.error||remove.error||tokens.error
  return <div className="mx-auto max-w-6xl space-y-6">
    <div><p className="text-sm font-medium text-blue-600">Programmatic access</p><h1 className="flex items-center gap-3 text-3xl font-bold"><KeyRound size={30}/>API tokens</h1><p className="mt-1 text-slate-500">Call LayerScope APIs without sharing your password, browser cookie, or 2FA code.</p></div>
    {error&&!revoke&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(error,'Unable to manage API tokens')}</p>}
    {issued&&<OneTimeToken value={issued} onClose={()=>setIssued(null)}/>}
    <section className="card p-5"><h2 className="mb-1 flex items-center gap-2 font-semibold"><ShieldCheck size={18}/>Create personal token</h2><p className="mb-4 text-sm text-slate-500">The token inherits your current role and stops working if your account is disabled, your security enrollment is reset, or the token expires.</p><CreateForm busy={create.isPending} onSubmit={body=>create.mutate(body)}/></section>
    <section className="card overflow-hidden"><div className="flex items-center justify-between border-b p-5"><div><h2 className="font-semibold">Your tokens</h2><p className="text-sm text-slate-500">Only a short prefix is retained for identification. Secret values cannot be recovered.</p></div><button className="btn-secondary" disabled={tokens.isFetching} onClick={()=>tokens.refetch()}><RefreshCw className={tokens.isFetching?'animate-spin':''} size={15}/>Refresh</button></div>
      <div className="overflow-x-auto"><table className="w-full min-w-[860px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="p-4">Name</th><th className="p-4">Status</th><th className="p-4">Prefix</th><th className="p-4">Created</th><th className="p-4">Last used</th><th className="p-4">Expires</th><th className="p-4 text-right">Action</th></tr></thead><tbody>{(tokens.data||[]).map(token=><tr className="border-t" key={token.id}><td className="p-4 font-semibold">{token.name}</td><td className="p-4"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${token.status==='active'?'bg-emerald-50 text-emerald-700':token.status==='expired'?'bg-amber-50 text-amber-700':'bg-slate-100 text-slate-600'}`}>{token.status}</span></td><td className="p-4 font-mono text-xs">{token.token_prefix}…</td><td className="p-4 text-slate-500">{date(token.created_at)}</td><td className="p-4 text-slate-500">{date(token.last_used_at)}</td><td className="p-4 text-slate-500">{date(token.expires_at)}</td><td className="p-4 text-right"><button className="btn-secondary text-rose-700" disabled={token.status!=='active'||remove.isPending} onClick={()=>setRevoke(token)}><Trash2 size={15}/>Revoke</button></td></tr>)}</tbody></table></div>
      {tokens.isLoading&&<p className="p-8 text-center text-slate-500">Loading API tokens...</p>}{tokens.data?.length===0&&<p className="p-8 text-center text-sm text-slate-500">No API tokens have been created.</p>}
    </section>
    {revoke&&<DestructiveConfirmDialog
      title={`Revoke ${revoke.name}?`} description="Every API caller using this token will immediately lose access. This token cannot be restored."
      confirmation={revoke.name} items={[`${revoke.token_prefix}…`]} summaries={[{label:'Token',value:revoke.name},{label:'Expires',value:date(revoke.expires_at)}]}
      warning="Revocation is permanent. Create a new token if this integration needs access again." eyebrow="Credential revocation" tone="security" action="verify"
      confirmLabel="Revoke token" busy={remove.isPending} error={errorMessage(remove.error,'')} onCancel={()=>setRevoke(null)} onConfirm={()=>remove.mutate(revoke.id)}/>}
  </div>
}

function CreateForm({busy,onSubmit}:{busy:boolean;onSubmit:(body:{name:string;expires_in_days:number})=>void}){
  function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();const form=event.currentTarget,data=new FormData(form);onSubmit({name:String(data.get('name')),expires_in_days:Number(data.get('days'))});form.reset()}
  return <form className="grid gap-3 sm:grid-cols-[1fr_180px_auto]" onSubmit={submit}><input className="input" name="name" placeholder="Example: CI report reader" required minLength={1} maxLength={100}/><select className="input" name="days" defaultValue="90" aria-label="Token lifetime"><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option></select><button className="btn-primary" disabled={busy}>{busy?<LoaderCircle className="animate-spin" size={16}/>:<KeyRound size={16}/>}Create token</button></form>
}

function OneTimeToken({value,onClose}:{value:IssuedApiToken;onClose:()=>void}){
  const [copied,setCopied]=useState(false)
  async function copy(){await navigator.clipboard.writeText(value.token);setCopied(true);window.setTimeout(()=>setCopied(false),1800)}
  return <section className="card border-blue-200 bg-blue-50/50 p-5"><div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-widest text-blue-700">Shown once</p><h2 className="mt-1 font-semibold">Save {value.name} now</h2><p className="mt-1 text-sm text-slate-600">LayerScope stores only its hash. Closing this panel permanently hides the secret.</p></div><button className="rounded-lg p-2 text-slate-500 hover:bg-white" onClick={onClose} aria-label="Hide issued token"><X size={18}/></button></div><div className="mt-4 flex flex-col gap-2 sm:flex-row"><code className="min-w-0 flex-1 select-all overflow-x-auto rounded-lg border bg-white p-3 text-xs">{value.token}</code><button className="btn-secondary" onClick={copy}>{copied?<Check size={16}/>:<Copy size={16}/>} {copied?'Copied':'Copy'}</button></div><p className="mt-3 flex items-center gap-2 text-xs text-slate-500"><Clock3 size={14}/>Expires {date(value.expires_at)}</p></section>
}
