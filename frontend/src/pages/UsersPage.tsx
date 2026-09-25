import {FormEvent,useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {Ban,Check,Copy,KeyRound,Pencil,RefreshCw,RotateCcw,Save,ShieldCheck,Trash2,UserPlus,Users,X} from 'lucide-react'
import {api} from '../api'
import {useAuth} from '../auth'
import DestructiveConfirmDialog from '../components/DestructiveConfirmDialog'
import {errorMessage} from '../errors'
import type {ManagedUser,TwoFactorReissue,UserActivation,UserRole} from '../types'
import StatusBadge from '../components/StatusBadge'

const roles:UserRole[]=['viewer','operator','admin']
type IssuedCode={kind:'activation';value:UserActivation}|{kind:'2fa';value:TwoFactorReissue}
type UserIntent={kind:'delete'|'activation'|'2fa'|'disable';user:ManagedUser}

export default function UsersPage(){
  const auth=useAuth(),qc=useQueryClient(),[issued,setIssued]=useState<IssuedCode|null>(null),[intent,setIntent]=useState<UserIntent|null>(null)
  const users=useQuery({queryKey:['users'],queryFn:()=>api.get<ManagedUser[]>('/api/users'),enabled:auth.user?.role==='admin',retry:false})
  const refresh=()=>void qc.invalidateQueries({queryKey:['users']})
  const completed=()=>{setIntent(null);refresh()}
  const create=useMutation({mutationFn:(body:{username:string;display_name:string;role:UserRole})=>api.post<UserActivation>('/api/users',body),onSuccess:value=>{setIssued({kind:'activation',value});refresh()}})
  const update=useMutation({mutationFn:({id,body}:{id:number;body:Record<string,unknown>})=>api.post<ManagedUser>(`/api/users/${id}/update`,body),onSuccess:completed})
  const reissueActivation=useMutation({mutationFn:(id:number)=>api.post<UserActivation>(`/api/users/${id}/reissue-activation`),onSuccess:value=>{setIssued({kind:'activation',value});completed()}})
  const reissue2fa=useMutation({mutationFn:(id:number)=>api.post<TwoFactorReissue>(`/api/users/${id}/reissue-2fa`),onSuccess:value=>{setIssued({kind:'2fa',value});completed()}})
  const unlock=useMutation({mutationFn:(id:number)=>api.post<ManagedUser>(`/api/users/${id}/unlock`),onSuccess:refresh})
  const remove=useMutation({mutationFn:(id:number)=>api.delete(`/api/users/${id}`),onSuccess:completed})
  const busy=update.isPending||reissueActivation.isPending||reissue2fa.isPending||unlock.isPending||remove.isPending
  const error=create.error||update.error||reissueActivation.error||reissue2fa.error||unlock.error||remove.error||users.error

  if(auth.user?.role!=='admin')return <div className="card border-rose-200 p-8 text-center text-rose-700"><Ban className="mx-auto mb-3"/><h1 className="text-xl font-bold">Administrator access required</h1><p className="mt-1 text-sm">Only administrators can manage local users.</p></div>

  function confirmAction(){if(!intent)return;const id=intent.user.id;if(intent.kind==='delete')remove.mutate(id);else if(intent.kind==='activation')reissueActivation.mutate(id);else if(intent.kind==='2fa')reissue2fa.mutate(id);else update.mutate({id,body:{active:false}})}
  const dialogError=intent?errorMessage(update.error||reissueActivation.error||reissue2fa.error||remove.error,''):''

  return <div className="space-y-6">
    <div><p className="text-sm font-medium text-blue-600">Local identity administration</p><h1 className="flex items-center gap-3 text-3xl font-bold"><Users size={30}/>User management</h1><p className="mt-1 text-slate-500">Create, edit, disable, remove, unlock, and securely re-enroll local users.</p></div>
    {error&&!intent&&<p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{errorMessage(error,'Unable to update users')}</p>}
    {issued&&<OneTimeCode issued={issued} onClose={()=>setIssued(null)}/>}
    <section className="card p-5"><h2 className="mb-1 flex items-center gap-2 font-semibold"><UserPlus size={18}/>Create user</h2><p className="mb-4 text-sm text-slate-500">The user chooses their own password and authenticator after receiving the one-time activation code.</p><CreateForm busy={create.isPending} onSubmit={body=>create.mutate(body)}/></section>
    <section className="card overflow-hidden">
      <div className="flex items-center justify-between border-b p-5"><div><h2 className="font-semibold">Local users</h2><p className="text-sm text-slate-500">{users.data?.length||0} account(s). Usernames are permanent identity keys; display names, roles, and access can be edited.</p></div><button className="btn-secondary" disabled={users.isFetching} onClick={()=>users.refetch()}><RefreshCw className={users.isFetching?'animate-spin':''} size={15}/>Refresh</button></div>
      <div className="overflow-x-auto"><table className="w-full min-w-[1120px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="p-4">User</th><th className="p-4">Status</th><th className="p-4">Role</th><th className="p-4">2FA</th><th className="p-4">Created</th><th className="p-4 text-right">Actions</th></tr></thead><tbody>{(users.data||[]).map(user=><UserRow key={user.id} user={user} self={user.id===auth.user?.id} busy={busy} onRename={display_name=>update.mutate({id:user.id,body:{display_name}})} onRole={role=>update.mutate({id:user.id,body:{role}})} onToggle={()=>user.active?setIntent({kind:'disable',user}):update.mutate({id:user.id,body:{active:true}})} onReissueActivation={()=>setIntent({kind:'activation',user})} onReissue2fa={()=>setIntent({kind:'2fa',user})} onUnlock={()=>unlock.mutate(user.id)} onDelete={()=>setIntent({kind:'delete',user})}/>)}</tbody></table></div>
      {users.isLoading&&<p className="p-8 text-center text-slate-500">Loading users...</p>}
    </section>
    {intent&&<UserConfirmation intent={intent} busy={busy} error={dialogError} onCancel={()=>setIntent(null)} onConfirm={confirmAction}/>}
  </div>
}

function CreateForm({busy,onSubmit}:{busy:boolean;onSubmit:(body:{username:string;display_name:string;role:UserRole})=>void}){
  function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();const form=event.currentTarget,data=new FormData(form);onSubmit({display_name:String(data.get('displayName')),username:String(data.get('username')),role:String(data.get('role')) as UserRole});form.reset()}
  return <form className="grid gap-3 md:grid-cols-[1fr_1fr_180px_auto]" onSubmit={submit}><input className="input" name="displayName" placeholder="Display name" required maxLength={100}/><input className="input" name="username" placeholder="Username" required minLength={3} maxLength={64} pattern="[A-Za-z0-9._-]+"/><select className="input" name="role" defaultValue="viewer">{roles.map(role=><option key={role} value={role}>{role[0].toUpperCase()+role.slice(1)}</option>)}</select><button className="btn-primary" disabled={busy}><UserPlus size={16}/>{busy?'Creating...':'Create user'}</button></form>
}

type UserRowProps={user:ManagedUser;self:boolean;busy:boolean;onRename:(name:string)=>void;onRole:(role:UserRole)=>void;onToggle:()=>void;onReissueActivation:()=>void;onReissue2fa:()=>void;onUnlock:()=>void;onDelete:()=>void}

function UserRow({user,self,busy,onRename,onRole,onToggle,onReissueActivation,onReissue2fa,onUnlock,onDelete}:UserRowProps){
  const locked=Boolean(user.locked_until&&new Date(user.locked_until)>new Date()),[editing,setEditing]=useState(false),[name,setName]=useState(user.display_name)
  function saveName(){const trimmed=name.trim();if(!trimmed||trimmed===user.display_name){setName(user.display_name);setEditing(false);return}onRename(trimmed);setEditing(false)}
  const pending=user.status==='pending_activation'||user.status==='activation_expired'
  return <tr className="border-t align-top">
    <td className="p-4">{editing?<div className="flex min-w-64 items-center gap-2"><input className="input" value={name} maxLength={100} autoFocus onChange={event=>setName(event.target.value)} onKeyDown={event=>{if(event.key==='Enter')saveName();if(event.key==='Escape'){setName(user.display_name);setEditing(false)}}}/><button className="btn-secondary p-2" disabled={busy||!name.trim()} title="Save display name" onClick={saveName}><Save size={15}/></button><button className="btn-secondary p-2" title="Cancel" onClick={()=>{setName(user.display_name);setEditing(false)}}><X size={15}/></button></div>:<div className="flex items-center gap-2"><div><div className="font-semibold">{user.display_name}{self&&<span className="ml-2 text-xs text-blue-600">You</span>}</div><div className="text-xs text-slate-500">{user.username}</div></div><button className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" disabled={busy} title="Edit display name" onClick={()=>setEditing(true)}><Pencil size={14}/></button></div>}</td>
    <td className="p-4"><StatusBadge status={user.status}/>{locked&&<span className="ml-2 inline-flex rounded-full bg-rose-100 px-2.5 py-1 text-xs font-semibold text-rose-700 ring-1 ring-inset ring-rose-200">Locked</span>}</td>
    <td className="p-4"><select className="input min-w-32" value={user.role} disabled={busy||self} onChange={event=>onRole(event.target.value as UserRole)}>{roles.map(role=><option key={role} value={role}>{role}</option>)}</select></td>
    <td className="p-4">{user.totp_enabled?<span className="inline-flex items-center gap-1 text-emerald-700"><ShieldCheck size={15}/>Enabled</span>:<span className="text-slate-500">Not enrolled</span>}</td>
    <td className="p-4 text-slate-500">{new Date(user.created_at).toLocaleString()}</td>
    <td className="p-4"><div className="flex flex-wrap justify-end gap-2">{locked&&<button className="btn-secondary" disabled={busy} onClick={onUnlock}><KeyRound size={14}/>Unlock</button>}{pending?<button className="btn-secondary" disabled={busy||self} onClick={onReissueActivation}><RotateCcw size={14}/>Reissue activation</button>:user.active&&user.totp_enabled?<button className="btn-secondary" disabled={busy||self} onClick={onReissue2fa}><RotateCcw size={14}/>Reissue 2FA</button>:null}{user.status==='active'?<button className="btn-secondary text-rose-700" disabled={busy||self} onClick={onToggle}><Ban size={14}/>Disable</button>:user.status==='disabled'&&user.totp_enabled?<button className="btn-secondary text-emerald-700" disabled={busy} onClick={onToggle}><Check size={14}/>Enable</button>:null}<button className="btn-secondary text-rose-700" disabled={busy||self} onClick={onDelete}><Trash2 size={14}/>Remove</button></div></td>
  </tr>
}

function OneTimeCode({issued,onClose}:{issued:IssuedCode;onClose:()=>void}){
  const [copied,setCopied]=useState(false),twoFactor=issued.kind==='2fa',value=issued.value
  const code=twoFactor?(value as TwoFactorReissue).reissue_code:(value as UserActivation).activation_code
  const expires=twoFactor?(value as TwoFactorReissue).reissue_expires_at:(value as UserActivation).activation_expires_at
  async function copy(){await navigator.clipboard.writeText(`${value.user.username}\n${code}`);setCopied(true)}
  return <section className="card border-blue-200 bg-blue-50 p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div className="min-w-0 flex-1"><h2 className="font-semibold text-blue-800">One-time {twoFactor?'2FA re-enrollment':'activation'} code for {value.user.username}</h2><p className="mt-1 text-sm text-blue-700">Shown only now. Send it through a trusted channel. It expires {new Date(expires).toLocaleString()}.{twoFactor?' Their existing password is unchanged.':''}</p><code className="mt-3 block break-all rounded-lg bg-white p-3 text-sm font-semibold text-slate-900">{code}</code></div><div className="flex gap-2"><button className="btn-secondary" onClick={copy}>{copied?<Check size={15}/>:<Copy size={15}/>} {copied?'Copied':'Copy'}</button><button className="btn-primary" onClick={onClose}>I saved it</button></div></div></section>
}

function UserConfirmation({intent,busy,error,onCancel,onConfirm}:{intent:UserIntent;busy:boolean;error:string;onCancel:()=>void;onConfirm:()=>void}){
  const user=intent.user,item=`${user.display_name} · ${user.username} · ${user.role}`
  if(intent.kind==='delete')return <DestructiveConfirmDialog title={`Remove ${user.username}?`} description="This permanently removes the local identity. The username will become available for a future account." confirmation={user.username} items={[item]} summaries={[{label:'Account role',value:user.role},{label:'Current status',value:user.status.replace(/_/g,' ')}]} warning="The account, active sessions, and recovery codes will be removed. Historical audit entries are retained without a link to the deleted identity. This cannot be undone." busy={busy} error={error} confirmLabel="Remove user" onCancel={onCancel} onConfirm={onConfirm}/>
  if(intent.kind==='activation')return <DestructiveConfirmDialog title={`Reset activation for ${user.username}?`} description="This is a full credential reset intended for a user who cannot activate or recover the account." confirmation={`RESET ${user.username}`} items={[item]} summaries={[{label:'Password',value:'Invalidated'},{label:'Authenticator',value:'Must enroll again'}]} warning="The current password, authenticator enrollment, recovery codes, and sessions will be revoked. A new one-time activation code will be shown only after confirmation." eyebrow="Credential reset" tone="warning" action="reissue" busy={busy} error={error} confirmLabel="Reset and issue code" onCancel={onCancel} onConfirm={onConfirm}/>
  if(intent.kind==='2fa')return <DestructiveConfirmDialog title={`Reissue 2FA for ${user.username}?`} description="This creates a one-time re-enrollment code without changing the user's existing password." confirmation={`REISSUE 2FA ${user.username}`} items={[item]} summaries={[{label:'Password',value:'Unchanged'},{label:'New secret',value:'Visible only to the user'}]} warning="Active sessions and existing recovery codes will be revoked. The current authenticator remains usable until the user begins the verified re-enrollment flow with their password and the new one-time code." eyebrow="Two-factor verification" tone="security" action="verify" busy={busy} error={error} confirmLabel="Issue verification code" onCancel={onCancel} onConfirm={onConfirm}/>
  return <DestructiveConfirmDialog title={`Disable ${user.username}?`} description="The account remains stored but will not be able to sign in until an administrator enables it again." confirmation={`DISABLE ${user.username}`} items={[item]} summaries={[{label:'Account data',value:'Preserved'},{label:'Active sessions',value:'Revoked'}]} warning="Disabling access immediately revokes the user's active sessions. Scan history, groups, audit records, password, and authenticator enrollment remain stored." eyebrow="Access control" tone="warning" action="verify" busy={busy} error={error} confirmLabel="Disable account" onCancel={onCancel} onConfirm={onConfirm}/>
}
