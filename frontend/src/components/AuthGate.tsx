import {FormEvent,useState} from 'react'
import {QRCodeSVG} from 'qrcode.react'
import {Check,Copy,KeyRound,LockKeyhole,ShieldCheck} from 'lucide-react'
import {useAuth} from '../auth'
import {errorMessage} from '../errors'

type Enrollment={secret:string;uri:string}

export default function AuthGate({children}:{children:React.ReactNode}){
  const auth=useAuth(),[enrollment,setEnrollment]=useState<Enrollment|null>(null),[mfaStep,setMfaStep]=useState(false),[activationStep,setActivationStep]=useState(false),[reenrollStep,setReenrollStep]=useState(false)
  if(auth.loading)return <Shell><p className="text-center text-slate-500">Loading secure session...</p></Shell>
  if(auth.recoveryCodes.length)return <RecoveryCodes/>
  if(auth.user)return <>{children}</>
  if(!auth.configured&&!enrollment)return <Setup onEnrollment={(secret,uri)=>setEnrollment({secret,uri})}/>
  if(enrollment)return <Enroll enrollment={enrollment}/>
  if(activationStep)return <Activate onEnrollment={(secret,uri)=>setEnrollment({secret,uri})} onBack={()=>setActivationStep(false)}/>
  if(reenrollStep)return <Reenroll onEnrollment={(secret,uri)=>setEnrollment({secret,uri})} onBack={()=>setReenrollStep(false)}/>
  return <Login mfaStep={mfaStep} setMfaStep={setMfaStep} onActivate={()=>setActivationStep(true)} onReenroll={()=>setReenrollStep(true)}/>
}

function Setup({onEnrollment}:{onEnrollment:(secret:string,uri:string)=>void}){
  const auth=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();setError('');const data=new FormData(event.currentTarget),password=String(data.get('password')),confirm=String(data.get('confirm'));if(password!==confirm){setError('Passwords do not match');return}setBusy(true);try{const result=await auth.setup(String(data.get('displayName')),String(data.get('username')),password);onEnrollment(result.secret,result.otpauth_uri)}catch(value){setError(message(value))}finally{setBusy(false)}}
  return <Shell><Heading title="Create the local administrator" text="Credentials and 2FA stay on this machine. No external identity service is used."/><form className="space-y-4" onSubmit={submit}><Field name="displayName" label="Display name" autoComplete="name"/><Field name="username" label="Username" autoComplete="username"/><Field name="password" label="Password" type="password" autoComplete="new-password" hint="Use at least 12 characters. Passphrases work well."/><Field name="confirm" label="Confirm password" type="password" autoComplete="new-password"/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><LockKeyhole size={17}/>{busy?'Creating account...':'Continue to 2FA'}</button></form></Shell>
}

function Enroll({enrollment}:{enrollment:Enrollment}){
  const auth=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();setBusy(true);setError('');try{await auth.verify(String(new FormData(event.currentTarget).get('code')))}catch(value){setError(message(value))}finally{setBusy(false)}}
  return <Shell wide><Heading title="Connect your authenticator" text="Scan this QR code with Aegis, FreeOTP, or another RFC 6238 compatible authenticator."/><div className="mx-auto my-6 w-fit rounded-2xl bg-white p-4"><QRCodeSVG value={enrollment.uri} size={190} level="M"/></div><div className="rounded-lg bg-slate-50 p-3 text-center"><p className="mb-1 text-xs text-slate-500">Manual setup key</p><code className="break-all text-sm font-semibold tracking-wider">{enrollment.secret}</code></div><form className="mt-5 space-y-4" onSubmit={submit}><Field name="code" label="6-digit code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6}/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><ShieldCheck size={17}/>{busy?'Verifying...':'Verify and finish setup'}</button></form></Shell>
}

function Activate({onEnrollment,onBack}:{onEnrollment:(secret:string,uri:string)=>void;onBack:()=>void}){
  const auth=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();setError('');const data=new FormData(event.currentTarget),password=String(data.get('password')),confirm=String(data.get('confirm'));if(password!==confirm){setError('Passwords do not match');return}setBusy(true);try{const result=await auth.activate(String(data.get('username')),String(data.get('activationCode')),password);onEnrollment(result.secret,result.otpauth_uri)}catch(value){setError(message(value))}finally{setBusy(false)}}
  return <Shell><Heading title="Activate your account" text="Use the one-time code provided by an administrator, choose your private password, then enroll your authenticator."/><form className="space-y-4" onSubmit={submit}><Field name="username" label="Username" autoComplete="username" autoFocus/><Field name="activationCode" label="Activation code" autoComplete="one-time-code"/><Field name="password" label="New password" type="password" autoComplete="new-password" hint="Use at least 12 characters. The administrator never receives this password."/><Field name="confirm" label="Confirm password" type="password" autoComplete="new-password"/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><ShieldCheck size={17}/>{busy?'Activating...':'Continue to 2FA'}</button><button type="button" className="btn-secondary w-full" onClick={onBack}>Back to sign in</button></form></Shell>
}

function Reenroll({onEnrollment,onBack}:{onEnrollment:(secret:string,uri:string)=>void;onBack:()=>void}){
  const auth=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();setError('');const data=new FormData(event.currentTarget);setBusy(true);try{const result=await auth.reenroll2fa(String(data.get('username')),String(data.get('reissueCode')),String(data.get('password')));onEnrollment(result.secret,result.otpauth_uri)}catch(value){setError(message(value))}finally{setBusy(false)}}
  return <Shell><Heading title="Re-enroll two-factor authentication" text="Use the one-time 2FA code issued by an administrator. Your existing password stays unchanged, and only you see the new authenticator secret."/><form className="space-y-4" onSubmit={submit}><Field name="username" label="Username" autoComplete="username" autoFocus/><Field name="password" label="Current password" type="password" autoComplete="current-password"/><Field name="reissueCode" label="2FA reissue code" autoComplete="one-time-code"/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><ShieldCheck size={17}/>{busy?'Checking...':'Continue to new 2FA setup'}</button><button type="button" className="btn-secondary w-full" onClick={onBack}>Back to sign in</button></form></Shell>
}

function Login({mfaStep,setMfaStep,onActivate,onReenroll}:{mfaStep:boolean;setMfaStep:(value:boolean)=>void;onActivate:()=>void;onReenroll:()=>void}){
  const auth=useAuth(),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submitPassword(event:FormEvent<HTMLFormElement>){event.preventDefault();setBusy(true);setError('');const data=new FormData(event.currentTarget);try{await auth.login(String(data.get('username')),String(data.get('password')));setMfaStep(true)}catch(value){setError(message(value))}finally{setBusy(false)}}
  async function submitCode(event:FormEvent<HTMLFormElement>){event.preventDefault();setBusy(true);setError('');try{await auth.verify(String(new FormData(event.currentTarget).get('code')))}catch(value){setError(message(value))}finally{setBusy(false)}}
  return <Shell><Heading title={mfaStep?'Two-factor authentication':'Sign in'} text={mfaStep?'Enter the current code from your authenticator, or use one recovery code.':'Use your local dashboard account.'}/>{mfaStep?<form className="space-y-4" onSubmit={submitCode}><Field name="code" label="Authenticator or recovery code" autoComplete="one-time-code" autoFocus/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><KeyRound size={17}/>{busy?'Verifying...':'Verify'}</button><button type="button" className="btn-secondary w-full" onClick={()=>{setMfaStep(false);setError('')}}>Back</button></form>:<form className="space-y-4" onSubmit={submitPassword}><Field name="username" label="Username" autoComplete="username" autoFocus/><Field name="password" label="Password" type="password" autoComplete="current-password"/>{error&&<ErrorText>{error}</ErrorText>}<button className="btn-primary w-full" disabled={busy}><LockKeyhole size={17}/>{busy?'Checking...':'Continue'}</button><button type="button" className="btn-secondary w-full" onClick={onActivate}>Activate an admin-created account</button><button type="button" className="btn-secondary w-full" onClick={onReenroll}>Re-enroll 2FA with an admin code</button></form>}</Shell>
}

function RecoveryCodes(){
  const auth=useAuth(),[copied,setCopied]=useState(false)
  async function copy(){await navigator.clipboard.writeText(auth.recoveryCodes.join('\n'));setCopied(true)}
  return <Shell wide><Heading title="Save your recovery codes" text="Each code works once if your authenticator is unavailable. Store them offline; they will not be shown again."/><div className="my-5 grid grid-cols-2 gap-2 rounded-xl bg-slate-50 p-4 font-mono text-sm">{auth.recoveryCodes.map(code=><code key={code}>{code}</code>)}</div><div className="flex gap-2"><button className="btn-secondary flex-1" onClick={copy}>{copied?<Check size={17}/>:<Copy size={17}/>} {copied?'Copied':'Copy codes'}</button><button className="btn-primary flex-1" onClick={auth.dismissRecoveryCodes}>I saved them</button></div></Shell>
}

function Shell({children,wide=false}:{children:React.ReactNode;wide?:boolean}){return <main className="flex min-h-screen items-center justify-center p-5"><section className={`card w-full p-7 ${wide?'max-w-xl':'max-w-md'}`}><div className="mb-6 flex items-center gap-3"><span className="rounded-xl bg-blue-600 p-3 text-white"><ShieldCheck size={24}/></span><div><p className="font-semibold">LayerScope</p><p className="text-xs text-slate-500">Local-first security</p></div></div>{children}</section></main>}
function Heading({title,text}:{title:string;text:string}){return <div className="mb-6"><h1 className="text-2xl font-bold">{title}</h1><p className="mt-2 text-sm leading-6 text-slate-500">{text}</p></div>}
function Field(props:React.InputHTMLAttributes<HTMLInputElement>&{label:string;hint?:string}){const {label,hint,...input}=props;return <label className="block"><span className="mb-1.5 block text-sm font-medium">{label}</span><input className="input" required {...input}/>{hint&&<span className="mt-1 block text-xs text-slate-500">{hint}</span>}</label>}
function ErrorText({children}:{children:React.ReactNode}){return <p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700">{children}</p>}
function message(value:unknown){return errorMessage(value,'Authentication failed')}
