/* eslint-disable react-refresh/only-export-components */
import {createContext,useContext,useEffect,useState} from 'react'
import {api,setCsrfToken,getCsrfToken} from './api'

export type AuthUser={id:number;username:string;display_name:string;role:'viewer'|'operator'|'admin';totp_enabled:boolean}
export type SetupResult={requires_totp_setup:boolean;secret:string;otpauth_uri:string;csrf_token:string}
type ChallengeResult={requires_totp:boolean;csrf_token:string}
type VerifyResult={user:AuthUser;csrf_token:string;recovery_codes:string[];recovery_code_used:boolean}
type AuthContextValue={loading:boolean;configured:boolean;user:AuthUser|null;recoveryCodes:string[];setup:(displayName:string,username:string,password:string)=>Promise<SetupResult>;activate:(username:string,activationCode:string,password:string)=>Promise<SetupResult>;reenroll2fa:(username:string,reissueCode:string,password:string)=>Promise<SetupResult>;login:(username:string,password:string)=>Promise<void>;verify:(code:string)=>Promise<void>;logout:()=>Promise<void>;dismissRecoveryCodes:()=>void}

const AuthContext=createContext<AuthContextValue|null>(null)

export function AuthProvider({children}:{children:React.ReactNode}){
  const [loading,setLoading]=useState(true),[configured,setConfigured]=useState(false),[user,setUser]=useState<AuthUser|null>(null),[recoveryCodes,setRecoveryCodes]=useState<string[]>([])
  useEffect(()=>{const expired=()=>{setCsrfToken('');setUser(null)};window.addEventListener('trivy-auth-required',expired);void initialize();return()=>window.removeEventListener('trivy-auth-required',expired)},[])
  async function initialize(){try{const status=await api.get<{configured:boolean}>('/api/auth/status');setConfigured(status.configured);if(status.configured){try{const me=await api.get<{user:AuthUser;csrf_token:string}>('/api/auth/me');setCsrfToken(me.csrf_token);setUser(me.user)}catch{setCsrfToken('');setUser(null)}}}finally{setLoading(false)}}
  async function setup(displayName:string,username:string,password:string){const result=await api.post<SetupResult>('/api/auth/setup',{display_name:displayName,username,password});setCsrfToken(result.csrf_token);return result}
  async function activate(username:string,activationCode:string,password:string){const result=await api.post<SetupResult>('/api/auth/activate',{username,activation_code:activationCode,password});setCsrfToken(result.csrf_token);return result}
  async function reenroll2fa(username:string,reissueCode:string,password:string){const result=await api.post<SetupResult>('/api/auth/reenroll-2fa',{username,reissue_code:reissueCode,password});setCsrfToken(result.csrf_token);return result}
  async function login(username:string,password:string){const result=await api.post<ChallengeResult>('/api/auth/login',{username,password});setCsrfToken(result.csrf_token)}
  async function verify(code:string){const result=await api.post<VerifyResult>('/api/auth/totp/verify',{code,csrf_token:getCsrfToken()});setCsrfToken(result.csrf_token);setConfigured(true);setUser(result.user);setRecoveryCodes(result.recovery_codes)}
  async function logout(){try{await api.post('/api/auth/logout')}finally{setCsrfToken('');setUser(null);setRecoveryCodes([])}}
  return <AuthContext.Provider value={{loading,configured,user,recoveryCodes,setup,activate,reenroll2fa,login,verify,logout,dismissRecoveryCodes:()=>setRecoveryCodes([])}}>{children}</AuthContext.Provider>
}

export function useAuth(){const value=useContext(AuthContext);if(!value)throw new Error('AuthProvider is missing');return value}
