import {errorFromResponse} from './errors'

const CSRF_KEY='trivy-dashboard-csrf'
export const getCsrfToken=()=>sessionStorage.getItem(CSRF_KEY)||''
export const setCsrfToken=(value:string)=>value?sessionStorage.setItem(CSRF_KEY,value):sessionStorage.removeItem(CSRF_KEY)

const json=async<T>(url:string,init?:RequestInit):Promise<T>=>{
  const headers=new Headers(init?.headers)
  const method=(init?.method||'GET').toUpperCase()
  if(['POST','PUT','PATCH','DELETE'].includes(method)&&getCsrfToken())headers.set('X-CSRF-Token',getCsrfToken())
  const response=await fetch(url,{...init,headers,credentials:'include'})
  if(response.status===401&&!url.startsWith('/api/auth/'))window.dispatchEvent(new Event('trivy-auth-required'))
  if(!response.ok)throw await errorFromResponse(response)
  return response.json()
}

export const api={
  get:<T>(url:string)=>json<T>(url),
  post:<T>(url:string,body?:unknown)=>json<T>(url,{method:'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)}),
  delete:<T>(url:string)=>json<T>(url,{method:'DELETE'}),
}
