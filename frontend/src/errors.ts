const UNREADABLE=new Set(['[object Object]','[object Array]','object Object'])
const SENSITIVE_KEY=/(password|passwd|secret|token|authorization|cookie|csrf|recovery|otp|code)/i
const PRIMARY_KEYS=['detail','message','error','errors','reason','title'] as const

export class ApiError extends Error{
  readonly status:number
  constructor(message:string,status:number){super(message);this.name='ApiError';this.status=status}
}

export function errorMessage(value:unknown,fallback='Something went wrong'):string{
  const message=formatValue(value,new WeakSet<object>(),0)
  return message&&!UNREADABLE.has(message)?message:fallback
}

export async function errorFromResponse(response:Response,fallback='Request failed'):Promise<ApiError>{
  let payload:unknown
  const contentType=response.headers.get('content-type')||''
  try{payload=contentType.includes('json')?await response.json():await response.text()}catch{payload=undefined}
  const statusLabel=response.statusText?`${response.status} ${response.statusText}`:`HTTP ${response.status}`
  return new ApiError(errorMessage(payload,`${fallback} (${statusLabel})`),response.status)
}

function formatValue(value:unknown,seen:WeakSet<object>,depth:number):string{
  if(value==null)return ''
  if(value instanceof Error)return clean(value.message)||formatValue((value as Error&{cause?:unknown}).cause,seen,depth+1)
  if(typeof value==='string'){
    const text=clean(value)
    if(!text)return ''
    if((text.startsWith('{')||text.startsWith('['))&&text.length<20_000){try{return formatValue(JSON.parse(text),seen,depth)}catch{return text}}
    return text
  }
  if(typeof value==='number'||typeof value==='boolean')return String(value)
  if(typeof value!=='object'||depth>5)return ''
  if(seen.has(value))return ''
  seen.add(value)
  if(Array.isArray(value))return unique(value.map(item=>formatValue(item,seen,depth+1)).filter(Boolean)).join('; ')

  const record=value as Record<string,unknown>
  const validation=formatValidation(record,seen,depth)
  if(validation)return validation
  for(const key of PRIMARY_KEYS){if(key in record){const message=formatValue(record[key],seen,depth+1);if(message)return message}}
  const safeEntries=Object.entries(record)
    .filter(([key])=>!SENSITIVE_KEY.test(key)&&!['input','ctx','url','traceback','stack'].includes(key.toLowerCase()))
    .slice(0,8)
    .map(([key,item])=>{const message=formatValue(item,seen,depth+1);return message?`${humanize(key)}: ${message}`:''})
    .filter(Boolean)
  return unique(safeEntries).join('; ')
}

function formatValidation(record:Record<string,unknown>,seen:WeakSet<object>,depth:number){
  if(typeof record.msg!=='string')return ''
  const location=Array.isArray(record.loc)?record.loc
    .filter(item=>!['body','query','path','header'].includes(String(item).toLowerCase()))
    .map(item=>humanize(String(item))).join(' → '):''
  const message=formatValue(record.msg,seen,depth+1)
  return location?`${location}: ${message}`:message
}

function clean(value:string){const text=value.replace(/\s+/g,' ').trim();return UNREADABLE.has(text)?'':text.slice(0,4000)}
function humanize(value:string){return value.replace(/[_-]+/g,' ').replace(/\b\w/g,letter=>letter.toUpperCase())}
function unique(values:string[]){return [...new Set(values)]}
