import {lazy,Suspense,useEffect} from 'react'
import {NavLink,Route,Routes} from 'react-router-dom'
import {ScanSearch} from 'lucide-react'
import {useQueryClient} from '@tanstack/react-query'
import JobActivity from './components/JobActivity'
import AppNavigation from './components/AppNavigation'

const OverviewPage=lazy(()=>import('./pages/OverviewPage'))
const ImagePage=lazy(()=>import('./pages/ImagePage'))
const InsightsPage=lazy(()=>import('./pages/InsightsPage'))
const HelpPage=lazy(()=>import('./pages/HelpPage'))
const DiagnosticsPage=lazy(()=>import('./pages/DiagnosticsPage'))
const JobsPage=lazy(()=>import('./pages/JobsPage'))
const ComponentsPage=lazy(()=>import('./pages/ComponentsPage'))
const UsersPage=lazy(()=>import('./pages/UsersPage'))
const DataManagementPage=lazy(()=>import('./pages/DataManagementPage'))
const GroupsPage=lazy(()=>import('./pages/GroupsPage'))
const ApiTokensPage=lazy(()=>import('./pages/ApiTokensPage'))
const ApiDocsPage=lazy(()=>import('./pages/ApiDocsPage'))

export default function App(){
  const qc=useQueryClient()
  useEffect(()=>{
    const events=new EventSource('/api/events')
    let timer:number|undefined,terminal=false,component=false
    const flush=()=>{
      const keys=new Set(component?['components','diagnostics']:['images','image','jobs','upload-jobs','service-status','overview'])
      if(terminal)['findings','finding-filters','comparison','packages','groups','group'].forEach(key=>keys.add(key))
      void qc.invalidateQueries({predicate:query=>keys.has(String(query.queryKey[0]))})
      timer=undefined;terminal=false;component=false
    }
    events.onmessage=message=>{
      try{
        const event=JSON.parse(message.data) as {type?:string;status?:string;job?:{status?:string}}
        component=component||event.type==='component_job'
        const status=event.status||event.job?.status
        terminal=terminal||status==='completed'||status==='failed'||status==='cancelled'
      }catch{/* A malformed event is harmless; the fallback poll will reconcile state. */}
      if(timer===undefined)timer=window.setTimeout(flush,400)
    }
    return()=>{events.close();if(timer!==undefined)window.clearTimeout(timer)}
  },[qc])
  return <div className="min-h-screen">
    <a href="#main-content" className="skip-link">Skip to main content</a>
    <AppNavigation/>
    <main id="main-content" className="mx-auto max-w-[1600px] p-4 sm:p-5 lg:p-6"><JobActivity/><Suspense fallback={<div className="card p-10 text-center text-sm text-slate-500">Loading workspace...</div>}><Routes><Route path="/" element={<OverviewPage/>}/><Route path="/groups" element={<GroupsPage/>}/><Route path="/jobs" element={<JobsPage/>}/><Route path="/components" element={<ComponentsPage/>}/><Route path="/images/:id" element={<ImagePage/>}/><Route path="/insights" element={<InsightsPage/>}/><Route path="/diagnostics" element={<DiagnosticsPage/>}/><Route path="/api-tokens" element={<ApiTokensPage/>}/><Route path="/api-docs" element={<ApiDocsPage/>}/><Route path="/users" element={<UsersPage/>}/><Route path="/data" element={<DataManagementPage/>}/><Route path="/help" element={<HelpPage/>}/><Route path="*" element={<NotFound/>}/></Routes></Suspense></main>
  </div>
}

function NotFound(){return <section className="card mx-auto max-w-xl p-10 text-center"><span className="mx-auto mb-4 inline-flex rounded-2xl bg-blue-50 p-4 text-blue-700"><ScanSearch size={28}/></span><p className="text-xs font-bold uppercase tracking-widest text-blue-700">Page not found</p><h1 className="mt-2 text-2xl font-bold">This dashboard route does not exist</h1><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">The address may be outdated, or the page may have moved.</p><NavLink className="btn-primary mt-6" to="/">Return to overview</NavLink></section>}
