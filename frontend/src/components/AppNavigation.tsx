import {useEffect,useMemo,useRef,useState} from 'react'
import {NavLink,useLocation} from 'react-router-dom'
import {
  BookOpenCheck,Boxes,BriefcaseBusiness,ChevronDown,CircleHelp,KeyRound,LayoutDashboard,
  LogOut,Menu,ScanSearch,ServerCog,ShieldCheck,Stethoscope,Trash2,UsersRound,X,
  type LucideIcon,
} from 'lucide-react'
import {useAuth,type AuthUser} from '../auth'
import ThemeToggle from './ThemeToggle'
import UploadArchives from './UploadArchives'

type NavigationGroup='Workspace'|'Operations'|'Access and API'|'Administration'|'Support'
type NavigationItem={to:string;label:string;description:string;icon:LucideIcon;group:NavigationGroup;end?:boolean;admin?:boolean;primary?:boolean}
type OpenMenu='more'|'account'|'mobile'|null

const navigationItems:NavigationItem[]=[
  {to:'/',label:'Overview',description:'Images and risk summary',icon:LayoutDashboard,group:'Workspace',end:true,primary:true},
  {to:'/groups',label:'Groups',description:'Organize related images',icon:Boxes,group:'Workspace',primary:true},
  {to:'/jobs',label:'Jobs',description:'Uploads and scan activity',icon:BriefcaseBusiness,group:'Workspace',primary:true},
  {to:'/insights',label:'Insights',description:'Compare and export scans',icon:ScanSearch,group:'Workspace',primary:true},
  {to:'/components',label:'Components',description:'Scanner databases and updates',icon:ServerCog,group:'Operations'},
  {to:'/diagnostics',label:'Diagnostics',description:'Runtime and storage health',icon:Stethoscope,group:'Operations'},
  {to:'/api-tokens',label:'API tokens',description:'Personal automation credentials',icon:KeyRound,group:'Access and API'},
  {to:'/api-docs',label:'API Docs',description:'Authenticated API reference',icon:BookOpenCheck,group:'Access and API'},
  {to:'/users',label:'Users',description:'Accounts, roles, and access',icon:UsersRound,group:'Administration',admin:true},
  {to:'/data',label:'Data',description:'Reports, backups, and removal',icon:Trash2,group:'Administration',admin:true},
  {to:'/help',label:'Help',description:'Guides and common questions',icon:CircleHelp,group:'Support'},
]

const groups:NavigationGroup[]=['Workspace','Operations','Access and API','Administration','Support']

function activePath(pathname:string,item:NavigationItem){
  return item.end?pathname===item.to:pathname===item.to||pathname.startsWith(`${item.to}/`)
}

function linkClass({isActive}:{isActive:boolean}){
  return `nav-link ${isActive?'nav-link-active':''}`
}

function initials(user:AuthUser|null){
  const source=user?.display_name.trim()||user?.username||'User'
  return source.split(/\s+/).slice(0,2).map(value=>value[0]?.toUpperCase()).join('')||'U'
}

export default function AppNavigation(){
  const auth=useAuth(),location=useLocation()
  const [openMenu,setOpenMenu]=useState<OpenMenu>(null)
  const headerRef=useRef<HTMLElement>(null)
  const moreButtonRef=useRef<HTMLButtonElement>(null)
  const accountButtonRef=useRef<HTMLButtonElement>(null)
  const mobileButtonRef=useRef<HTMLButtonElement>(null)
  const visibleItems=useMemo(()=>navigationItems.filter(item=>!item.admin||auth.user?.role==='admin'),[auth.user?.role])
  const primaryItems=visibleItems.filter(item=>item.primary)
  const moreItems=visibleItems.filter(item=>!item.primary)
  const moreActive=moreItems.some(item=>activePath(location.pathname,item))

  useEffect(()=>setOpenMenu(null),[location.pathname])
  useEffect(()=>{
    if(!openMenu)return
    function dismissOutside(event:PointerEvent){
      if(!headerRef.current?.contains(event.target as Node))setOpenMenu(null)
    }
    function dismissWithKeyboard(event:KeyboardEvent){
      if(event.key!=='Escape')return
      event.preventDefault()
      const trigger=openMenu==='more'?moreButtonRef.current:openMenu==='account'?accountButtonRef.current:mobileButtonRef.current
      setOpenMenu(null)
      trigger?.focus()
    }
    document.addEventListener('pointerdown',dismissOutside)
    document.addEventListener('keydown',dismissWithKeyboard)
    return()=>{document.removeEventListener('pointerdown',dismissOutside);document.removeEventListener('keydown',dismissWithKeyboard)}
  },[openMenu])

  function toggle(menu:Exclude<OpenMenu,null>){setOpenMenu(current=>current===menu?null:menu)}

  return <header ref={headerRef} className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950 text-white shadow-lg shadow-slate-950/10">
    <div className="mx-auto flex min-h-16 max-w-[1600px] items-center justify-between gap-2 px-3 py-2 sm:gap-3 sm:px-5">
      <div className="flex min-w-0 items-center gap-5">
        <NavLink to="/" className="flex min-w-0 shrink-0 items-center gap-2.5 rounded-lg font-semibold" aria-label="LayerScope overview">
          <span className="rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 p-2 shadow-lg shadow-blue-950/30"><ShieldCheck size={20}/></span>
          <span className="hidden min-[380px]:block"><span className="block leading-4">LayerScope</span><span className="hidden text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500 sm:block">Image security</span></span>
        </NavLink>
        <nav className="hidden items-center gap-1 xl:flex" aria-label="Primary navigation">
          {primaryItems.map(item=>{const Icon=item.icon;return <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}><Icon size={16}/>{item.label}</NavLink>})}
          <div className="relative">
            <button ref={moreButtonRef} type="button" className={`nav-link ${moreActive?'nav-link-active':''}`} onClick={()=>toggle('more')} aria-expanded={openMenu==='more'} aria-controls="desktop-more-navigation">
              More <ChevronDown size={15} className={`transition-transform ${openMenu==='more'?'rotate-180':''}`}/>
            </button>
            {openMenu==='more'&&<DesktopMore items={moreItems}/>}
          </div>
        </nav>
      </div>

      <div className="flex min-w-0 items-center gap-1.5 sm:gap-2">
        <UploadArchives/>
        <div className="hidden sm:block"><ThemeToggle/></div>
        <div className="relative">
          <button ref={accountButtonRef} type="button" className="flex min-h-10 items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-2 text-sm transition hover:border-slate-600 hover:bg-slate-800" onClick={()=>toggle('account')} aria-expanded={openMenu==='account'} aria-controls="account-navigation" aria-label="Open account menu">
            <span className="flex size-7 items-center justify-center rounded-md bg-blue-500/20 text-xs font-bold text-blue-200">{initials(auth.user)}</span>
            <span className="hidden max-w-32 truncate text-left 2xl:block"><span className="block truncate font-medium">{auth.user?.display_name}</span><span className="block text-[10px] capitalize text-slate-400">{auth.user?.role}</span></span>
            <ChevronDown size={14} className={`hidden text-slate-400 transition-transform 2xl:block ${openMenu==='account'?'rotate-180':''}`}/>
          </button>
          {openMenu==='account'&&<AccountMenu user={auth.user} onLogout={()=>void auth.logout()}/>}
        </div>
        <button ref={mobileButtonRef} type="button" className="btn-secondary p-2 xl:hidden" onClick={()=>toggle('mobile')} aria-expanded={openMenu==='mobile'} aria-controls="mobile-navigation" aria-label={openMenu==='mobile'?'Close navigation':'Open navigation'}>{openMenu==='mobile'?<X size={18}/>:<Menu size={18}/>}</button>
      </div>
    </div>
    {openMenu==='mobile'&&<MobileNavigation items={visibleItems} user={auth.user}/>}
  </header>
}

function DesktopMore({items}:{items:NavigationItem[]}){
  return <div id="desktop-more-navigation" className="absolute left-0 top-full mt-3 w-[36rem] overflow-hidden rounded-2xl border border-slate-700 bg-slate-950 p-3 shadow-2xl shadow-slate-950/50">
    <div className="grid grid-cols-2 gap-2">
      {items.map(item=><NavigationCard key={item.to} item={item}/>)}
    </div>
  </div>
}

function NavigationCard({item}:{item:NavigationItem}){
  const Icon=item.icon
  return <NavLink to={item.to} end={item.end} className={({isActive})=>`group flex min-h-16 items-center gap-3 rounded-xl border px-3 py-2.5 transition ${isActive?'border-blue-400/30 bg-blue-500/15':'border-transparent hover:border-slate-700 hover:bg-white/5'}`}>
    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-slate-900 text-slate-400 transition group-hover:text-white"><Icon size={18}/></span>
    <span className="min-w-0"><span className="block text-sm font-semibold text-slate-100">{item.label}</span><span className="block truncate text-xs text-slate-400">{item.description}</span></span>
  </NavLink>
}

function AccountMenu({user,onLogout}:{user:AuthUser|null;onLogout:()=>void}){
  return <div id="account-navigation" className="absolute right-0 top-full mt-3 w-64 overflow-hidden rounded-2xl border border-slate-700 bg-slate-950 p-2 shadow-2xl shadow-slate-950/50">
    <div className="border-b border-slate-800 px-3 py-3">
      <p className="truncate text-sm font-semibold text-slate-100">{user?.display_name}</p>
      <p className="mt-0.5 truncate text-xs text-slate-400">@{user?.username}</p>
      <span className="mt-2 inline-flex rounded-full border border-slate-700 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-300">{user?.role}</span>
    </div>
    <div className="p-1 sm:hidden"><ThemeToggle/></div>
    <button type="button" className="flex min-h-10 w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm font-medium text-slate-300 transition hover:bg-white/5 hover:text-white" onClick={onLogout}><LogOut size={17}/>Sign out</button>
  </div>
}

function MobileNavigation({items,user}:{items:NavigationItem[];user:AuthUser|null}){
  return <div id="mobile-navigation" className="absolute inset-x-0 top-full border-t border-slate-800 bg-slate-950 shadow-2xl shadow-slate-950/50 xl:hidden">
    <div className="mx-auto max-h-[calc(100vh-4rem)] max-w-[1600px] overflow-y-auto px-4 py-4 sm:px-5">
      <div className="mb-4 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/60 px-3 py-2.5">
        <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-100">{user?.display_name}</p><p className="truncate text-xs text-slate-400">@{user?.username}</p></div>
        <span className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-300">{user?.role}</span>
      </div>
      <div className="grid gap-x-6 gap-y-5 sm:grid-cols-2 lg:grid-cols-3">
        {groups.map(group=>{const groupItems=items.filter(item=>item.group===group),groupId=`mobile-group-${group.replace(/ /g,'-')}`;if(!groupItems.length)return null;return <section key={group} aria-labelledby={groupId}>
          <h2 id={groupId} className="mb-2 px-2 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{group}</h2>
          <nav className="grid gap-1" aria-label={`${group} navigation`}>{groupItems.map(item=>{const Icon=item.icon;return <NavLink key={item.to} to={item.to} end={item.end} className={({isActive})=>`nav-link justify-start ${isActive?'nav-link-active':''}`}><Icon size={17}/><span>{item.label}</span><span className="ml-auto hidden truncate text-[11px] font-normal text-slate-500 min-[520px]:block">{item.description}</span></NavLink>})}</nav>
        </section>})}
      </div>
    </div>
  </div>
}
