import {useEffect,useState} from 'react'
import {Moon,Sun} from 'lucide-react'

type Theme='light'|'dark'

function initialTheme():Theme{
  const saved=localStorage.getItem('trivy-dashboard-theme')
  if(saved==='light'||saved==='dark')return saved
  return matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'
}

export default function ThemeToggle(){
  const [theme,setTheme]=useState<Theme>(initialTheme)
  useEffect(()=>{
    document.documentElement.classList.toggle('dark',theme==='dark')
    document.documentElement.style.colorScheme=theme
    localStorage.setItem('trivy-dashboard-theme',theme)
  },[theme])
  return <button className="btn-secondary p-2" onClick={()=>setTheme(theme==='dark'?'light':'dark')} aria-label={`Switch to ${theme==='dark'?'light':'dark'} theme`} title={`Switch to ${theme==='dark'?'light':'dark'} theme`}>
    {theme==='dark'?<Sun size={17}/>:<Moon size={17}/>}<span className="hidden md:inline">{theme==='dark'?'Light':'Dark'}</span>
  </button>
}
