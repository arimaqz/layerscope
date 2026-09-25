import React from 'react'
import ReactDOM from 'react-dom/client'
import {QueryClient,QueryClientProvider} from '@tanstack/react-query'
import {BrowserRouter} from 'react-router-dom'
import App from './App'
import {AuthProvider} from './auth'
import AuthGate from './components/AuthGate'
import './index.css'

const savedTheme=localStorage.getItem('trivy-dashboard-theme')
const dark=savedTheme==='dark'||(!savedTheme&&matchMedia('(prefers-color-scheme: dark)').matches)
document.documentElement.classList.toggle('dark',dark)
document.documentElement.style.colorScheme=dark?'dark':'light'

const queryClient=new QueryClient({defaultOptions:{queries:{staleTime:10000,gcTime:600000,retry:2,refetchOnWindowFocus:true}}})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><QueryClientProvider client={queryClient}>
    <BrowserRouter><AuthProvider><AuthGate><App/></AuthGate></AuthProvider></BrowserRouter>
  </QueryClientProvider></React.StrictMode>
)
