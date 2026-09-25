export const SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'] as const

export const SEVERITY_COLORS:Record<string,string>={
  CRITICAL:'#7f1d1d',
  HIGH:'#dc2626',
  MEDIUM:'#f97316',
  LOW:'#2563eb',
  UNKNOWN:'#64748b',
}

const styles:Record<string,{badge:string;active:string;inactive:string;dot:string}>={
  CRITICAL:{
    badge:'bg-red-200 text-red-950 ring-red-500 dark:bg-red-950/80 dark:text-red-100 dark:ring-red-800',
    active:'bg-red-950 text-white ring-red-950',
    inactive:'bg-red-100 text-red-950 ring-red-300 hover:bg-red-200 dark:bg-red-950/50 dark:text-red-100 dark:ring-red-900',
    dot:'bg-red-900 dark:bg-red-700',
  },
  HIGH:{
    badge:'bg-red-100 text-red-800 ring-red-300 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-700',
    active:'bg-red-600 text-white ring-red-600',
    inactive:'bg-red-50 text-red-800 ring-red-200 hover:bg-red-100 dark:bg-red-950/30 dark:text-red-200 dark:ring-red-800',
    dot:'bg-red-600 dark:bg-red-400',
  },
  MEDIUM:{
    badge:'bg-orange-100 text-orange-800 ring-orange-300 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-700',
    active:'bg-orange-600 text-white ring-orange-600',
    inactive:'bg-orange-50 text-orange-800 ring-orange-200 hover:bg-orange-100 dark:bg-orange-950/30 dark:text-orange-200 dark:ring-orange-800',
    dot:'bg-orange-600 dark:bg-orange-400',
  },
  LOW:{
    badge:'bg-blue-100 text-blue-800 ring-blue-300 dark:bg-blue-950/60 dark:text-blue-200 dark:ring-blue-700',
    active:'bg-blue-600 text-white ring-blue-600',
    inactive:'bg-blue-50 text-blue-800 ring-blue-200 hover:bg-blue-100 dark:bg-blue-950/30 dark:text-blue-200 dark:ring-blue-800',
    dot:'bg-blue-600 dark:bg-blue-400',
  },
  UNKNOWN:{
    badge:'bg-slate-100 text-slate-700 ring-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-600',
    active:'bg-slate-700 text-white ring-slate-700',
    inactive:'bg-slate-50 text-slate-700 ring-slate-200 hover:bg-slate-100 dark:bg-slate-900 dark:text-slate-200 dark:ring-slate-700',
    dot:'bg-slate-500 dark:bg-slate-400',
  },
}

export function severityStyle(value:string){return styles[value.toUpperCase()]||styles.UNKNOWN}
export function normalizeSeverity(value:string){const normalized=value.toUpperCase();return styles[normalized]?normalized:'UNKNOWN'}
