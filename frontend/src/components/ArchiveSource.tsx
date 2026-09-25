import {FileJson,HardDriveUpload,FolderLock} from 'lucide-react'
import type {ArchiveSourceType} from '../types'

export default function ArchiveSource({source,compact=false}:{source:ArchiveSourceType;compact?:boolean}){
  const values=source==='upload'?{Icon:HardDriveUpload,label:'Dashboard upload',title:'Stored in the dashboard data volume'}:source==='report'?{Icon:FileJson,label:'Imported report',title:'Saved findings only; the original image archive is not included'}:{Icon:FolderLock,label:'Mounted archive',title:'Discovered from a configured read-only scan root'},Icon=values.Icon
  return <span className={`inline-flex items-center gap-1.5 text-slate-500 ${compact?'text-xs':'text-sm'}`} title={values.title}><Icon size={compact?13:15}/>{values.label}</span>
}
