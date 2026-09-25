import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  Archive, ChevronDown, CircleHelp, Download, Gauge, LifeBuoy, Play, Search, ServerCog,
  ShieldCheck, SquareTerminal, Upload, UserRoundCog, X, type LucideIcon,
} from 'lucide-react'
import { useAuth, type AuthUser } from '../auth'

type Access = 'Everyone' | 'Operator or administrator' | 'Administrator'
type HelpItem = {
  id: string
  title: string
  answer: ReactNode
  searchText: string
  access?: Access
  link?: { to: string; label: string }
}
type HelpCategory = {
  id: string
  title: string
  description: string
  icon: LucideIcon
  items: HelpItem[]
}

const categories: HelpCategory[] = [
  {
    id: 'getting-started', title: 'Getting started', icon: Play,
    description: 'Learn the workspace, add archives, and complete a first scan.',
    items: [
      {
        id: 'navigate', title: 'Where do I find each workspace?', searchText: 'navigation menu more account overview groups jobs insights operations access api administration support',
        answer: <>Overview, Groups, Jobs, and Insights are the main workspaces. On wide screens, open <b>More</b> for Components, Diagnostics, API tools, administration, and Help. On smaller screens, the main menu groups every destination by purpose. The account menu shows your signed-in role and sign-out action.</>,
      },
      {
        id: 'supported-files', title: 'What files can I add?', searchText: 'supported file format docker oci archive tar',
        answer: <>LayerScope accepts Docker or OCI image archives saved as <code>.tar</code>. It does not scan a registry name, Dockerfile, ZIP file, or running container directly.</>,
      },
      {
        id: 'add-archives', title: 'Should I mount a folder or upload archives?', searchText: 'image dir windows folder path mount read only upload persistent volume firefox multiple large files',
        answer: <><b>Mount a folder</b> for large or frequently changing collections: set <code>IMAGE_DIR</code> in <code>.env</code> and rebuild Compose. Mounted archives remain read-only. Use <b>Upload .tar files</b> for convenient browser imports; uploads are stored in the persistent data volume and multiple files are sent sequentially to keep browser memory bounded. A running container cannot mount a new host folder from a browser field.</>,
        link: { to: '/', label: 'Open Overview' },
      },
      {
        id: 'first-scan', title: 'How do I run my first scan?', searchText: 'discover select scan selected progress first scan', access: 'Operator or administrator',
        answer: <>On Overview, use <b>Discover</b> if a mounted TAR is not listed, select one or more archives, then choose <b>Scan selected</b>. LayerScope queues persistent jobs and shows stage-based progress. Two scans run concurrently by default.</>,
        link: { to: '/', label: 'Open Overview' },
      },
    ],
  },
  {
    id: 'scanning', title: 'Scanning and jobs', icon: Gauge,
    description: 'Understand scan coverage, queues, groups, and progress.',
    items: [
      {
        id: 'job-status', title: 'Where can I follow uploads and scans?', searchText: 'job upload receiving validation queued running completed failed cancelled retry cancel progress',
        answer: <>Jobs shows upload history and scan activity together, including receiving, validation, queued, running, completed, failed, and cancelled states. Active scans can be cancelled; failed or cancelled scans can be retried.</>,
        link: { to: '/jobs', label: 'Open Jobs' },
      },
      {
        id: 'progress', title: 'Are scan percentages exact?', searchText: 'percentage estimate stage progress sse polling',
        answer: <>No. Trivy does not expose a stable item-by-item percentage for archive scans. The progress bar is a stage-based estimate; the stage text explains what Trivy and LayerScope are doing.</>,
      },
      {
        id: 'groups', title: 'How do image groups work?', searchText: 'groups membership add replace delete group scan related images', access: 'Operator or administrator',
        answer: <>From Overview, <b>Add to group</b> adds only missing memberships—it does not replace existing members. Groups summarizes membership coverage and latest completed-scan risk. An image in several groups contributes once to each group. Use Groups to edit membership, scan a group, or export its latest completed results as JSON, HTML, PDF, Elastic, or DefectDojo. Group exports list members that were excluded because they have no completed scan. Deleting a group removes only the group and its memberships; images, archives, scans, findings, and raw JSON remain unchanged.</>,
        link: { to: '/groups', label: 'Open Groups' },
      },
      {
        id: 'offline-scans', title: 'Can normal scans run offline?', searchText: 'offline internet network database vex telemetry java jar coverage vulnerability db',
        answer: <>Yes for normal OS-package scanning. The backend image seeds a vulnerability database on first start, and normal scans disable automatic database, Java DB, VEX, and telemetry downloads. Images containing JAR files need the optional Java index installed in advance for full Java coverage; otherwise Jobs records a coverage warning.</>,
        link: { to: '/components', label: 'Review scanner components' },
      },
      {
        id: 'restart-capacity', title: 'What happens after a restart or at capacity?', searchText: 'restart recover resume queue capacity retry storage workers sse connections',
        answer: <>A running scan returns to the persistent queue and restarts its analysis after the service comes back; completed results remain unchanged. When queue, storage, or connection capacity is exhausted, new requests receive a retryable response while accepted work continues. Jobs shows the current limits.</>,
        link: { to: '/jobs', label: 'Review capacity' },
      },
    ],
  },
  {
    id: 'results-reports', title: 'Results and reports', icon: Archive,
    description: 'Explore findings, compare scans, and move report data safely.',
    items: [
      {
        id: 'review-findings', title: 'How do I explore scan findings?', searchText: 'vulnerability findings severity package target fix search sort resize drawer details',
        answer: <>Select an archive name to open its latest results. Filter by severity, package, target, fix availability, or text; resize and sort columns; then select a vulnerability to read its complete details.</>,
        link: { to: '/', label: 'Choose an image' },
      },
      {
        id: 'compare-scans', title: 'How do I compare two scans?', searchText: 'insights compare history new resolved unchanged net',
        answer: <>After an archive has at least two completed scans, Insights calculates new, resolved, unchanged, and net finding counts from the saved results. Changing the UI never reruns Trivy.</>,
        link: { to: '/insights', label: 'Open Insights' },
      },
      {
        id: 'export-formats', title: 'Which export format should I use?', searchText: 'export report json html pdf elastic ecs ndjson defectdojo generic findings download format',
        answer: <><b>LayerScope JSON</b> is the portable format that can be imported back. <b>HTML</b> and <b>PDF</b> are human-readable reports and may include a one-time PNG/JPEG logo. LayerScope validates and cleans the logo, embeds it locally, and never saves it. <b>Elastic NDJSON</b> targets an authorized Elasticsearch <code>/_bulk</code> endpoint using ECS 9.5.0 fields. <b>DefectDojo JSON</b> targets the Generic Findings Import scan type; Unknown severity maps to Info with an explicit justification.</>,
        link: { to: '/insights', label: 'Open report exports' },
      },
      {
        id: 'report-import', title: 'What does importing a report restore?', searchText: 'import report restore normalized findings packages raw json tar report only duplicate', access: 'Administrator',
        answer: <>Importing LayerScope JSON restores completed scan dates, coverage notes, normalized findings, and package inventory as a clearly marked report-only entry. It does not restore the original TAR or raw Trivy JSON, so the entry can be searched, compared, and exported but cannot be rescanned or downloaded. Re-importing the same report is safely skipped.</>,
        link: { to: '/data', label: 'Open Data' },
      },
      {
        id: 'report-privacy', title: 'Do exports reveal private storage paths?', searchText: 'privacy report archive paths host credentials raw evidence',
        answer: <>No. LayerScope JSON, HTML, PDF, Elastic, and DefectDojo exports identify images by name and scan metadata while omitting internal archive paths, host details, credentials, and raw Trivy evidence.</>,
      },
    ],
  },
  {
    id: 'automation-api', title: 'Automation and API', icon: SquareTerminal,
    description: 'Use personal tokens, authenticated API docs, and the CLI.',
    items: [
      {
        id: 'api-tokens', title: 'How do personal API tokens work?', searchText: 'api token bearer authorization secret hash expire revoke role csrf',
        answer: <>Each user manages their own expiring bearer tokens. Copy the complete secret when it is created because only its hash is retained. Tokens inherit the owner's current role and stop working after revocation or security-impacting account changes. A bearer token cannot create replacement tokens.</>,
        link: { to: '/api-tokens', label: 'Manage API tokens' },
      },
      {
        id: 'api-docs', title: 'Where is the API documentation?', searchText: 'api docs openapi schema swagger redoc curl powershell explorer',
        answer: <>API Docs provides the authenticated endpoint catalog, schemas, role requirements, and curl and PowerShell examples. Safe JSON reads can run with the browser session; mutations and downloads remain examples only. Authenticated clients can download <code>/api/openapi.json</code>. Public Swagger and ReDoc routes are disabled.</>,
        link: { to: '/api-docs', label: 'Open API Docs' },
      },
      {
        id: 'cli', title: 'Can I scan from CI/CD or another tool?', searchText: 'cli pipeline cicd ci cd jenkins automation exit codes severity gate token stdin environment secret file',
        answer: <>Yes. The Python <code>layerscope</code> client streams uploads, queues and waits for scans, applies severity gates, reads findings, exports reports, and uses stable exit codes with bounded waits. Supply its token through a protected environment variable, standard input, or restricted secret file—never as a command argument. Setup and Jenkins examples are in <code>cli/README.md</code> and <code>examples/ci</code>.</>,
      },
    ],
  },
  {
    id: 'administration', title: 'Administration and recovery', icon: UserRoundCog,
    description: 'Manage accounts, backups, stored data, and recovery safely.',
    items: [
      {
        id: 'user-lifecycle', title: 'How are local accounts managed?', searchText: 'users create account activate role unlock disable remove self registration pending', access: 'Administrator',
        answer: <>Users cannot self-register. An administrator creates a pending account and privately sends its one-time activation code; the user chooses their own password and enrolls their own authenticator. Administrators can manage eligible accounts but cannot remove themselves or the last active administrator.</>,
        link: { to: '/users', label: 'Open Users' },
      },
      {
        id: 'two-factor', title: 'How do 2FA reissue and admin password recovery differ?', searchText: 'totp otp 2fa reissue lost password recovery code reset admin aegis freeotp', access: 'Administrator',
        answer: <><b>Reissue 2FA</b> gives a user a one-time enrollment code and preserves their password. If an administrator loses only their password but still has their authenticator or an unused recovery code, an authorized person with server access can use the interactive recovery command in <code>INSTALL.md</code>. It preserves 2FA, revokes sessions, and is audited. There is no browser reset or second-factor bypass.</>,
      },
      {
        id: 'remove-data', title: 'What is deleted when I remove an image?', searchText: 'delete remove image scan findings packages raw json tar mounted hide restore disk space', access: 'Administrator',
        answer: <>Removing an image deletes its saved scans, findings, packages, and raw JSON. A dashboard-uploaded TAR is permanently deleted; a read-only mounted TAR stays on the host and is hidden until restored. Export LayerScope JSON first if you may need the normalized report later.</>,
        link: { to: '/data', label: 'Open Data' },
      },
      {
        id: 'backup', title: 'What is protected by backup and restore?', searchText: 'backup restore tdbackup password encrypted sqlite auth key accounts audit raw tar rollback session', access: 'Administrator',
        answer: <>An encrypted <code>.tdbackup</code> includes SQLite data, local accounts, the authentication key, audit history, raw Trivy JSON, and uploaded TAR files. Downloadable component databases and host-mounted archives are excluded. Restore stages and validates content before replacement, requires idle queues and typed confirmation, then revokes restored sessions. The backup password is never stored and cannot be recovered.</>,
        link: { to: '/data', label: 'Manage backups' },
      },
      {
        id: 'persistent-storage', title: 'Where is application data stored?', searchText: 'docker volume trivy data sqlite accounts uploads raw jobs database compose down v delete', access: 'Administrator',
        answer: <>The <code>trivy-data</code> Docker volume contains SQLite, accounts, uploaded archives, raw JSON, jobs, and updated component databases. <code>docker compose down</code> keeps this volume. Adding <code>-v</code> deletes it and must not be used for a normal update.</>,
      },
    ],
  },
  {
    id: 'components-diagnostics', title: 'Components and diagnostics', icon: ServerCog,
    description: 'Maintain scanner data and understand runtime health.',
    items: [
      {
        id: 'component-updates', title: 'How do vulnerability database updates work?', searchText: 'components check updates update now registry ghcr java database deadline install', access: 'Operator or administrator',
        answer: <><b>Check for updates</b> reads database update deadlines and tests the configured official registries. <b>Update now</b> explicitly downloads and verifies the selected OCI database artifact. The Java index is optional and large; install it before scanning JAR-containing images offline.</>,
        link: { to: '/components', label: 'Open Components' },
      },
      {
        id: 'diagnostics', title: 'What does Diagnostics check?', searchText: 'diagnostics health trivy sqlite scan roots workers storage cache registries host probe',
        answer: <>Diagnostics reports Trivy, SQLite, scan roots, workers, storage, temporary scan workspace, vulnerability and Java databases, and configured registries. It also lists optional components that are not installed.</>,
        link: { to: '/diagnostics', label: 'Open Diagnostics' },
      },
      {
        id: 'storage-headroom', title: 'Why can storage headroom differ from Docker disk size?', searchText: 'storage headroom docker desktop sparse virtual disk host probe free space capacity',
        answer: <>Docker Desktop can report the large maximum size of its sparse virtual disk instead of real host free space. LayerScope uses the smaller Docker-volume or read-only host-drive probe value when the probe is configured, then protects the configured storage reserve.</>,
        link: { to: '/jobs', label: 'Review storage capacity' },
      },
    ],
  },
  {
    id: 'security', title: 'Security boundaries', icon: ShieldCheck,
    description: 'Know what LayerScope protects and which actions require care.',
    items: [
      {
        id: 'credential-privacy', title: 'Who can see passwords and authenticator secrets?', searchText: 'password authenticator totp secret privacy administrator activation recovery codes',
        answer: <>Only the user enters their password and sees their TOTP enrollment secret. Administrators receive only one-time activation or reissue codes, which expire and are stored only as hashes. Recovery codes and API tokens are also shown only once.</>,
      },
      {
        id: 'authorization', title: 'Why are some pages or actions missing?', searchText: 'rbac role viewer operator administrator hidden pages permissions authorization',
        answer: <>Your role controls available actions: viewers inspect saved data, operators can run scans and maintain scanner components, and administrators manage users, backups, imports, and deletion. Hiding a control is only a convenience; the backend enforces every permission.</>,
      },
      {
        id: 'safe-updates', title: 'Which update commands preserve my data?', searchText: 'docker compose update rebuild volume down v preserve data destructive', access: 'Administrator',
        answer: <>Rebuilding or recreating the application containers preserves the named data volume. Never use <code>docker compose down -v</code> for a normal update because <code>-v</code> removes persistent LayerScope data.</>,
      },
    ],
  },
  {
    id: 'troubleshooting', title: 'Troubleshooting', icon: LifeBuoy,
    description: 'Resolve common discovery, upload, scan, and storage problems.',
    items: [
      {
        id: 'archive-not-found', title: 'Why is a mounted TAR not listed?', searchText: 'archive missing not found discover image dir mount windows extension tar count',
        answer: <>Confirm the host folder is bound to the configured container scan root, the file really ends in <code>.tar</code>, and Docker Desktop can share that drive. Then use <b>Discover</b>. Changing <code>IMAGE_DIR</code> requires recreating the backend container because bind mounts are fixed when a container starts.</>,
        link: { to: '/', label: 'Open Overview' },
      },
      {
        id: 'large-uploads', title: 'What should I do when a large upload fails?', searchText: 'upload connection failed parsing body firefox crash multiple files request limit tar invalid',
        answer: <>Keep the tab open while LayerScope sends selected files one at a time. Successful earlier files remain saved, rejected partial files are removed, and the remaining queue continues. Review the upload summary and Diagnostics before retrying; confirm the file is a valid Docker/OCI TAR and fits the configured per-file, request, and storage limits.</>,
        link: { to: '/diagnostics', label: 'Check Diagnostics' },
      },
      {
        id: 'no-space', title: 'Why did Trivy report “no space left on device”?', searchText: 'no space left device trivy tmp temporary model safetensors layer disk workspace cleanup',
        answer: <>Large files inside an image can require substantial temporary disk space during layer analysis. LayerScope uses <code>/data/trivy-tmp</code> instead of the container's small memory-backed <code>/tmp</code> and cleans it after each scan. Check the scan workspace and real host-drive free space in Diagnostics before retrying.</>,
        link: { to: '/diagnostics', label: 'Inspect scan storage' },
      },
      {
        id: 'zero-findings', title: 'Does zero vulnerabilities mean an image is completely secure?', searchText: 'zero no vulnerabilities secure findings unknown secret configuration misconfiguration cis license coverage',
        answer: <>No. It means the enabled Trivy vulnerability analyzers found no matching known vulnerabilities in detected packages. Review scan coverage and database freshness. The current scan does not prove the absence of secrets, configuration problems, CIS benchmark failures, or unknown defects.</>,
        link: { to: '/components', label: 'Check database coverage' },
      },
    ],
  },
]

const quickStarts = [
  { number: '1', title: 'Add an archive', text: 'Mount a read-only folder or upload Docker/OCI TAR files.', to: '/', linkLabel: 'Open Overview', icon: Upload },
  { number: '2', title: 'Run and follow a scan', text: 'Select images on Overview, then follow persistent work in Jobs.', to: '/jobs', linkLabel: 'Open Jobs', icon: Gauge },
  { number: '3', title: 'Review and export', text: 'Open image findings, compare history, and create reports.', to: '/insights', linkLabel: 'Open Insights', icon: Download },
]

export default function HelpPage() {
  const { user } = useAuth()
  const [query, setQuery] = useState('')
  const filteredCategories = useMemo(() => {
    const search = normalize(query)
    if (!search) return categories
    return categories.map(category => ({
      ...category,
      items: category.items.filter(item => matches(item, category, search)),
    })).filter(category => category.items.length > 0)
  }, [query])
  const resultCount = filteredCategories.reduce((total, category) => total + category.items.length, 0)

  return <div className="mx-auto max-w-7xl space-y-8">
    <section className="overflow-hidden rounded-3xl border bg-gradient-to-br from-slate-950 via-slate-900 to-blue-950 px-5 py-8 text-white shadow-xl sm:px-8 lg:px-10" aria-labelledby="help-page-heading">
      <div className="grid gap-8 lg:grid-cols-[1fr_22rem] lg:items-end">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-cyan-300"><CircleHelp size={18}/>LayerScope Help</p>
          <h1 id="help-page-heading" className="mt-3 max-w-3xl text-3xl font-bold tracking-tight sm:text-4xl">What would you like to do?</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">Follow a workflow, browse by topic, or search concise answers. Long-form installation and security details remain in the repository documentation.</p>
        </div>
        <div>
          <label htmlFor="help-search" className="mb-2 block text-sm font-semibold text-slate-200">Search Help</label>
          <div className="relative">
            <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18}/>
            <input id="help-search" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Try “large upload” or “API token”" className="min-h-12 w-full rounded-xl border border-slate-600 bg-slate-950/70 py-3 pl-10 pr-11 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/30"/>
            {query && <button type="button" onClick={() => setQuery('')} className="absolute right-2 top-1/2 flex size-8 -translate-y-1/2 items-center justify-center rounded-lg text-slate-400 hover:bg-white/10 hover:text-white" aria-label="Clear Help search"><X size={17}/></button>}
          </div>
          <p className="mt-2 text-xs text-slate-400" aria-live="polite">{query ? `${resultCount} ${resultCount === 1 ? 'answer' : 'answers'} found` : `Signed in as ${user?.role ?? 'user'}`}</p>
        </div>
      </div>
    </section>

    {!query && <section aria-labelledby="quick-start-heading">
      <div className="mb-4"><p className="text-sm font-semibold text-blue-600">Recommended workflow</p><h2 id="quick-start-heading" className="text-2xl font-bold">Start here</h2></div>
      <ol className="grid gap-4 lg:grid-cols-3">
        {quickStarts.map(step => { const Icon = step.icon; return <li key={step.number} className="card relative p-5"><div className="flex items-start gap-4"><span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-blue-600 font-bold text-white" aria-hidden="true">{step.number}</span><div><Icon className="mb-3 text-blue-600" size={22}/><h3 className="font-semibold">{step.title}</h3><p className="mt-1 text-sm leading-6 text-slate-600">{step.text}</p><Link to={step.to} className="mt-3 inline-flex text-sm font-semibold text-blue-600 hover:underline">{step.linkLabel}<span aria-hidden="true"> →</span></Link></div></div></li> })}
      </ol>
    </section>}

    {!query && <nav aria-label="Help categories" className="card p-4 sm:p-5">
      <p className="mb-3 text-xs font-bold uppercase tracking-[0.16em] text-slate-500">Browse by topic</p>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {categories.map(category => { const Icon = category.icon; return <a key={category.id} href={`#${category.id}`} className="flex min-h-12 items-center gap-3 rounded-xl border bg-slate-50 px-3 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-blue-300 hover:bg-blue-50 hover:text-blue-700"><Icon size={18} className="shrink-0 text-blue-600"/><span>{category.title}</span><span className="ml-auto text-xs font-normal text-slate-400">{category.items.length}</span></a> })}
      </div>
    </nav>}

    <div className="space-y-8">
      {filteredCategories.map(category => <HelpSection key={category.id} category={category} role={user?.role}/>) }
      {resultCount === 0 && <section className="card px-6 py-12 text-center" aria-live="polite"><Search className="mx-auto text-slate-400" size={30}/><h2 className="mt-4 text-lg font-semibold">No matching help found</h2><p className="mt-2 text-sm text-slate-500">Try a shorter phrase such as “upload”, “backup”, “Java”, or “token”.</p><button type="button" className="btn-secondary mt-5" onClick={() => setQuery('')}>Clear search</button></section>}
    </div>

    <aside className="rounded-2xl border border-amber-300 bg-amber-50 p-5" aria-labelledby="safety-note-heading">
      <div className="flex gap-3"><ShieldCheck className="mt-0.5 shrink-0 text-amber-700" size={22}/><div><h2 id="safety-note-heading" className="font-semibold text-amber-800">Before changing or removing data</h2><p className="mt-1 text-sm leading-6 text-amber-800">Export a portable LayerScope JSON report or an encrypted backup first. Rebuilding containers preserves the named volume, but <code>docker compose down -v</code> permanently removes it. Follow <code>INSTALL.md</code> and <code>SECURITY.md</code> for deployment and recovery procedures.</p></div></div>
    </aside>
  </div>
}

function HelpSection({ category, role }: { category: HelpCategory; role?: AuthUser['role'] }) {
  const Icon = category.icon
  return <section id={category.id} className="scroll-mt-24" aria-labelledby={`${category.id}-heading`}><div className="mb-4 flex items-start gap-3"><span className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-blue-600"><Icon size={22}/></span><div><h2 id={`${category.id}-heading`} className="text-xl font-bold sm:text-2xl">{category.title}</h2><p className="mt-1 text-sm text-slate-500">{category.description}</p></div></div><div className="card divide-y overflow-hidden">{category.items.map(item => <HelpTopic key={item.id} item={item} role={role}/>)}</div></section>
}

function HelpTopic({ item, role }: { item: HelpItem; role?: AuthUser['role'] }) {
  const canFollowLink = item.link && (role === 'admin' || (item.link.to !== '/users' && item.link.to !== '/data'))
  return <details id={`help-${item.id}`} className="group scroll-mt-24"><summary className="flex min-h-16 cursor-pointer list-none items-center justify-between gap-4 px-4 py-4 transition hover:bg-slate-50 sm:px-5"><span className="min-w-0"><span className="block font-semibold text-slate-900">{item.title}</span>{item.access && <span className="mt-1 inline-flex rounded-full border bg-slate-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">{item.access}</span>}</span><ChevronDown className="shrink-0 text-slate-400 transition-transform group-open:rotate-180" size={19}/></summary><div className="border-t bg-slate-50 px-4 py-4 text-sm leading-6 text-slate-600 sm:px-5"><p>{item.answer}</p>{item.link && canFollowLink && <Link to={item.link.to} className="mt-3 inline-flex min-h-9 items-center font-semibold text-blue-600 hover:underline">{item.link.label}<span aria-hidden="true"> →</span></Link>}</div></details>
}

function normalize(value: string) {
  return value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, ' ').trim()
}

function matches(item: HelpItem, category: HelpCategory, query: string) {
  const haystack = normalize(`${category.title} ${category.description} ${item.title} ${item.searchText} ${item.access ?? ''}`)
  if (haystack.includes(query)) return true
  const words = haystack.split(' ')
  return query.split(' ').every(token => words.some(word => word.includes(token) || token.includes(word) || (token.length >= 4 && oneEditApart(token, word))))
}

function oneEditApart(left: string, right: string) {
  if (Math.abs(left.length - right.length) > 1) return false
  let i = 0, j = 0, edits = 0
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) { i += 1; j += 1; continue }
    edits += 1
    if (edits > 1) return false
    if (left.length > right.length) i += 1
    else if (right.length > left.length) j += 1
    else { i += 1; j += 1 }
  }
  if (i < left.length || j < right.length) edits += 1
  return edits <= 1
}
