// 서버 OpenAPI 스펙(server/api/openapi.yaml)과 맞춰 유지
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/$/, '')

export type EventCategory = 'intrusion' | 'resource_abuse' | 'vulnerability_scan' | 'etc'
export type EventSeverity = 'low' | 'medium' | 'high' | 'critical'

export type Health = { status: string; version: string; time: string }

export type DetectEvent = {
  id: number
  category: EventCategory
  severity: EventSeverity
  source?: string
  message: string
  detectedAt: string
  detector?: string
  rule?: string
}

export type CheckStatus = 'ok' | 'warn' | 'fail'

export type DetectorCheck = { name: string; status: CheckStatus; detail: string }

export type DetectorStatus = {
  name: string
  intervalSeconds: number
  lastRunAt?: string
  lastDurationMs?: number
  lastError?: string
  findings: number
  summary: string
  compactSuccessRuns?: boolean
  checks: DetectorCheck[]
}

export type DetectorList = { platform: string; host: string; items: DetectorStatus[] }

export type DetectorDetail = { platform: string; host: string; status: DetectorStatus; sources: string[] }

export type DetectorRun = {
  id: number
  startedAt: string
  durationMs: number
  error?: string
  summary: string
  findings: number
  checksOk: number
  checksWarn: number
  checksFail: number
  checks?: DetectorCheck[]
}

export type DetectorRunList = { items: DetectorRun[]; total: number }

export type ProcUsage = { pid: number; name: string; exe: string; user: string; cpuPct: number; rss: number; highSince?: string }

export type SystemStatus = {
  at: string
  cpu: { usagePct: number; userPct: number; systemPct: number; load1: number; load5: number; load15: number; cores: number }
  memory: { total: number; used: number; usedPct: number; pressure: 'normal' | 'warn' | 'critical' | string; swapTotal: number; swapUsed: number }
  disks: { mount: string; total: number; used: number; free: number; usedPct: number }[]
  topCpu: ProcUsage[]
  topMem: ProcUsage[]
}

export type ProcConnections = {
  pid: number
  name: string
  exe: string
  conns: number
  external: number
  hosts: number
  synSent: number
  ports: number[]
  sample: string[]
  txBytes: number
  rxBytes: number
  flags: string[]
}

export type NetworkStatus = {
  at: string
  gateway: string
  gatewayMac: string
  interface: string
  dns: string[]
  proxies: string[]
  internet: { reachable: boolean; latencyMs: number; target: string; error?: string }
  interfaces: { name: string; up: boolean; addrs: string[]; rxBps: number; txBps: number }[]
  rxBps: number
  txBps: number
  established: number
  external: number
  processes: ProcConnections[]
  connections: { local: string; remote: string; remotePort: number; scope: string; state: string; pid: number; process: string; txBytes: number; rxBytes: number }[]
}

export type FirewallComponent = {
  id: string
  name: string
  kind: 'builtin' | 'third_party' | 'info' | string
  state: 'on' | 'off' | 'unknown' | 'info' | string
  detail?: string
  settings: { name: string; value: string; status: 'ok' | 'warn' | 'fail' | string; note?: string }[]
  rules: { target: string; action: string; note?: string; warn: boolean }[]
  files: { path: string; content: string }[]
}

export type FirewallStatus = { at: string; platform: string; active: boolean; components: FirewallComponent[] }

export type MetricRange = '1h' | '6h' | '24h' | '7d'
export type MetricSeriesList = { range: string; items: { name: string; points: { t: string; v: number }[] }[] }

export type ClipboardCanaryCheck = {
  chain: string
  canary: string
  observed?: string
  changed: boolean
  swapped: boolean
  afterMs?: number
}

export type ClipboardTestResult = {
  startedAt: string
  durationMs: number
  swapped: boolean
  restored: boolean
  note?: string
  checks: ClipboardCanaryCheck[]
}

export type RecordingKind = 'screen' | 'mic' | 'camera' | 'remote' | 'input'

export type RecordingUse = {
  kind: RecordingKind
  app: string
  name: string
  pid: number
  exe?: string
  hidden: boolean
  trusted: boolean
  note?: string
  since: string
}

export type RecordingTool = {
  kind: RecordingKind
  label: string
  pid: number
  user: string
  exe: string
  args: string
  trusted: boolean
  warn: boolean
  note?: string
}

export type RecordingPermission = {
  service: RecordingKind
  client: string
  allowed: boolean
  scope: 'system' | 'user' | string
  updated?: string
  warn: boolean
  note?: string
}

export type RecordingActivity = { kind: RecordingKind; app: string; name: string; pid: number; hidden: boolean; start: string; end?: string }

export type RecordingStatus = {
  at: string
  platform: string
  uses: RecordingUse[]
  devices: { kind: RecordingKind; name: string; inUse: boolean }[]
  tools: RecordingTool[]
  permissions: RecordingPermission[]
  permError?: string
  recent: RecordingActivity[]
  notes: string[]
}

export type EventList = { items: DetectEvent[]; total: number }

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      msg = ((await res.json()) as { message?: string }).message ?? msg
    } catch {
      /* non-JSON body */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

function query(params: Record<string, string | number | undefined>) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, String(v))
  const qs = q.toString()
  return qs ? `?${qs}` : ''
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>('/health', { signal }),
  detectors: (signal?: AbortSignal) => request<DetectorList>('/detectors', { signal }),
  detector: (name: string, signal?: AbortSignal) => request<DetectorDetail>(`/detectors/${encodeURIComponent(name)}`, { signal }),
  detectorRuns: (name: string, params: { limit?: number; offset?: number } = {}, signal?: AbortSignal) =>
    request<DetectorRunList>(`/detectors/${encodeURIComponent(name)}/runs${query(params)}`, { signal }),
  systemStatus: (signal?: AbortSignal) => request<SystemStatus>('/system/status', { signal }),
  networkStatus: (signal?: AbortSignal) => request<NetworkStatus>('/network/status', { signal }),
  firewallStatus: (signal?: AbortSignal) => request<FirewallStatus>('/firewall/status', { signal }),
  openFirewallSettings: () => request<void>('/firewall/open', { method: 'POST' }),
  recordingStatus: (signal?: AbortSignal) => request<RecordingStatus>('/recording/status', { signal }),
  metrics: (names: string[], range: MetricRange, signal?: AbortSignal) =>
    request<MetricSeriesList>(`/metrics${query({ names: names.join(','), range })}`, { signal }),
  clipboardTest: () => request<ClipboardTestResult>('/clipboard/test', { method: 'POST' }),
  detectorRun: (name: string, id: number, signal?: AbortSignal) =>
    request<DetectorRun>(`/detectors/${encodeURIComponent(name)}/runs/${id}`, { signal }),
  listEvents: (
    params: { category?: EventCategory; detector?: string; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) => request<EventList>(`/events${query(params)}`, { signal }),
}
