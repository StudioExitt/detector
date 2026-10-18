import type { ReactNode } from 'react'
import { Camera, EyeOff, Mic, Monitor, ShieldAlert, ShieldCheck, type LucideIcon } from 'lucide-react'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n, type MessageKey } from '../i18n'
import { api, type RecordingKind, type RecordingStatus, type RecordingUse } from '../lib/api'
import { duration } from '../lib/format'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import EventsPage from './EventsPage'

const sensors: { kind: RecordingKind; icon: LucideIcon }[] = [
  { kind: 'screen', icon: Monitor },
  { kind: 'mic', icon: Mic },
  { kind: 'camera', icon: Camera },
]

const th = 'px-3 py-2 font-medium'
const tableHead = 'border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400'

function kindLabel(t: (k: MessageKey) => string, kind: string) {
  const key = `rec.kind.${kind}` as MessageKey
  const s = t(key)
  return s === key ? kind : s
}

export default function RecordingPage() {
  const { t, lang } = useI18n()
  const { data, error, loading, reload } = useFetch((s) => api.recordingStatus(s), [])
  useInterval(reload, 10000)

  const untrusted = data?.uses.filter((u) => !u.trusted) ?? []
  const hidden = untrusted.some((u) => u.hidden)
  const time = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString(lang) : '')

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400">{data ? t('rec.collectedAt', { time: time(data.at) }) : ''}</span>
        <span className="ml-auto">
          <RefreshButton onClick={reload} loading={loading} />
        </span>
      </div>

      {error && <ErrorBox error={error} />}

      {data && (
        <div
          className={`flex items-start gap-3 rounded-xl border px-4 py-3 ${
            hidden
              ? 'border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200'
              : untrusted.length > 0
                ? 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200'
                : 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200'
          }`}
        >
          {untrusted.length > 0 ? <ShieldAlert className="mt-0.5 size-6 shrink-0" /> : <ShieldCheck className="mt-0.5 size-6 shrink-0" />}
          <div>
            <div className="font-semibold">{hidden ? t('rec.hiddenTitle') : untrusted.length > 0 ? t('rec.activeTitle') : t('rec.idle')}</div>
            <div className="text-sm opacity-90">{hidden ? t('rec.hiddenHint') : untrusted.length > 0 ? t('rec.activeHint') : t('rec.idleHint')}</div>
          </div>
        </div>
      )}

      {data && (
        <div className="grid gap-4 md:grid-cols-3">
          {sensors.map((s) => (
            <SensorCard key={s.kind} kind={s.kind} icon={s.icon} data={data} />
          ))}
        </div>
      )}

      {data && data.notes.length > 0 && (
        <Card title={t('rec.notes')}>
          <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-400">
            {data.notes.map((n) => (
              <li key={n} className="flex items-start gap-1.5">
                <StatusIcon status="warn" className="mt-0.5 size-3.5 shrink-0" />
                {n}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {data && (
        <Card title={t('rec.tools', { count: data.tools.length })}>
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('rec.toolsHint')}</p>
          {data.tools.length === 0 ? (
            <p className="text-sm text-slate-500">{t('rec.noTools')}</p>
          ) : (
            <Table head={[t('rec.kindCol'), t('rec.app'), 'PID', 'Exe']}>
              {data.tools.map((x) => (
                <tr key={`${x.exe}-${x.kind}`} className={x.warn ? 'bg-rose-50/60 dark:bg-rose-500/5' : ''}>
                  <td className="px-3 py-1.5 pl-4 whitespace-nowrap">{kindLabel(t, x.kind)}</td>
                  <td className="px-3 py-1.5 font-medium">
                    {x.label} {x.trusted && <Badge>{t('rec.trusted')}</Badge>}
                    {x.note && <div className="text-xs font-normal text-amber-700 dark:text-amber-400">{x.note}</div>}
                  </td>
                  <td className="px-3 py-1.5 tabular-nums">{x.pid}</td>
                  <td className="px-3 py-1.5 pr-4 font-mono text-xs break-all" title={x.args}>
                    {x.exe}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      {data && (data.permissions.length > 0 || data.permError) && (
        <Card title={t('rec.permissions', { count: data.permissions.filter((p) => p.allowed).length })}>
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('rec.permissionsHint')}</p>
          {data.permError && (
            <p className="mb-3 flex items-center gap-1.5 text-sm text-amber-800 dark:text-amber-300">
              <StatusIcon status="warn" className="size-3.5" />
              {data.permError}
            </p>
          )}
          {data.permissions.length === 0 ? (
            !data.permError && <p className="text-sm text-slate-500">{t('rec.noPermissions')}</p>
          ) : (
            <Table head={[t('rec.kindCol'), t('rec.app'), t('fw.action'), t('rec.scope'), t('rec.updated')]}>
              {[...data.permissions]
                .sort((a, b) => Number(b.warn) - Number(a.warn) || a.service.localeCompare(b.service) || a.client.localeCompare(b.client))
                .map((p) => (
                  <tr key={`${p.scope}-${p.service}-${p.client}`} className={p.warn ? 'bg-amber-50/60 dark:bg-amber-500/5' : ''}>
                    <td className="px-3 py-1.5 pl-4 whitespace-nowrap">{kindLabel(t, p.service)}</td>
                    <td className="px-3 py-1.5 font-mono text-xs break-all">
                      {p.client}
                      {p.note && <div className="font-sans text-amber-700 dark:text-amber-400">{p.note}</div>}
                    </td>
                    <td className="px-3 py-1.5 whitespace-nowrap">
                      <StatusIcon status={p.allowed ? (p.warn ? 'warn' : 'ok') : 'fail'} className="mr-1 inline size-3.5" />
                      {p.allowed ? t('rec.permAllowed') : t('rec.permDenied')}
                    </td>
                    <td className="px-3 py-1.5 text-xs">{p.scope}</td>
                    <td className="px-3 py-1.5 pr-4 text-xs whitespace-nowrap">{p.updated ? new Date(p.updated).toLocaleString(lang) : ''}</td>
                  </tr>
                ))}
            </Table>
          )}
        </Card>
      )}

      {data && (
        <Card title={t('rec.recent')}>
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('rec.recentHint')}</p>
          {data.recent.length === 0 ? (
            <p className="text-sm text-slate-500">{t('rec.noRecent')}</p>
          ) : (
            <Table head={[t('rec.kindCol'), t('rec.app'), t('rec.start'), t('rec.end')]}>
              {data.recent.map((r, i) => (
                <tr key={`${r.kind}-${r.app}-${r.start}-${i}`}>
                  <td className="px-3 py-1.5 pl-4 whitespace-nowrap">{kindLabel(t, r.kind)}</td>
                  <td className="px-3 py-1.5">
                    {r.hidden ? <Badge tone="danger">{t('rec.hidden')}</Badge> : r.name}
                    {(r.hidden || r.app !== r.name) && (
                      <span className="ml-1 font-mono text-xs text-slate-500">{r.hidden ? `PID ${r.pid}` : r.app}</span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 text-xs whitespace-nowrap">{new Date(r.start).toLocaleString(lang)}</td>
                  <td className="px-3 py-1.5 pr-4 text-xs whitespace-nowrap">
                    {r.end ? new Date(r.end).toLocaleTimeString(lang) : <Badge tone="warn">{t('rec.ongoing')}</Badge>}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      <h2 className="pt-2 text-sm font-semibold">{t('rec.events')}</h2>
      <EventsPage detector="recording" />
    </div>
  )
}

function SensorCard({ kind, icon: Icon, data }: { kind: RecordingKind; icon: LucideIcon; data: RecordingStatus }) {
  const { t } = useI18n()
  const uses = data.uses.filter((u) => u.kind === kind)
  const devices = data.devices.filter((d) => d.kind === kind)
  const active = uses.length > 0
  const alert = uses.some((u) => !u.trusted)

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Icon className="size-4" />
          {kindLabel(t, kind)}
        </span>
      }
      actions={
        <span
          className={`rounded-md px-2 py-0.5 text-xs font-medium ${
            alert
              ? 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300'
              : active
                ? 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300'
                : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300'
          }`}
        >
          {active ? t('rec.inUse') : t('rec.notInUse')}
        </span>
      }
    >
      {uses.length > 0 && (
        <ul className="mb-3 space-y-2">
          {uses.map((u) => (
            <UseRow key={`${u.app}-${u.pid}`} u={u} />
          ))}
        </ul>
      )}
      {kind !== 'screen' && (
        <div>
          <div className="mb-1 text-xs text-slate-500 dark:text-slate-400">{t('rec.devices')}</div>
          {devices.length === 0 ? (
            <p className="text-sm text-slate-500">{t('rec.noDevices')}</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {devices.map((d) => (
                <li key={d.name} className="flex items-center gap-1.5">
                  <span className={`size-2 shrink-0 rounded-full ${d.inUse ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
                  <span className="min-w-0 truncate">{d.name}</span>
                  {d.inUse && <span className="ml-auto text-xs text-amber-700 dark:text-amber-400">{t('rec.inUse')}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {kind === 'screen' && uses.length === 0 && <p className="text-sm text-slate-500">{t('rec.screenIdle')}</p>}
    </Card>
  )
}

function UseRow({ u }: { u: RecordingUse }) {
  const { t } = useI18n()
  return (
    <li className={`rounded-lg border px-3 py-2 text-sm ${u.hidden ? 'border-rose-200 dark:border-rose-500/30' : 'border-slate-200 dark:border-slate-800'}`}>
      <div className="flex flex-wrap items-center gap-1.5 font-medium">
        {u.hidden && <EyeOff className="size-4 text-rose-600 dark:text-rose-400" />}
        {u.hidden ? t('rec.hidden') : u.name}
        {u.trusted && <Badge>{t('rec.trusted')}</Badge>}
        <span className="ml-auto text-xs font-normal text-slate-500">{t('rec.since', { time: duration(u.since) })}</span>
      </div>
      <div className="font-mono text-xs break-all text-slate-500 dark:text-slate-400">
        {[u.app !== u.name ? u.app : '', u.pid ? `PID ${u.pid}` : '', u.exe ?? ''].filter(Boolean).join(' · ')}
      </div>
      {u.note && <div className="text-xs text-slate-600 dark:text-slate-400">{u.note}</div>}
    </li>
  )
}

function Badge({ children, tone }: { children: ReactNode; tone?: 'warn' | 'danger' }) {
  const cls =
    tone === 'danger'
      ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300'
      : tone === 'warn'
        ? 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300'
        : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
  return <span className={`rounded-md px-1.5 py-0.5 text-xs font-normal ${cls}`}>{children}</span>
}

function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="-mx-4 overflow-x-auto">
      <table className="w-full min-w-[560px] text-sm">
        <thead>
          <tr className={tableHead}>
            {head.map((h, i) => (
              <th key={h} className={`${th} ${i === 0 ? 'pl-4' : ''} ${i === head.length - 1 ? 'pr-4' : ''}`}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
    </div>
  )
}
