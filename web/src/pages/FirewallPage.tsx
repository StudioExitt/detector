import { useState } from 'react'
import { ChevronRight, ExternalLink, ShieldCheck, ShieldOff } from 'lucide-react'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n, type MessageKey } from '../i18n'
import { api, type FirewallComponent } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import EventsPage from './EventsPage'

export default function FirewallPage() {
  const { t, lang } = useI18n()
  const { data, error, loading, reload } = useFetch((s) => api.firewallStatus(s), [])
  useInterval(reload, 30000)

  const enabled = data?.components.filter((c) => c.state === 'on' && c.kind !== 'info') ?? []
  const isMac = data?.platform.startsWith('darwin') ?? false

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {data ? t('fw.collectedAt', { time: new Date(data.at).toLocaleTimeString(lang) }) : ''}
        </span>
        <span className="ml-auto flex items-center gap-2">
          {isMac && <OpenSettingsButton />}
          <RefreshButton onClick={reload} loading={loading} />
        </span>
      </div>

      {error && <ErrorBox error={error} />}

      {data && (
        <div
          className={`flex items-start gap-3 rounded-xl border px-4 py-3 ${
            data.active
              ? 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200'
              : 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200'
          }`}
        >
          {data.active ? <ShieldCheck className="mt-0.5 size-6 shrink-0" /> : <ShieldOff className="mt-0.5 size-6 shrink-0" />}
          <div>
            <div className="font-semibold">{data.active ? t('fw.active') : t('fw.inactive')}</div>
            <div className="text-sm opacity-90">
              {data.active ? t('fw.activeHint', { names: enabled.map((c) => c.name).join(', ') }) : t('fw.inactiveHint')}
            </div>
          </div>
        </div>
      )}

      {data && data.components.length === 0 && <p className="text-sm text-slate-500">{t('fw.none')}</p>}
      {data?.components.map((c) => <ComponentCard key={c.id} c={c} />)}

      <h2 className="pt-2 text-sm font-semibold">{t('fw.events')}</h2>
      <EventsPage detector="firewall" />
    </div>
  )
}

// Opens System Settings > Network > Firewall on the Mac running the server.
function OpenSettingsButton() {
  const { t } = useI18n()
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const open = async () => {
    try {
      await api.openFirewallSettings()
      setMsg({ ok: true, text: t('fw.opened') })
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message })
    }
    setTimeout(() => setMsg(null), 4000)
  }
  return (
    <>
      {msg && (
        <span className={`text-xs ${msg.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-700 dark:text-rose-400'}`}>{msg.text}</span>
      )}
      <button
        type="button"
        onClick={open}
        title={t('fw.openHint')}
        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
      >
        <ExternalLink className="size-3.5" />
        {t('fw.open')}
      </button>
    </>
  )
}

const stateStyle: Record<string, string> = {
  on: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300',
  off: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
  unknown: 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300',
  info: 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300',
}

function label(t: (k: MessageKey) => string, prefix: string, v: string) {
  const key = `${prefix}.${v}` as MessageKey
  const s = t(key)
  return s === key ? v : s
}

function ComponentCard({ c }: { c: FirewallComponent }) {
  const { t } = useI18n()
  const [filter, setFilter] = useState<'all' | 'allow' | 'block' | 'warn'>('all')
  const counts = {
    all: c.rules.length,
    allow: c.rules.filter((r) => r.action === 'allow').length,
    block: c.rules.filter((r) => r.action === 'block').length,
    warn: c.rules.filter((r) => r.warn).length,
  }
  const rules = c.rules.filter((r) => filter === 'all' || (filter === 'warn' ? r.warn : r.action === filter))
  const stateIcon = c.state === 'on' ? 'ok' : c.state === 'off' ? 'warn' : null

  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-2">
          {c.name}
          <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-normal text-slate-600 dark:bg-slate-800 dark:text-slate-400">
            {label(t, 'fw.kind', c.kind)}
          </span>
        </span>
      }
      actions={
        <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${stateStyle[c.state] ?? stateStyle.unknown}`}>
          {stateIcon && <StatusIcon status={stateIcon} className="size-3.5" />}
          {label(t, 'fw.state', c.state)}
        </span>
      }
    >
      {c.detail && <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">{c.detail}</p>}

      {c.settings.length > 0 && (
        <div className="-mx-4 mb-4 overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="px-3 py-2 pl-4 font-medium">{t('fw.setting')}</th>
                <th className="px-3 py-2 font-medium">{t('fw.value')}</th>
                <th className="px-3 py-2 pr-4 font-medium">{t('fw.note')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {c.settings.map((s) => (
                <tr key={s.name}>
                  <td className="px-3 py-1.5 pl-4 font-medium">{s.name}</td>
                  <td className="px-3 py-1.5 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1.5">
                      <StatusIcon status={s.status === 'fail' ? 'fail' : s.status === 'warn' ? 'warn' : 'ok'} className="size-3.5" />
                      {s.value}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 pr-4 text-xs text-slate-600 dark:text-slate-400">{s.note ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* an unknown state (e.g. pf without root) has no readable rules: don't claim "no rules" */}
      {(c.rules.length > 0 || (c.kind !== 'info' && c.state !== 'unknown')) && (
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold">{t('fw.rules', { count: c.rules.length })}</h3>
            {c.rules.length > 0 &&
              c.kind !== 'info' &&
              (['all', 'allow', 'block', 'warn'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFilter(f)}
                  disabled={f !== 'all' && counts[f] === 0}
                  aria-pressed={filter === f}
                  className={`rounded-lg border px-2 py-0.5 text-xs font-medium disabled:opacity-40 ${
                    filter === f
                      ? 'border-blue-500 bg-blue-50 text-blue-700 dark:border-blue-400 dark:bg-blue-500/15 dark:text-blue-300'
                      : 'border-slate-200 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800'
                  }`}
                >
                  {f === 'all' ? t('fw.filter.all') : f === 'warn' ? t('fw.filter.warn') : label(t, 'fw.action', f)} {counts[f]}
                </button>
              ))}
          </div>
          {c.rules.length === 0 ? (
            <p className="text-sm text-slate-500">{t('fw.noRules')}</p>
          ) : (
            <div className="-mx-4 overflow-x-auto">
              <table className="w-full min-w-[560px] text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="px-3 py-2 pl-4 font-medium">{t('fw.target')}</th>
                    <th className="px-3 py-2 font-medium">{t('fw.action')}</th>
                    <th className="px-3 py-2 pr-4 font-medium">{t('fw.note')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {rules.map((r, i) => (
                    <tr key={`${r.target}-${i}`} className={r.warn ? 'bg-amber-50/60 dark:bg-amber-500/5' : ''}>
                      <td className="px-3 py-1.5 pl-4 font-mono text-xs break-all">{r.target}</td>
                      <td className="px-3 py-1.5 whitespace-nowrap">
                        <span
                          className={`rounded-md px-2 py-0.5 text-xs font-medium ${
                            r.action === 'block'
                              ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300'
                              : r.action === 'allow' || r.action === 'active'
                                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300'
                          }`}
                        >
                          {label(t, 'fw.action', r.action)}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 pr-4 text-xs">
                        {r.warn && <span className="mr-1 text-amber-700 dark:text-amber-400">⚠</span>}
                        <span className={r.warn ? 'text-amber-800 dark:text-amber-300' : 'text-slate-600 dark:text-slate-400'}>{r.note ?? ''}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {c.files.length > 0 && (
        <div className="mt-4 space-y-2">
          <h3 className="text-sm font-semibold">{t('fw.files')}</h3>
          {c.files.map((f) => (
            <details key={f.path} className="group rounded-lg border border-slate-200 dark:border-slate-800">
              <summary className="flex cursor-pointer list-none items-center gap-1.5 px-3 py-2 font-mono text-xs">
                <ChevronRight className="size-4 text-slate-400 transition-transform group-open:rotate-90" />
                {f.path}
              </summary>
              <pre className="max-h-80 overflow-auto border-t border-slate-200 bg-slate-50 px-3 py-2 text-xs leading-relaxed dark:border-slate-800 dark:bg-slate-950">
                {f.content}
              </pre>
            </details>
          ))}
        </div>
      )}
    </Card>
  )
}
