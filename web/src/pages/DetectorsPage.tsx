import type { ReactNode } from 'react'
import { ChevronRight, Clock, Timer } from 'lucide-react'
import { Link } from 'react-router'
import StatusIcon from '../components/StatusIcon'
import { ErrorBox, RefreshButton } from '../components/ui'
import { useI18n, type MessageKey } from '../i18n'
import { api, type DetectorStatus } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'

export function detectorLabel(t: (k: MessageKey) => string, name: string) {
  const key = `detector.${name}` as MessageKey
  const label = t(key)
  return label === key ? name : label
}

export default function DetectorsPage() {
  const { t } = useI18n()
  const { data, error, loading, reload } = useFetch((s) => api.detectors(s), [])
  useInterval(reload, 15000)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
        {data && (
          <>
            <span>
              <span className="text-slate-500 dark:text-slate-400">{t('detectors.platform')}</span>{' '}
              <span className="font-mono">{data.platform}</span>
            </span>
            <span>
              <span className="text-slate-500 dark:text-slate-400">{t('detectors.host')}</span>{' '}
              <span className="font-mono">{data.host}</span>
            </span>
          </>
        )}
        <span className="ml-auto flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
          {t('detectors.autoRefresh')}
          <RefreshButton onClick={reload} loading={loading} />
        </span>
      </div>

      {error && <ErrorBox error={error} />}
      {data && data.items.length === 0 && <p className="text-sm text-slate-500">{t('detectors.none')}</p>}
      <div className="grid gap-4 xl:grid-cols-2">
        {data?.items.map((d) => <DetectorCard key={d.name} d={d} />)}
      </div>
    </div>
  )
}

function DetectorCard({ d }: { d: DetectorStatus }) {
  const { t, lang } = useI18n()
  const healthy = !d.lastError && !!d.lastRunAt
  // surface the most important check results; the rest are on the detail page
  const issues = d.checks.filter((c) => c.status !== 'ok')
  const preview = [...issues.filter((c) => c.status === 'fail'), ...issues.filter((c) => c.status === 'warn')].slice(0, 3)

  return (
    <Link
      to={`/detectors/${encodeURIComponent(d.name)}`}
      className="group block rounded-xl border border-slate-200 bg-white shadow-sm transition-colors hover:border-blue-400 focus-visible:outline-2 focus-visible:outline-blue-500 dark:border-slate-800 dark:bg-slate-900 dark:hover:border-blue-500/60"
    >
      <div className="flex items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <StatusIcon status={d.lastError ? 'fail' : d.lastRunAt ? 'ok' : 'warn'} />
          {detectorLabel(t, d.name)}
          <span className="font-mono text-xs font-normal text-slate-500">{d.name}</span>
        </h2>
        <span
          className={`rounded-md px-2 py-0.5 text-xs font-medium ${
            healthy
              ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300'
              : 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300'
          }`}
        >
          {d.lastError ? t('detectors.error') : d.lastRunAt ? t('detectors.healthy') : t('detectors.notRun')}
        </span>
      </div>

      <div className="p-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
          <Stat label={t('detectors.interval')} value={`${d.intervalSeconds}s`} />
          <Stat
            label={t('detectors.lastRun')}
            value={d.lastRunAt ? new Date(d.lastRunAt).toLocaleTimeString(lang) : '-'}
            icon={<Clock className="size-3" />}
          />
          <Stat label={t('detectors.duration')} value={d.lastDurationMs != null ? `${d.lastDurationMs}ms` : '-'} icon={<Timer className="size-3" />} />
          <Stat label={t('detectors.findings')} value={String(d.findings)} />
        </dl>

        {d.summary && <p className="mt-3 text-sm">{d.summary}</p>}
        {d.lastError && (
          <p className="mt-2 rounded-lg bg-rose-50 px-3 py-2 font-mono text-xs break-all text-rose-700 dark:bg-rose-500/10 dark:text-rose-300">
            {d.lastError}
          </p>
        )}

        {preview.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs">
            {preview.map((c, i) => (
              <li key={`${c.name}-${i}`} className="flex min-w-0 items-start gap-2">
                <StatusIcon status={c.status} className="mt-0.5 size-3.5" />
                <span className="max-w-[60%] shrink-0 truncate font-medium" title={c.name}>
                  {c.name}
                </span>
                <span className="min-w-0 truncate text-slate-500 dark:text-slate-400">{c.detail}</span>
              </li>
            ))}
          </ul>
        )}

        <div className="mt-3 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
          <span>{t('detectors.showChecks', { count: d.checks.length })}</span>
          <span className="inline-flex items-center gap-0.5 font-medium text-blue-600 group-hover:underline dark:text-blue-400">
            {t('detectors.viewDetail')}
            <ChevronRight className="size-4" />
          </span>
        </div>
      </div>
    </Link>
  )
}

function Stat({ label, value, icon }: { label: string; value: string; icon?: ReactNode }) {
  return (
    <div>
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="flex items-center gap-1 font-medium tabular-nums">
        {icon}
        {value}
      </dd>
    </div>
  )
}
