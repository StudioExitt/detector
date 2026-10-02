import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router'
import EventTable from '../components/EventTable'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import { detectorLabel } from './DetectorsPage'

export default function Dashboard() {
  const { t, lang } = useI18n()
  const health = useFetch((s) => api.health(s), [])
  const events = useFetch((s) => api.listEvents({ limit: 10 }, s), [])
  const detectors = useFetch((s) => api.detectors(s), [])
  useInterval(detectors.reload, 15000)
  const ok = health.data?.status === 'ok' && !health.error

  return (
    <div className="space-y-4 md:space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <Card title={t('dashboard.serverStatus')} actions={<RefreshButton onClick={health.reload} loading={health.loading} />}>
          <div className="flex items-center gap-2">
            {ok ? <ShieldCheck className="size-6 text-emerald-500" /> : <ShieldAlert className="size-6 text-rose-500" />}
            <span className="text-lg font-semibold">{health.error ? 'offline' : (health.data?.status ?? '…')}</span>
          </div>
        </Card>
        <Card title={t('dashboard.version')}>
          <span className="font-mono text-lg">{health.data?.version ?? '-'}</span>
        </Card>
        <Card title={t('dashboard.serverTime')}>
          <span className="text-lg tabular-nums">
            {health.data ? new Date(health.data.time).toLocaleString(lang) : '-'}
          </span>
        </Card>
      </div>

      <Card
        title={
          <Link to="/detectors" className="hover:underline">
            {t('menu.detectors')}
          </Link>
        }
        actions={<RefreshButton onClick={detectors.reload} loading={detectors.loading} />}
      >
        {detectors.error ? (
          <ErrorBox error={detectors.error} />
        ) : (
          <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {detectors.data?.items.map((d) => (
              <li key={d.name}>
                <Link
                  to={`/detectors/${encodeURIComponent(d.name)}`}
                  className="flex items-start gap-2 rounded-lg border border-slate-200 px-3 py-2 transition-colors hover:border-blue-400 dark:border-slate-800 dark:hover:border-blue-500/60"
                >
                  <StatusIcon status={d.lastError ? 'fail' : d.lastRunAt ? 'ok' : 'warn'} className="mt-0.5 size-4" />
                  <div className="min-w-0">
                    <div className="text-sm font-medium">{detectorLabel(t, d.name)}</div>
                    <div className="truncate text-xs text-slate-500 dark:text-slate-400" title={d.lastError || d.summary}>
                      {d.lastError || d.summary || t('detectors.notRun')}
                    </div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card
        title={
          <>
            {t('dashboard.recentEvents')}
            {events.data && (
              <span className="ml-2 font-normal text-slate-500">{t('common.total', { count: events.data.total })}</span>
            )}
          </>
        }
        actions={<RefreshButton onClick={events.reload} loading={events.loading} />}
      >
        {events.error ? <ErrorBox error={events.error} /> : events.data ? <EventTable items={events.data.items} /> : <Loading />}
      </Card>
    </div>
  )
}

function Loading() {
  const { t } = useI18n()
  return <p className="py-6 text-center text-sm text-slate-500">{t('common.loading')}</p>
}
