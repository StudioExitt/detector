import { Fragment, useCallback, useState, type ReactNode } from 'react'
import { ArrowLeft, ChevronRight, Clock, Timer } from 'lucide-react'
import { Link, useParams, useSearchParams } from 'react-router'
import CheckTable from '../components/CheckTable'
import ClipboardTestPanel from '../components/ClipboardTestPanel'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, Pager, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { ApiError, api, type DetectorRun } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import { detectorLabel } from './DetectorsPage'
import EventsPage from './EventsPage'

const TABS = ['checks', 'runs', 'events'] as const
type Tab = (typeof TABS)[number]
const RUNS_PAGE = 50

export default function DetectorDetailPage() {
  const { name = '' } = useParams()
  const { t, lang } = useI18n()
  const [params, setParams] = useSearchParams()
  const tab: Tab = TABS.includes(params.get('tab') as Tab) ? (params.get('tab') as Tab) : 'checks'

  const detail = useFetch((s) => api.detector(name, s), [name])
  const runsHead = useFetch((s) => api.detectorRuns(name, { limit: 1 }, s), [name])
  const reloadAll = useCallback(() => {
    detail.reload()
    runsHead.reload()
  }, [detail.reload, runsHead.reload])
  useInterval(reloadAll, 15000)

  if (detail.error instanceof ApiError && detail.error.status === 404) {
    return (
      <div className="space-y-4">
        <BackLink />
        <ErrorBox error={new Error(t('detectors.notFound', { name }))} />
      </div>
    )
  }

  const st = detail.data?.status
  const state = st?.lastError ? 'fail' : st?.lastRunAt ? 'ok' : 'warn'

  return (
    <div className="space-y-4">
      <BackLink />

      <div className="flex flex-wrap items-center gap-3">
        {st && <StatusIcon status={state} className="size-6" />}
        <h2 className="text-xl font-semibold">{detectorLabel(t, name)}</h2>
        <span className="font-mono text-sm text-slate-500">{name}</span>
        {detail.data && (
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {detail.data.platform} · {detail.data.host}
          </span>
        )}
        <span className="ml-auto">
          <RefreshButton onClick={reloadAll} loading={detail.loading} />
        </span>
      </div>

      {detail.error && <ErrorBox error={detail.error} />}

      {st && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Tile label={t('detectors.interval')} value={`${st.intervalSeconds}s`} />
          <Tile
            label={t('detectors.lastRun')}
            value={st.lastRunAt ? new Date(st.lastRunAt).toLocaleTimeString(lang) : '-'}
            icon={<Clock className="size-3.5" />}
          />
          <Tile
            label={t('detectors.duration')}
            value={st.lastDurationMs != null ? `${st.lastDurationMs}ms` : '-'}
            icon={<Timer className="size-3.5" />}
          />
          <Tile label={t('detectors.findings')} value={String(st.findings)} />
          <Tile label={t('detectors.totalRuns')} value={runsHead.data ? String(runsHead.data.total) : '-'} />
        </div>
      )}

      {st && (st.summary || st.lastError) && (
        <Card>
          {st.summary && <p className="text-sm">{st.summary}</p>}
          {st.lastError && (
            <p className="mt-2 rounded-lg bg-rose-50 px-3 py-2 font-mono text-xs break-all text-rose-700 dark:bg-rose-500/10 dark:text-rose-300">
              {st.lastError}
            </p>
          )}
        </Card>
      )}

      {detail.data && detail.data.sources.length > 0 && (
        <Card title={t('detectors.sources')}>
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-300">
            {detail.data.sources.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </Card>
      )}

      {name === 'clipboard' && st && !st.lastError && <ClipboardTestPanel onDone={reloadAll} />}

      <div className="flex gap-1 border-b border-slate-200 dark:border-slate-800" role="tablist">
        {TABS.map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={tab === k}
            onClick={() => setParams(k === 'checks' ? {} : { tab: k }, { replace: true })}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${
              tab === k
                ? 'border-blue-600 text-blue-700 dark:border-blue-400 dark:text-blue-300'
                : 'border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
            }`}
          >
            {t(`detectors.tab.${k}`)}
          </button>
        ))}
      </div>

      {tab === 'checks' && st && (
        <Card>
          <CheckTable checks={st.checks} />
        </Card>
      )}
      {tab === 'runs' && (
        <RunsPanel
          name={name}
          compactSuccess={!!st?.compactSuccessRuns}
          lastRunAt={st?.lastRunAt}
          onRefresh={detail.reload}
        />
      )}
      {tab === 'events' && <EventsPage detector={name} />}
    </div>
  )
}

function BackLink() {
  const { t } = useI18n()
  return (
    <Link
      to="/detectors"
      className="inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
    >
      <ArrowLeft className="size-4" />
      {t('detectors.back')}
    </Link>
  )
}

function Tile({ label, value, icon }: { label: string; value: string; icon?: ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className="mt-1 flex items-center gap-1.5 text-lg font-semibold tabular-nums">
        {icon}
        {value}
      </div>
    </div>
  )
}

function RunsPanel({
  name,
  compactSuccess,
  lastRunAt,
  onRefresh,
}: {
  name: string
  compactSuccess: boolean
  lastRunAt?: string
  onRefresh: () => void
}) {
  const { t, lang } = useI18n()
  const [page, setPage] = useState(0)
  const [openId, setOpenId] = useState<number | null>(null)
  const { data, error, loading, reload } = useFetch(
    (s) => api.detectorRuns(name, { limit: RUNS_PAGE, offset: page * RUNS_PAGE }, s),
    [name, page],
  )
  const lastPage = data ? Math.max(0, Math.ceil(data.total / RUNS_PAGE) - 1) : 0
  const fmt = new Intl.DateTimeFormat(lang, { dateStyle: 'short', timeStyle: 'medium' })
  const th = 'px-3 py-2 text-left text-xs font-medium whitespace-nowrap text-slate-500 dark:text-slate-400'

  const refresh = () => {
    reload()
    onRefresh() // also refreshes the last run time shown below
  }

  return (
    <Card
      title={data ? t('common.total', { count: data.total }) : t('common.loading')}
      actions={<RefreshButton onClick={refresh} loading={loading} />}
    >
      {compactSuccess && (
        <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg bg-slate-50 px-3 py-2 text-xs dark:bg-slate-800/60">
          <span className="text-slate-600 dark:text-slate-400">{t('detectors.run.compactSuccess')}</span>
          {lastRunAt && (
            <span className="inline-flex items-center gap-1 font-medium">
              <StatusIcon status="ok" className="size-3.5" />
              {t('detectors.run.lastRun', { time: new Date(lastRunAt).toLocaleString(lang) })}
            </span>
          )}
        </div>
      )}
      {error && <ErrorBox error={error} />}
      {data && data.items.length === 0 && <p className="py-6 text-center text-sm text-slate-500">{t('common.empty')}</p>}
      {data && data.items.length > 0 && (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800">
                <th className={`${th} w-8 pl-4`} />
                <th className={th}>{t('detectors.run.startedAt')}</th>
                <th className={th}>{t('detectors.run.result')}</th>
                <th className={th}>{t('detectors.duration')}</th>
                <th className={th}>{t('detectors.run.checks')}</th>
                <th className={th}>{t('detectors.run.findings')}</th>
                <th className={`${th} pr-4`}>{t('detectors.run.summary')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.items.map((r) => {
                const open = openId === r.id
                return (
                  <Fragment key={r.id}>
                    <tr
                      onClick={() => setOpenId(open ? null : r.id)}
                      className={`cursor-pointer align-top hover:bg-slate-50 dark:hover:bg-slate-800/50 ${
                        open ? 'bg-slate-50 dark:bg-slate-800/50' : ''
                      }`}
                    >
                      <td className="py-2 pl-4">
                        <ChevronRight className={`size-4 text-slate-400 transition-transform ${open ? 'rotate-90' : ''}`} />
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap tabular-nums">{fmt.format(new Date(r.startedAt))}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                          <StatusIcon status={r.error ? 'fail' : 'ok'} className="size-3.5" />
                          {r.error ? t('detectors.error') : t('detectors.run.ok')}
                        </span>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap tabular-nums">{r.durationMs}ms</td>
                      <td className="px-3 py-2 whitespace-nowrap tabular-nums">
                        <span className="text-emerald-600 dark:text-emerald-400">{r.checksOk}</span>
                        {' / '}
                        <span className={r.checksWarn ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400'}>{r.checksWarn}</span>
                        {' / '}
                        <span className={r.checksFail ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}>{r.checksFail}</span>
                      </td>
                      <td className="px-3 py-2 tabular-nums">
                        {r.findings > 0 ? (
                          <span className="rounded-md bg-rose-100 px-2 py-0.5 text-xs font-semibold text-rose-700 dark:bg-rose-500/15 dark:text-rose-300">
                            {r.findings}
                          </span>
                        ) : (
                          <span className="text-slate-400">0</span>
                        )}
                      </td>
                      <td className="px-3 py-2 pr-4 [overflow-wrap:anywhere]">
                        {r.summary}
                        {r.error && <div className="mt-0.5 font-mono text-xs text-rose-600 dark:text-rose-400">{r.error}</div>}
                      </td>
                    </tr>
                    {open && (
                      <tr>
                        <td colSpan={7} className="bg-slate-50/60 px-4 py-3 dark:bg-slate-900/60">
                          <RunChecks name={name} run={r} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pager page={page} lastPage={lastPage} onChange={setPage} />
    </Card>
  )
}

function RunChecks({ name, run }: { name: string; run: DetectorRun }) {
  const { t, lang } = useI18n()
  const { data, error } = useFetch((s) => api.detectorRun(name, run.id, s), [name, run.id])
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
        {t('detectors.run.checksAt', { time: new Date(run.startedAt).toLocaleString(lang) })}
      </div>
      {error && <ErrorBox error={error} />}
      {data ? <CheckTable checks={data.checks ?? []} /> : !error && <p className="text-xs text-slate-500">{t('common.loading')}</p>}
    </div>
  )
}
