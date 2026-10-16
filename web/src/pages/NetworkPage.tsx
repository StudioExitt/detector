import { useCallback, useMemo, useRef, useState } from 'react'
import { List, Search, X } from 'lucide-react'
import LineChart from '../components/LineChart'
import { RangePicker, rangeStepMs, StatTile, toChartSeries } from '../components/monitor'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { api, type MetricRange, type NetworkStatus } from '../lib/api'
import { bytes, rate } from '../lib/format'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import EventsPage from './EventsPage'

export default function NetworkPage() {
  const { t, lang } = useI18n()
  const [range, setRange] = useState<MetricRange>('1h')
  const status = useFetch((s) => api.networkStatus(s), [])
  const metrics = useFetch((s) => api.metrics(['net.rx_bps', 'net.tx_bps', 'net.latency_ms', 'net.external'], range, s), [range])
  const reload = useCallback(() => {
    status.reload()
    metrics.reload()
  }, [status.reload, metrics.reload])
  useInterval(reload, 15000)

  const st = status.data
  const step = rangeStepMs[range]
  const listRef = useRef<HTMLDivElement>(null)
  const [procFilter, setProcFilter] = useState<{ pid: number; name: string } | null>(null)
  const showList = (proc: { pid: number; name: string } | null) => {
    setProcFilter(proc)
    listRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {st ? t('monitor.sampledAt', { time: new Date(st.at).toLocaleTimeString(lang) }) : ''}
        </span>
        <span className="ml-auto flex items-center gap-2">
          <RangePicker value={range} onChange={setRange} />
          <RefreshButton onClick={reload} loading={status.loading} />
        </span>
      </div>

      {status.error && <ErrorBox error={status.error} />}

      {st && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatTile
            label={t('net.internet')}
            value={st.internet.reachable ? `${st.internet.latencyMs.toFixed(0)} ms` : st.internet.target ? t('net.down') : '-'}
            status={st.internet.reachable ? 'ok' : st.internet.target ? 'fail' : undefined}
            statusText={st.internet.reachable ? t('net.up') : t('net.down')}
            sub={st.internet.error ?? st.internet.target}
          />
          <StatTile
            label={t('net.traffic')}
            value={<span className="text-lg">↓ {rate(st.rxBps)}</span>}
            sub={`↑ ${rate(st.txBps)}`}
          />
          <button
            type="button"
            onClick={() => showList(null)}
            className="group rounded-xl text-left focus-visible:outline-2 focus-visible:outline-blue-500"
            title={t('net.showList')}
          >
            <StatTile
              label={t('net.connections')}
              value={st.established}
              sub={
                <span className="flex items-center justify-between gap-2">
                  {t('net.externalCount', { n: st.external, procs: st.processes.length })}
                  <span className="inline-flex shrink-0 items-center gap-0.5 font-medium text-blue-600 group-hover:underline dark:text-blue-400">
                    <List className="size-3.5" />
                    {t('net.showList')}
                  </span>
                </span>
              }
            />
          </button>
          <StatTile
            label={t('net.proxy')}
            value={<span className="text-lg">{st.proxies.length ? t('net.proxySet') : t('net.proxyNone')}</span>}
            status={st.proxies.length ? 'warn' : 'ok'}
            statusText={st.proxies.length ? t('level.warn') : t('level.ok')}
            sub={st.proxies.join(', ') || '-'}
          />
        </div>
      )}

      {st && (
        <Card title={t('net.config')}>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
            <Item label={t('net.gateway')} value={`${st.gateway || '-'}${st.gatewayMac ? ` (${st.gatewayMac})` : ''} · ${st.interface || '-'}`} />
            <Item label="DNS" value={st.dns.join(', ') || '-'} />
            <Item
              label={t('net.interfaces')}
              value={st.interfaces
                .filter((i) => !i.name.startsWith('lo'))
                .map((i) => `${i.name} ${i.addrs.filter((a) => !a.startsWith('fe80')).join(' ')}`)
                .join(' · ')}
            />
          </dl>
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t('net.chart.traffic')}>
          {metrics.error ? (
            <ErrorBox error={metrics.error} />
          ) : (
            <LineChart
              series={toChartSeries(metrics.data, [
                { name: 'net.rx_bps', label: t('net.rx'), slot: 1 },
                { name: 'net.tx_bps', label: t('net.tx'), slot: 2 },
              ])}
              format={(v) => rate(v)}
              height={330}
              minTop={1024}
              stepMs={step}
            />
          )}
        </Card>
        <div className="grid min-w-0 gap-4">
          <Card title={t('net.chart.latency')}>
            <LineChart series={toChartSeries(metrics.data, [{ name: 'net.latency_ms', label: 'ms', slot: 1 }])} format={(v) => `${v.toFixed(0)}ms`} height={130} minTop={10} stepMs={step} />
          </Card>
          <Card title={t('net.chart.external')}>
            <LineChart series={toChartSeries(metrics.data, [{ name: 'net.external', label: t('net.connections'), slot: 1 }])} format={(v) => v.toFixed(0)} height={130} stepMs={step} />
          </Card>
        </div>
      </div>

      {st && (
        <Card title={t('net.byProcess')}>
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <th className="px-3 py-2 pl-4 font-medium">{t('monitor.proc')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('net.col.conns')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('net.col.external')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('net.col.hosts')}</th>
                  <th className="px-3 py-2 font-medium">{t('net.col.ports')}</th>
                  <th className="px-3 py-2 font-medium">{t('net.col.remote')}</th>
                  <th className="px-3 py-2 pr-4 text-right font-medium">↑ / ↓</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {st.processes.slice(0, 50).map((p) => (
                  <tr
                    key={`${p.pid}-${p.exe}`}
                    onClick={() => showList({ pid: p.pid, name: p.name || '?' })}
                    title={t('net.showList')}
                    className={`cursor-pointer ${p.flags.length ? 'bg-amber-50/60 hover:bg-amber-100/60 dark:bg-amber-500/5 dark:hover:bg-amber-500/10' : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'}`}
                  >
                    <td className="max-w-64 px-3 py-1.5 pl-4">
                      <div className="truncate font-medium" title={p.exe}>
                        {p.name || '?'} <span className="font-normal text-slate-500">({p.pid})</span>
                      </div>
                      {p.flags.length > 0 && <div className="text-xs text-amber-700 dark:text-amber-400">⚠ {p.flags.join(', ')}</div>}
                    </td>
                    <td className="px-3 py-1.5 text-right tabular-nums">{p.conns}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums">{p.external}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums">{p.hosts}</td>
                    <td className="px-3 py-1.5 font-mono text-xs">{p.ports.slice(0, 6).join(', ') || '-'}</td>
                    <td className="max-w-64 truncate px-3 py-1.5 font-mono text-xs" title={p.sample.join('\n')}>
                      {p.sample.join(', ') || '-'}
                    </td>
                    <td className="px-3 py-1.5 pr-4 text-right text-xs whitespace-nowrap tabular-nums">
                      {p.txBytes || p.rxBytes ? `${bytes(p.txBytes)} / ${bytes(p.rxBytes)}` : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <div ref={listRef} className="scroll-mt-4">
        {st && <ConnectionList status={st} proc={procFilter} onClearProc={() => setProcFilter(null)} />}
      </div>

      <h2 className="pt-2 text-sm font-semibold">{t('monitor.events')}</h2>
      <EventsPage detector="network" />
    </div>
  )
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="font-mono text-xs break-all">{value}</dd>
    </div>
  )
}

type Scope = 'all' | 'public' | 'private' | 'loopback'
type StateFilter = 'established' | 'other' | 'all'

function ConnectionList({
  status,
  proc,
  onClearProc,
}: {
  status: NetworkStatus
  proc: { pid: number; name: string } | null
  onClearProc: () => void
}) {
  const { t } = useI18n()
  const [scope, setScope] = useState<Scope>('all')
  const [state, setState] = useState<StateFilter>('established')
  const [q, setQ] = useState('')

  const all = status.connections
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return all.filter(
      (c) =>
        (!proc || c.pid === proc.pid) &&
        (scope === 'all' || c.scope === scope) &&
        (state === 'all' || (state === 'established') === (c.state === 'ESTABLISHED')) &&
        (!needle ||
          c.process.toLowerCase().includes(needle) ||
          c.remote.toLowerCase().includes(needle) ||
          c.local.toLowerCase().includes(needle) ||
          String(c.pid) === needle),
    )
  }, [all, proc, scope, state, q])

  const seg = (active: boolean) =>
    `rounded-md px-2 py-1 text-xs font-medium ${
      active ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
    }`
  const scopeBadge: Record<string, string> = {
    public: 'bg-blue-100 text-blue-800 dark:bg-blue-500/15 dark:text-blue-300',
    private: 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300',
    loopback: 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
  }

  return (
    <Card title={t('net.list.title')} actions={<span className="text-xs text-slate-500">{t('net.list.shown', { shown: rows.length, total: all.length })}</span>}>
      <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('net.list.hint')}</p>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-lg border border-slate-200 p-0.5 dark:border-slate-700" role="group" aria-label={t('net.list.scope')}>
          {(['all', 'public', 'private', 'loopback'] as const).map((s) => (
            <button key={s} type="button" aria-pressed={scope === s} onClick={() => setScope(s)} className={seg(scope === s)}>
              {t(`net.scope.${s}`)}
            </button>
          ))}
        </div>
        <div className="inline-flex rounded-lg border border-slate-200 p-0.5 dark:border-slate-700" role="group" aria-label={t('net.list.state')}>
          {(['established', 'other', 'all'] as const).map((s) => (
            <button key={s} type="button" aria-pressed={state === s} onClick={() => setState(s)} className={seg(state === s)}>
              {t(`net.state.${s}`)}
            </button>
          ))}
        </div>
        {proc && (
          <span className="inline-flex items-center gap-1 rounded-lg bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 dark:bg-blue-500/15 dark:text-blue-300">
            {t('net.list.proc', { name: proc.name, pid: proc.pid })}
            <button type="button" onClick={onClearProc} aria-label={t('net.list.clear')} className="rounded hover:bg-blue-100 dark:hover:bg-blue-500/20">
              <X className="size-3.5" />
            </button>
          </span>
        )}
        <label className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-slate-400" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t('net.list.search')}
            className="h-8 w-full rounded-lg border border-slate-200 bg-transparent pr-3 pl-8 text-xs outline-none focus:border-blue-500 dark:border-slate-700"
          />
        </label>
      </div>

      {rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-slate-500">{t('net.list.empty')}</p>
      ) : (
        <div className="-mx-4 max-h-[32rem] overflow-auto">
          <table className="w-full min-w-[820px] text-sm">
            <thead className="sticky top-0 bg-white dark:bg-slate-900">
              <tr className="border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="px-3 py-2 pl-4 font-medium">{t('monitor.proc')}</th>
                <th className="px-3 py-2 font-medium">{t('net.list.local')}</th>
                <th className="px-3 py-2 font-medium">{t('net.col.remote')}</th>
                <th className="px-3 py-2 font-medium">{t('net.list.scope')}</th>
                <th className="px-3 py-2 font-medium">{t('net.list.state')}</th>
                <th className="px-3 py-2 pr-4 text-right font-medium">↑ / ↓</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((c, i) => (
                <tr key={`${c.local}-${c.remote}-${c.pid}-${i}`} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <td className="max-w-56 truncate px-3 py-1.5 pl-4" title={c.process}>
                    <span className="font-medium">{c.process || '?'}</span> <span className="text-slate-500">({c.pid || '-'})</span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">{c.local}</td>
                  <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">{c.remote}</td>
                  <td className="px-3 py-1.5">
                    <span className={`rounded-md px-1.5 py-0.5 text-xs ${scopeBadge[c.scope] ?? scopeBadge.private}`}>
                      {t(`net.scope.${(['public', 'private', 'loopback'].includes(c.scope) ? c.scope : 'private') as 'public' | 'private' | 'loopback'}`)}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">{c.state}</td>
                  <td className="px-3 py-1.5 pr-4 text-right text-xs whitespace-nowrap tabular-nums">
                    {c.txBytes || c.rxBytes ? `${bytes(c.txBytes)} / ${bytes(c.rxBytes)}` : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
