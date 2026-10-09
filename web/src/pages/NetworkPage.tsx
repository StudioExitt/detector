import { useCallback, useState } from 'react'
import LineChart from '../components/LineChart'
import { RangePicker, rangeStepMs, StatTile, toChartSeries } from '../components/monitor'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { api, type MetricRange } from '../lib/api'
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
          <StatTile
            label={t('net.connections')}
            value={st.established}
            sub={t('net.externalCount', { n: st.external, procs: st.processes.length })}
          />
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
                  <tr key={`${p.pid}-${p.exe}`} className={p.flags.length ? 'bg-amber-50/60 dark:bg-amber-500/5' : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'}>
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
