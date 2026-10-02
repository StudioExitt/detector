import { useCallback, useState } from 'react'
import LineChart from '../components/LineChart'
import { levelOf, RangePicker, rangeStepMs, StatTile, toChartSeries } from '../components/monitor'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { api, type MetricRange, type ProcUsage } from '../lib/api'
import { bytes, duration, pct } from '../lib/format'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import EventsPage from './EventsPage'

export default function SystemPage() {
  const { t, lang } = useI18n()
  const [range, setRange] = useState<MetricRange>('1h')
  const status = useFetch((s) => api.systemStatus(s), [])
  const metrics = useFetch((s) => api.metrics(['cpu.usage', 'mem.used_pct', 'disk.used_pct', 'cpu.load1'], range, s), [range])
  const reload = useCallback(() => {
    status.reload()
    metrics.reload()
  }, [status.reload, metrics.reload])
  useInterval(reload, 15000)

  const st = status.data
  const pressureLevel = st?.memory.pressure === 'critical' ? 'fail' : st?.memory.pressure === 'warn' ? 'warn' : 'ok'

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
            label="CPU"
            value={pct(st.cpu.usagePct)}
            meter={st.cpu.usagePct}
            status={levelOf(st.cpu.usagePct, 75, 90)}
            statusText={t(`level.${levelOf(st.cpu.usagePct, 75, 90)}`)}
            sub={t('monitor.load', { l1: st.cpu.load1.toFixed(2), l5: st.cpu.load5.toFixed(2), l15: st.cpu.load15.toFixed(2), cores: st.cpu.cores })}
          />
          <StatTile
            label={t('monitor.memory')}
            value={pct(st.memory.usedPct)}
            meter={st.memory.usedPct}
            status={pressureLevel}
            statusText={t('monitor.pressure', { p: t(`pressure.${pressureKey(st.memory.pressure)}`) })}
            sub={`${bytes(st.memory.used)} / ${bytes(st.memory.total)}`}
          />
          <StatTile
            label={t('monitor.swap')}
            value={bytes(st.memory.swapUsed)}
            meter={st.memory.swapTotal ? (st.memory.swapUsed / st.memory.swapTotal) * 100 : 0}
            sub={t('monitor.of', { total: bytes(st.memory.swapTotal) })}
          />
          {st.disks.map((d) => (
            <StatTile
              key={d.mount}
              label={t('monitor.disk', { mount: d.mount })}
              value={pct(d.usedPct)}
              meter={d.usedPct}
              status={levelOf(d.usedPct, 90, 95)}
              statusText={t(`level.${levelOf(d.usedPct, 90, 95)}`)}
              sub={t('monitor.free', { free: bytes(d.free), total: bytes(d.total) })}
            />
          ))}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t('monitor.chart.usage')}>
          {metrics.error ? (
            <ErrorBox error={metrics.error} />
          ) : (
            <LineChart
              series={toChartSeries(metrics.data, [
                { name: 'cpu.usage', label: 'CPU', slot: 1 },
                { name: 'mem.used_pct', label: t('monitor.memory'), slot: 2 },
                { name: 'disk.used_pct', label: t('monitor.diskShort'), slot: 3 },
              ])}
              format={pct}
              yMax={100}
              stepMs={rangeStepMs[range]}
            />
          )}
        </Card>
        <Card title={t('monitor.chart.load')}>
          <LineChart
            series={toChartSeries(metrics.data, [{ name: 'cpu.load1', label: 'load 1m', slot: 1 }])}
            format={(v) => v.toFixed(v >= 10 ? 0 : 2)}
            stepMs={rangeStepMs[range]}
          />
        </Card>
      </div>

      {st && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={t('monitor.topCpu')}>
            <ProcTable procs={st.topCpu} at={st.at} />
          </Card>
          <Card title={t('monitor.topMem')}>
            <ProcTable procs={st.topMem} at={st.at} />
          </Card>
        </div>
      )}

      <h2 className="pt-2 text-sm font-semibold">{t('monitor.events')}</h2>
      <EventsPage category="resource_abuse" />
    </div>
  )
}

function ProcTable({ procs, at }: { procs: ProcUsage[]; at: string }) {
  const { t } = useI18n()
  const th = 'px-3 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400'
  return (
    <div className="-mx-4 overflow-x-auto">
      <table className="w-full min-w-[440px] text-sm">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-800">
            <th className={`${th} pl-4`}>{t('monitor.proc')}</th>
            <th className={`${th} text-right`}>CPU</th>
            <th className={`${th} text-right`}>{t('monitor.memory')}</th>
            <th className={`${th} pr-4`}>{t('monitor.user')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {procs.map((p) => (
            <tr key={p.pid} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
              <td className="max-w-52 px-3 py-1.5 pl-4">
                <div className="truncate font-medium" title={p.exe}>
                  {p.name} <span className="font-normal text-slate-500">({p.pid})</span>
                </div>
                {p.highSince && (
                  <div className="text-xs text-amber-700 dark:text-amber-400">⚠ {t('monitor.highFor', { d: duration(p.highSince, new Date(at).getTime()) })}</div>
                )}
              </td>
              <td className="px-3 py-1.5 text-right whitespace-nowrap tabular-nums">{pct(p.cpuPct)}</td>
              <td className="px-3 py-1.5 text-right whitespace-nowrap tabular-nums">{bytes(p.rss)}</td>
              <td className="max-w-28 truncate px-3 py-1.5 pr-4 text-slate-600 dark:text-slate-400" title={p.user}>
                {p.user}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function pressureKey(p: string): 'normal' | 'warn' | 'critical' {
  return p === 'warn' || p === 'critical' ? p : 'normal'
}
