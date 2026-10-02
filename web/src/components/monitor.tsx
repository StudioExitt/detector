import type { ReactNode } from 'react'
import { useI18n } from '../i18n'
import type { MetricRange, MetricSeriesList } from '../lib/api'
import type { ChartSeries } from './LineChart'
import StatusIcon from './StatusIcon'

const RANGES: MetricRange[] = ['1h', '6h', '24h', '7d']

export function RangePicker({ value, onChange }: { value: MetricRange; onChange: (r: MetricRange) => void }) {
  const { t } = useI18n()
  return (
    <div className="inline-flex rounded-lg border border-slate-200 p-0.5 text-xs dark:border-slate-700" role="group" aria-label={t('chart.range')}>
      {RANGES.map((r) => (
        <button
          key={r}
          type="button"
          onClick={() => onChange(r)}
          aria-pressed={value === r}
          className={`rounded-md px-2.5 py-1 font-medium ${
            value === r ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
          }`}
        >
          {r}
        </button>
      ))}
    </div>
  )
}

/** Headline number tile; status is shown with an icon + text, never color alone. */
export function StatTile({
  label,
  value,
  sub,
  status,
  statusText,
  meter,
}: {
  label: string
  value: ReactNode
  sub?: ReactNode
  status?: 'ok' | 'warn' | 'fail'
  statusText?: string
  meter?: number // 0..100
}) {
  const bar = status === 'fail' ? 'bg-rose-500' : status === 'warn' ? 'bg-amber-500' : 'bg-blue-500'
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
        <span>{label}</span>
        {status && (
          <span className="inline-flex items-center gap-1">
            <StatusIcon status={status} className="size-3.5" />
            {statusText}
          </span>
        )}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {meter !== undefined && (
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" role="meter" aria-valuenow={Math.round(meter)} aria-valuemin={0} aria-valuemax={100}>
          <div className={`h-full rounded-full ${bar}`} style={{ width: `${Math.min(100, Math.max(0, meter))}%` }} />
        </div>
      )}
      {sub && <div className="mt-1.5 truncate text-xs text-slate-500 dark:text-slate-400">{sub}</div>}
    </div>
  )
}

/** Maps API series to chart series; colors follow the metric (entity), in fixed slot order. */
export function toChartSeries(
  data: MetricSeriesList | null,
  defs: { name: string; label: string; slot: 1 | 2 | 3; scale?: number }[],
): ChartSeries[] {
  return defs.map((d) => ({
    key: d.name,
    label: d.label,
    color: `var(--series-${d.slot})`,
    points: (data?.items.find((s) => s.name === d.name)?.points ?? []).map((p) => ({ t: new Date(p.t).getTime(), v: p.v * (d.scale ?? 1) })),
  }))
}

export const rangeStepMs: Record<MetricRange, number> = { '1h': 15e3, '6h': 90e3, '24h': 360e3, '7d': 2520e3 }

export function levelOf(v: number, warn: number, fail: number): 'ok' | 'warn' | 'fail' {
  return v >= fail ? 'fail' : v >= warn ? 'warn' : 'ok'
}
