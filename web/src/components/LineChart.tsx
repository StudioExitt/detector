import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { Table2 } from 'lucide-react'
import { useI18n } from '../i18n'

export type ChartSeries = {
  key: string
  label: string
  /** CSS color, e.g. var(--series-1) — assigned by entity, in fixed order */
  color: string
  points: { t: number; v: number }[]
}

type Props = {
  series: ChartSeries[]
  /** formats a value for axis, labels and tooltip */
  format: (v: number) => string
  /** fixed y max (e.g. 100 for percentages); otherwise derived from data */
  yMax?: number
  height?: number
  /** expected gap between points (ms); larger gaps break the line */
  stepMs?: number
}

const PAD = { top: 12, right: 72, bottom: 24, left: 52 }

export default function LineChart({ series, format, yMax, height = 220, stepMs }: Props) {
  const { t, lang } = useI18n()
  const wrapRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(600)
  const [hover, setHover] = useState<number | null>(null)
  const [showTable, setShowTable] = useState(false)

  useLayoutEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(280, e.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const all = series.flatMap((s) => s.points)
  const times = useMemo(() => [...new Set(series.flatMap((s) => s.points.map((p) => p.t)))].sort((a, b) => a - b), [series])
  const tMin = times[0] ?? 0
  const tMax = times[times.length - 1] ?? 1
  const dataMax = Math.max(0, ...all.map((p) => p.v))
  const top = yMax ?? niceMax(dataMax)
  const innerW = width - PAD.left - PAD.right
  const innerH = height - PAD.top - PAD.bottom
  const x = (tt: number) => PAD.left + (tMax === tMin ? innerW / 2 : ((tt - tMin) / (tMax - tMin)) * innerW)
  const y = (v: number) => PAD.top + innerH - (Math.min(v, top) / top) * innerH
  const gap = stepMs ?? (times.length > 1 ? (tMax - tMin) / (times.length - 1) : 0)

  const paths = series.map((s) => {
    let d = ''
    s.points.forEach((p, i) => {
      const brk = i === 0 || (gap > 0 && p.t - s.points[i - 1].t > gap * 3)
      d += `${brk ? 'M' : 'L'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`
    })
    return d
  })

  const timeFmt = new Intl.DateTimeFormat(lang, tMax - tMin > 36 * 3600e3 ? { month: 'numeric', day: 'numeric', hour: '2-digit' } : { hour: '2-digit', minute: '2-digit' })
  const fullFmt = new Intl.DateTimeFormat(lang, { dateStyle: 'short', timeStyle: 'medium' })
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * top)
  const xTicks = times.length > 1 ? [0, 0.25, 0.5, 0.75, 1].map((f) => tMin + f * (tMax - tMin)) : times

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    if (!times.length) return
    const rect = e.currentTarget.getBoundingClientRect()
    const tt = tMin + ((e.clientX - rect.left) / rect.width) * (tMax - tMin)
    let best = 0
    for (let i = 1; i < times.length; i++) if (Math.abs(times[i] - tt) < Math.abs(times[best] - tt)) best = i
    setHover(times[best])
  }

  const valueAt = (s: ChartSeries, tt: number) => s.points.find((p) => p.t === tt)?.v

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
        {series.length > 1 &&
          series.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        <button
          type="button"
          onClick={() => setShowTable((v) => !v)}
          className="ml-auto inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800"
          aria-pressed={showTable}
        >
          <Table2 className="size-3.5" />
          {t('chart.table')}
        </button>
      </div>

      <div ref={wrapRef} className="relative">
        {all.length === 0 ? (
          <div className="flex items-center justify-center text-sm text-slate-500" style={{ height }}>
            {t('chart.noData')}
          </div>
        ) : (
          <svg width={width} height={height} className="block overflow-visible" role="img" aria-label={series.map((s) => s.label).join(', ')}>
            {yTicks.map((v) => (
              <g key={v}>
                <line x1={PAD.left} x2={PAD.left + innerW} y1={y(v)} y2={y(v)} className="stroke-slate-200 dark:stroke-slate-800" strokeWidth={1} />
                <text x={PAD.left - 6} y={y(v)} dy="0.32em" textAnchor="end" className="fill-slate-500 text-[10px] tabular-nums dark:fill-slate-400">
                  {format(v)}
                </text>
              </g>
            ))}
            {xTicks.map((tt, i) => (
              <text key={i} x={x(tt)} y={height - 6} textAnchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'} className="fill-slate-500 text-[10px] tabular-nums dark:fill-slate-400">
                {timeFmt.format(tt)}
              </text>
            ))}
            {series.map((s, i) => (
              <path key={s.key} d={paths[i]} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            ))}
            {/* direct labels at the line ends (text in ink, the colored dot carries identity) */}
            {endLabels(series, x, y, format).map((l) => (
              <g key={l.key}>
                <circle cx={l.x} cy={l.py} r={3} fill={l.color} className="stroke-white dark:stroke-slate-900" strokeWidth={2} />
                <text x={l.x + 8} y={l.y} dy="0.32em" className="fill-slate-700 text-[10px] font-medium tabular-nums dark:fill-slate-300">
                  {l.text}
                </text>
              </g>
            ))}
            {hover !== null && (
              <g pointerEvents="none">
                <line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={PAD.top + innerH} className="stroke-slate-400 dark:stroke-slate-500" strokeWidth={1} strokeDasharray="3 3" />
                {series.map((s) => {
                  const v = valueAt(s, hover)
                  return v === undefined ? null : (
                    <circle key={s.key} cx={x(hover)} cy={y(v)} r={4} fill={s.color} className="stroke-white dark:stroke-slate-900" strokeWidth={2} />
                  )
                })}
              </g>
            )}
            <rect
              x={PAD.left}
              y={PAD.top}
              width={innerW}
              height={innerH}
              fill="transparent"
              onPointerMove={onMove}
              onPointerLeave={() => setHover(null)}
            />
          </svg>
        )}
        {hover !== null && (
          <div
            className="pointer-events-none absolute top-1 z-10 min-w-36 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs shadow-md dark:border-slate-700 dark:bg-slate-900"
            style={x(hover) > width / 2 ? { right: width - x(hover) + 10 } : { left: x(hover) + 10 }}
          >
            <div className="mb-1 font-medium tabular-nums">{fullFmt.format(hover)}</div>
            {series.map((s) => {
              const v = valueAt(s, hover)
              return (
                <div key={s.key} className="flex items-center justify-between gap-3">
                  <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
                    <span className="inline-block size-2 rounded-full" style={{ background: s.color }} />
                    {s.label}
                  </span>
                  <span className="font-medium tabular-nums">{v === undefined ? '-' : format(v)}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {showTable && (
        <div className="mt-2 max-h-56 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800">
              <tr>
                <th className="px-2 py-1 text-left font-medium">{t('chart.time')}</th>
                {series.map((s) => (
                  <th key={s.key} className="px-2 py-1 text-right font-medium">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 tabular-nums dark:divide-slate-800">
              {[...times].reverse().map((tt) => (
                <tr key={tt}>
                  <td className="px-2 py-0.5">{fullFmt.format(tt)}</td>
                  {series.map((s) => {
                    const v = valueAt(s, tt)
                    return (
                      <td key={s.key} className="px-2 py-0.5 text-right">
                        {v === undefined ? '-' : format(v)}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function niceMax(v: number) {
  if (v <= 0) return 1
  const p = 10 ** Math.floor(Math.log10(v))
  // tops whose quarter steps are round numbers (e.g. 40 -> 10, 20, 30, 40)
  for (const m of [1, 2, 4, 6, 8, 10]) if (m * p >= v * 1.1) return m * p
  return 10 * p
}

// end-of-line labels, nudged apart vertically so they never overlap
function endLabels(series: ChartSeries[], x: (t: number) => number, y: (v: number) => number, format: (v: number) => string) {
  const labels = series
    .filter((s) => s.points.length > 0)
    .map((s) => {
      const last = s.points[s.points.length - 1]
      const py = y(last.v)
      return { key: s.key, color: s.color, x: x(last.t), py, y: py, text: `${format(last.v)}` }
    })
    .sort((a, b) => a.y - b.y)
  for (let i = 1; i < labels.length; i++) {
    if (labels[i].y - labels[i - 1].y < 12) labels[i].y = labels[i - 1].y + 12
  }
  return labels
}
