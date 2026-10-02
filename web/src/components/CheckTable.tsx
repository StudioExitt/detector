import { useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { useI18n } from '../i18n'
import type { CheckStatus, DetectorCheck } from '../lib/api'
import StatusIcon from './StatusIcon'

const FILTERS: (CheckStatus | 'all')[] = ['all', 'fail', 'warn', 'ok']

// Point-in-time check list with status filter and text search.
export default function CheckTable({ checks }: { checks: DetectorCheck[] }) {
  const { t } = useI18n()
  const [filter, setFilter] = useState<CheckStatus | 'all'>('all')
  const [q, setQ] = useState('')

  const counts = useMemo(() => {
    const c = { all: checks.length, ok: 0, warn: 0, fail: 0 }
    for (const ch of checks) c[ch.status]++
    return c
  }, [checks])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return checks.filter(
      (c) =>
        (filter === 'all' || c.status === filter) &&
        (!needle || c.name.toLowerCase().includes(needle) || c.detail.toLowerCase().includes(needle)),
    )
  }, [checks, filter, q])

  if (checks.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('common.empty')}</p>
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            disabled={f !== 'all' && counts[f] === 0}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium disabled:opacity-40 ${
              filter === f
                ? 'border-blue-500 bg-blue-50 text-blue-700 dark:border-blue-400 dark:bg-blue-500/15 dark:text-blue-300'
                : 'border-slate-200 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800'
            }`}
          >
            {f !== 'all' && <StatusIcon status={f} className="size-3.5" />}
            {f === 'all' ? t('detectors.filter.all') : t(`status.${f}`)}
            <span className="tabular-nums text-slate-500 dark:text-slate-400">{counts[f]}</span>
          </button>
        ))}
        <label className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-slate-400" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t('detectors.search')}
            className="h-8 w-full rounded-lg border border-slate-200 bg-transparent pr-3 pl-8 text-xs outline-none focus:border-blue-500 dark:border-slate-700"
          />
        </label>
      </div>

      <div className="-mx-4 overflow-x-auto">
        <table className="w-full min-w-[560px] text-xs">
          <thead>
            <tr className="border-b border-slate-200 text-left text-slate-500 dark:border-slate-800 dark:text-slate-400">
              <th className="w-24 px-3 py-2 pl-4 font-medium">{t('detectors.check.status')}</th>
              <th className="px-3 py-2 font-medium">{t('detectors.check.name')}</th>
              <th className="px-3 py-2 pr-4 font-medium">{t('detectors.check.detail')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {rows.map((c, i) => (
              <tr key={`${c.name}-${i}`} className="align-top hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <td className="px-3 py-1.5 pl-4">
                  <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                    <StatusIcon status={c.status} className="size-3.5" />
                    {t(`status.${c.status}`)}
                  </span>
                </td>
                <td className="w-1/3 px-3 py-1.5 font-medium [overflow-wrap:anywhere]">{c.name}</td>
                <td className="px-3 py-1.5 pr-4 text-slate-600 [overflow-wrap:anywhere] dark:text-slate-400">{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
