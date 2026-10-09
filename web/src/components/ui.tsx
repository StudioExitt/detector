import type { ReactNode } from 'react'
import { RefreshCw, ServerCrash } from 'lucide-react'
import { useI18n } from '../i18n'
import type { EventSeverity } from '../lib/api'

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      {(title || actions) && (
        <div className="flex items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold">{title}</h2>
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function RefreshButton({ onClick, loading }: { onClick: () => void; loading?: boolean }) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
    >
      <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
      {t('common.refresh')}
    </button>
  )
}

export function ErrorBox({ error }: { error: Error }) {
  const { t } = useI18n()
  return (
    <div className="flex items-center gap-2 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:bg-rose-500/10 dark:text-rose-300">
      <ServerCrash className="size-4 shrink-0" />
      <span>
        {t('common.error')}: {error.message}
      </span>
    </div>
  )
}

const severityStyle: Record<EventSeverity, string> = {
  low: 'bg-slate-100 text-slate-700 dark:bg-slate-700/40 dark:text-slate-300',
  medium: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-500/15 dark:text-orange-300',
  critical: 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300',
}

export function SeverityBadge({ severity }: { severity: EventSeverity }) {
  const { t } = useI18n()
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${severityStyle[severity]}`}>
      {t(`severity.${severity}`)}
    </span>
  )
}

export function Pager({ page, lastPage, onChange }: { page: number; lastPage: number; onChange: (p: number) => void }) {
  const { t } = useI18n()
  if (lastPage <= 0) return null
  const btn =
    'rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium hover:bg-slate-100 disabled:opacity-40 disabled:hover:bg-transparent dark:border-slate-700 dark:hover:bg-slate-800'
  return (
    <div className="mt-4 flex items-center justify-end gap-2 text-sm">
      <button type="button" className={btn} disabled={page === 0} onClick={() => onChange(page - 1)}>
        {t('common.prev')}
      </button>
      <span className="tabular-nums">
        {page + 1} / {lastPage + 1}
      </span>
      <button type="button" className={btn} disabled={page >= lastPage} onClick={() => onChange(page + 1)}>
        {t('common.next')}
      </button>
    </div>
  )
}
