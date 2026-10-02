import { useI18n } from '../i18n'
import type { DetectEvent } from '../lib/api'
import { SeverityBadge } from './ui'

export default function EventTable({ items, showCategory = true }: { items: DetectEvent[]; showCategory?: boolean }) {
  const { t, lang } = useI18n()

  if (items.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('common.empty')}</p>
  }

  const fmt = new Intl.DateTimeFormat(lang, { dateStyle: 'short', timeStyle: 'medium' })
  const th = 'px-3 py-2 text-left text-xs font-medium whitespace-nowrap uppercase tracking-wide text-slate-500 dark:text-slate-400'

  return (
    <div className="-mx-4 overflow-x-auto">
      <table className="w-full min-w-[720px] text-sm">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-800">
            <th className={`${th} pl-4`}>{t('event.detectedAt')}</th>
            {showCategory && <th className={th}>{t('event.category')}</th>}
            <th className={th}>{t('event.severity')}</th>
            <th className={th}>{t('event.source')}</th>
            <th className={`${th} pr-4`}>{t('event.message')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {items.map((e) => (
            <tr key={e.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
              <td className="px-3 py-2 pl-4 whitespace-nowrap tabular-nums">{fmt.format(new Date(e.detectedAt))}</td>
              {showCategory && <td className="px-3 py-2 whitespace-nowrap">{t(`category.${e.category}`)}</td>}
              <td className="px-3 py-2">
                <SeverityBadge severity={e.severity} />
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                <div className="line-clamp-2 w-48 break-all" title={e.source}>
                  {e.source ?? '-'}
                </div>
              </td>
              <td className="min-w-72 px-3 py-2 pr-4 [overflow-wrap:anywhere]">
                <div>{e.message}</div>
                {e.rule && <div className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">{e.rule}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
