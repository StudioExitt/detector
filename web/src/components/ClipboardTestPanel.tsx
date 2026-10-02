import { useState } from 'react'
import { ClipboardCheck, LoaderCircle, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useI18n } from '../i18n'
import { api, type ClipboardTestResult } from '../lib/api'
import { Card, ErrorBox } from './ui'

export default function ClipboardTestPanel({ onDone }: { onDone?: () => void }) {
  const { t } = useI18n()
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<ClipboardTestResult | null>(null)
  const [error, setError] = useState<Error | null>(null)

  const run = async () => {
    setRunning(true)
    setError(null)
    try {
      setResult(await api.clipboardTest())
      onDone?.()
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)))
    } finally {
      setRunning(false)
    }
  }

  return (
    <Card
      title={t('clip.title')}
      actions={
        <button
          type="button"
          onClick={run}
          disabled={running}
          className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-60"
        >
          {running ? <LoaderCircle className="size-3.5 animate-spin" /> : <ClipboardCheck className="size-3.5" />}
          {running ? t('clip.running') : t('clip.run')}
        </button>
      }
    >
      <p className="text-sm">{t('clip.desc')}</p>
      <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">{t('clip.warn')}</p>

      {error && (
        <div className="mt-3">
          <ErrorBox error={error} />
        </div>
      )}

      {result && (
        <div className="mt-4 space-y-3">
          <div
            className={`flex items-start gap-2 rounded-lg px-3 py-2 text-sm font-medium ${
              result.swapped
                ? 'bg-rose-50 text-rose-800 dark:bg-rose-500/10 dark:text-rose-300'
                : 'bg-emerald-50 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300'
            }`}
          >
            {result.swapped ? <ShieldAlert className="mt-0.5 size-4 shrink-0" /> : <ShieldCheck className="mt-0.5 size-4 shrink-0" />}
            <span>{result.swapped ? t('clip.swapped') : t('clip.clean')}</span>
          </div>
          <p className={`text-xs ${result.restored ? 'text-slate-500 dark:text-slate-400' : 'text-rose-600 dark:text-rose-400'}`}>
            {result.restored ? `✓ ${t('clip.restored')}` : t('clip.restoreFailed')} · {result.durationMs}ms
            {result.note && ` · ${result.note}`}
          </p>
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[640px] text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-left text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <th className="px-3 py-2 pl-4 font-medium">{t('clip.chain')}</th>
                  <th className="px-3 py-2 font-medium">{t('clip.canary')}</th>
                  <th className="px-3 py-2 font-medium">{t('clip.observed')}</th>
                  <th className="px-3 py-2 pr-4 font-medium">{t('clip.after')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono dark:divide-slate-800">
                {result.checks.map((c) => (
                  <tr key={c.canary} className={c.swapped ? 'bg-rose-50/60 dark:bg-rose-500/5' : ''}>
                    <td className="px-3 py-1.5 pl-4 font-sans font-medium uppercase">{c.chain}</td>
                    <td className="px-3 py-1.5 break-all">{c.canary}</td>
                    <td className={`px-3 py-1.5 break-all ${c.swapped ? 'font-semibold text-rose-700 dark:text-rose-300' : 'text-slate-500'}`}>
                      {c.changed ? c.observed : t('clip.unchanged')}
                    </td>
                    <td className="px-3 py-1.5 pr-4 tabular-nums">{c.afterMs != null ? `${c.afterMs}ms` : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Card>
  )
}
