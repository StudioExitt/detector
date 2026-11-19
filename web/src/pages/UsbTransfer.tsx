import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, ArrowRight, Ban, ChevronRight, CornerLeftUp, File, FileAudio, Folder, HardDrive, Monitor, Smartphone } from 'lucide-react'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n, type MessageKey } from '../i18n'
import { api, type UsbFileEntry, type UsbFileLocation, type UsbTransferJob } from '../lib/api'
import { bytes } from '../lib/format'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'

const btn =
  'inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-50'
const btnNormal = `${btn} border-slate-200 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800`
const btnPrimary = `${btn} border-sky-300 bg-sky-50 text-sky-800 hover:bg-sky-100 dark:border-sky-500/40 dark:bg-sky-500/10 dark:text-sky-300 dark:hover:bg-sky-500/20`
const btnWarn = `${btn} border-amber-300 text-amber-800 hover:bg-amber-50 dark:border-amber-500/40 dark:text-amber-300 dark:hover:bg-amber-500/10`

type Crumb = { id: string; name: string }
type PaneState = { loc: string; stack: Crumb[] }
type Side = 'left' | 'right'

const kindIcon = { pc: Monitor, volume: HardDrive, mtp: Smartphone }

function usable(l: UsbFileLocation) {
  return !l.error
}

// default panes: a PC folder on the left, a USB disk / phone on the right
function defaults(locs: UsbFileLocation[]): [string, string] {
  const ok = locs.filter(usable)
  const left = ok.find((l) => l.kind === 'pc') ?? ok[0]
  const right = ok.find((l) => l.kind !== 'pc' && l.id !== left?.id) ?? ok.find((l) => l.id !== left?.id)
  return [left?.id ?? '', right?.id ?? '']
}

export default function UsbTransfer() {
  const { t } = useI18n()
  const locs = useFetch((s) => api.usbFileLocations(s), [])
  const jobs = useFetch((s) => api.usbTransfers(s), [])
  const [mp3Only, setMp3Only] = useState(true)
  const [overwrite, setOverwrite] = useState(false)
  const [panes, setPanes] = useState<Record<Side, PaneState>>({ left: { loc: '', stack: [] }, right: { loc: '', stack: [] } })
  const [refresh, setRefresh] = useState(0)
  const [startError, setStartError] = useState<string | null>(null)

  const running = jobs.data?.items.find((j) => j.state === 'running')
  useInterval(jobs.reload, running ? 1000 : 15000)

  // a job just finished: reload both panes and the free space
  const prevRunning = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (prevRunning.current !== undefined && !running) {
      setRefresh((n) => n + 1)
      locs.reload()
    }
    prevRunning.current = running?.id
  }, [running, locs.reload])

  // pick / repair pane locations whenever the location list changes
  const list = locs.data?.locations
  useEffect(() => {
    if (!list) return
    setPanes((p) => {
      const [dl, dr] = defaults(list)
      const has = (id: string) => list.some((l) => l.id === id)
      const left = has(p.left.loc) ? p.left : { loc: dl, stack: [] }
      const right = has(p.right.loc) ? p.right : { loc: dr !== left.loc ? dr : '', stack: [] }
      return left === p.left && right === p.right ? p : { left, right }
    })
  }, [list])

  const disabled = locs.error?.message.includes('disabled')

  const start = async (from: Side, items: UsbFileEntry[], move: boolean) => {
    const to: Side = from === 'left' ? 'right' : 'left'
    const src = panes[from]
    const dst = panes[to]
    const dstName = [list?.find((l) => l.id === dst.loc)?.name, ...dst.stack.map((c) => c.name)].filter(Boolean).join(' / ')
    if (move && !confirm(t('xfer.confirmMove', { count: items.length, to: dstName }))) return
    setStartError(null)
    try {
      await api.usbTransferStart({
        from: src.loc,
        fromDir: src.stack.at(-1)?.id ?? '',
        items: items.map((e) => e.id),
        to: dst.loc,
        toDir: dst.stack.at(-1)?.id ?? '',
        move,
        overwrite,
        ext: mp3Only ? 'mp3' : undefined,
      })
    } catch (e) {
      setStartError((e as Error).message)
    }
    jobs.reload()
  }

  return (
    <Card
      title={t('xfer.title')}
      actions={
        <RefreshButton
          onClick={() => {
            locs.reload()
            setRefresh((n) => n + 1)
          }}
          loading={locs.loading}
        />
      }
    >
      {disabled ? (
        <p className="text-sm text-slate-500">{t('xfer.disabled')}</p>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {t('xfer.hint')} {t('xfer.dirHint')}
          </p>
          {locs.error && <ErrorBox error={locs.error} />}
          {locs.data?.notes.map((n) => (
            <div key={n} className="flex items-start gap-1.5 text-sm text-slate-600 dark:text-slate-400">
              <StatusIcon status="warn" className="mt-0.5 size-3.5 shrink-0" />
              {n}
            </div>
          ))}
          <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
            <label className="inline-flex items-center gap-1.5">
              <input type="checkbox" checked={mp3Only} onChange={(e) => setMp3Only(e.target.checked)} />
              {t('xfer.mp3Only')}
            </label>
            <label className="inline-flex items-center gap-1.5">
              <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
              {t('xfer.overwrite')}
            </label>
          </div>
          {startError && <ErrorBox error={new Error(startError)} />}

          {list && list.length === 0 ? (
            <p className="text-sm text-slate-500">{t('xfer.noLocation')}</p>
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {(['left', 'right'] as const).map((side) => (
                <Pane
                  key={side}
                  side={side}
                  locations={list ?? []}
                  state={panes[side]}
                  onChange={(s) => setPanes((p) => ({ ...p, [side]: s }))}
                  ext={mp3Only ? 'mp3' : ''}
                  refresh={refresh}
                  canSend={!running && !!panes[side === 'left' ? 'right' : 'left'].loc}
                  targetReadOnly={!!list?.find((l) => l.id === panes[side === 'left' ? 'right' : 'left'].loc)?.readOnly}
                  onSend={(items, move) => start(side, items, move)}
                />
              ))}
            </div>
          )}
          {running && <p className="text-xs text-slate-500">{t('xfer.wait')}</p>}

          {jobs.data && jobs.data.items.length > 0 && (
            <div>
              <div className="mb-1.5 text-xs font-medium text-slate-500 dark:text-slate-400">{t('xfer.jobs')}</div>
              <div className="space-y-2">
                {jobs.data.items.slice(0, 5).map((j) => (
                  <JobRow key={j.id} j={j} onCancel={() => api.usbTransferCancel(j.id).then(jobs.reload)} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function Pane({
  side,
  locations,
  state,
  onChange,
  ext,
  refresh,
  canSend,
  targetReadOnly,
  onSend,
}: {
  side: Side
  locations: UsbFileLocation[]
  state: PaneState
  onChange: (s: PaneState) => void
  ext: string
  refresh: number
  canSend: boolean
  targetReadOnly: boolean
  onSend: (items: UsbFileEntry[], move: boolean) => void
}) {
  const { t, lang } = useI18n()
  const loc = locations.find((l) => l.id === state.loc)
  const dir = state.stack.at(-1)?.id ?? ''
  const files = useFetch(
    (s) => (loc && usable(loc) ? api.usbFiles(loc.id, dir, ext, s) : Promise.resolve(null)),
    [loc?.id, loc?.error, dir, ext, refresh],
  )
  const [sel, setSel] = useState<Set<string>>(new Set())
  useEffect(() => setSel(new Set()), [state.loc, dir, ext, refresh])

  // phones open in their Music folder (once per selected storage; going back to the top stays there)
  const autoEnter = useRef<string | null>(null)
  useEffect(() => {
    autoEnter.current = loc?.kind === 'mtp' ? state.loc : null
  }, [state.loc, loc?.kind])
  useEffect(() => {
    if (!files.data || autoEnter.current !== state.loc || files.data.location.id !== state.loc) return
    autoEnter.current = null
    if (state.stack.length > 0) return
    const music = files.data.entries.find((e) => e.dir && e.name.toLowerCase() === 'music')
    if (music) onChange({ ...state, stack: [{ id: music.id, name: music.name }] })
  }, [files.data, state, onChange])

  const entries = files.data?.entries ?? []
  const chosen = entries.filter((e) => sel.has(e.id))
  const chosenDirs = chosen.filter((e) => e.dir).length
  const total = chosen.reduce((a, e) => a + e.size, 0)
  const allOn = entries.length > 0 && chosen.length === entries.length
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  const Arrow = side === 'left' ? ArrowRight : ArrowLeft
  const sendDisabled = !canSend || chosen.length === 0 || targetReadOnly

  return (
    <div className="flex min-w-0 flex-col rounded-lg border border-slate-200 dark:border-slate-800">
      <div className="space-y-1.5 border-b border-slate-200 p-2.5 dark:border-slate-800">
        <select
          className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900"
          value={state.loc}
          onChange={(e) => onChange({ loc: e.target.value, stack: [] })}
        >
          <option value="">—</option>
          {locations.map((l) => (
            <option key={l.id} value={l.id} disabled={!!l.error}>
              [{t(`xfer.kind.${l.kind}` as MessageKey)}] {l.name}
              {l.error ? ` — ${l.error}` : ''}
            </option>
          ))}
        </select>
        {loc && (
          <div className="flex items-center gap-x-2 text-xs text-slate-500 dark:text-slate-400">
            {(() => {
              const Icon = kindIcon[loc.kind]
              return <Icon className="size-3.5 shrink-0" />
            })()}
            <span className="min-w-0 truncate" title={loc.detail}>
              {loc.detail}
            </span>
            {loc.size > 0 && <span className="ml-auto shrink-0 whitespace-nowrap">{t('xfer.free', { free: bytes(loc.free), size: bytes(loc.size) })}</span>}
            {loc.readOnly && <span className="shrink-0 text-amber-700 dark:text-amber-300">{t('xfer.readOnly')}</span>}
          </div>
        )}
        {loc && (
          <div className="flex flex-wrap items-center gap-0.5 text-xs">
            <button type="button" className="rounded px-1 py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => onChange({ ...state, stack: [] })}>
              {t('xfer.top')}
            </button>
            {state.stack.map((c, i) => (
              <span key={c.id} className="inline-flex items-center gap-0.5">
                <ChevronRight className="size-3 text-slate-400" />
                <button
                  type="button"
                  className="rounded px-1 py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800"
                  onClick={() => onChange({ ...state, stack: state.stack.slice(0, i + 1) })}
                >
                  {c.name}
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="max-h-96 min-h-40 overflow-y-auto">
        {loc?.error && <p className="p-3 text-sm text-amber-700 dark:text-amber-300">{loc.error}</p>}
        {files.error && (
          <div className="p-2">
            <ErrorBox error={files.error} />
          </div>
        )}
        {files.loading && !files.data && <p className="p-3 text-sm text-slate-500">…</p>}
        {files.data && (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="w-8 px-2 py-1.5">
                  <input
                    type="checkbox"
                    checked={allOn}
                    disabled={entries.length === 0}
                    onChange={() => setSel(allOn ? new Set() : new Set(entries.map((e) => e.id)))}
                  />
                </th>
                <th className="px-2 py-1.5 font-medium">{t('xfer.name')}</th>
                <th className="px-2 py-1.5 text-right font-medium">{t('xfer.size')}</th>
                <th className="hidden px-2 py-1.5 font-medium sm:table-cell">{t('xfer.modified')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {state.stack.length > 0 && (
                <tr className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => onChange({ ...state, stack: state.stack.slice(0, -1) })}>
                  <td className="px-2 py-1" />
                  <td className="px-2 py-1 text-slate-500" colSpan={3}>
                    <span className="inline-flex items-center gap-1.5">
                      <CornerLeftUp className="size-3.5" />
                      {t('xfer.up')}
                    </span>
                  </td>
                </tr>
              )}
              {entries.map((e) => (
                <tr
                  key={e.id}
                  className={`cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50 ${sel.has(e.id) ? 'bg-sky-50/70 dark:bg-sky-500/10' : ''}`}
                  onClick={() => (e.dir ? onChange({ ...state, stack: [...state.stack, { id: e.id, name: e.name }] }) : toggle(e.id))}
                >
                  <td className="px-2 py-1" onClick={(ev) => ev.stopPropagation()}>
                    <input type="checkbox" checked={sel.has(e.id)} onChange={() => toggle(e.id)} />
                  </td>
                  <td className="px-2 py-1 break-all">
                    <span className="inline-flex items-center gap-1.5">
                      {e.dir ? (
                        <Folder className="size-3.5 shrink-0 text-sky-600 dark:text-sky-400" />
                      ) : /\.(mp3|m4a|aac|wav|flac|ogg)$/i.test(e.name) ? (
                        <FileAudio className="size-3.5 shrink-0 text-slate-500" />
                      ) : (
                        <File className="size-3.5 shrink-0 text-slate-400" />
                      )}
                      {e.name}
                    </span>
                  </td>
                  <td className="px-2 py-1 text-right text-xs whitespace-nowrap tabular-nums">{e.dir ? '' : bytes(e.size)}</td>
                  <td className="hidden px-2 py-1 text-xs whitespace-nowrap text-slate-500 sm:table-cell">
                    {e.modified ? new Date(e.modified).toLocaleDateString(lang) : ''}
                  </td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-3 py-3 text-sm text-slate-500">
                    {t('xfer.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-slate-200 p-2.5 dark:border-slate-800">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {chosenDirs > 0
            ? t('xfer.selectedDirs', { count: chosen.length, dirs: chosenDirs, size: bytes(total) })
            : t('xfer.selected', { count: chosen.length, size: bytes(total) })}
        </span>
        <span className="ml-auto flex gap-1.5">
          <button type="button" className={btnPrimary} disabled={sendDisabled} onClick={() => onSend(chosen, false)}>
            {side === 'right' && <Arrow className="size-3.5" />}
            {t('xfer.copy')}
            {side === 'left' && <Arrow className="size-3.5" />}
          </button>
          <button type="button" className={btnWarn} disabled={sendDisabled} onClick={() => onSend(chosen, true)}>
            {side === 'right' && <Arrow className="size-3.5" />}
            {t('xfer.move')}
            {side === 'left' && <Arrow className="size-3.5" />}
          </button>
        </span>
      </div>
    </div>
  )
}

function JobRow({ j, onCancel }: { j: UsbTransferJob; onCancel: () => void }) {
  const { t, lang } = useI18n()
  const [open, setOpen] = useState(false)
  const pct =
    j.bytes > 0 ? Math.min(100, (j.bytesDone / j.bytes) * 100) : j.files > 0 ? ((j.done + j.failed) / j.files) * 100 : j.state === 'running' ? 0 : 100
  const status = j.state === 'running' ? 'warn' : j.state === 'done' && j.failed === 0 ? 'ok' : 'fail'
  const problems = useMemo(() => j.results.filter((r) => !r.ok), [j.results])
  return (
    <div className="rounded-lg border border-slate-200 px-3 py-2 text-sm dark:border-slate-800">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <StatusIcon status={status} className="size-4 shrink-0" />
        <span className="font-medium">{t(`xfer.state.${j.state}` as MessageKey)}</span>
        <span className="text-xs text-slate-500">{j.move ? t('xfer.move') : t('xfer.copy')}</span>
        <span className="min-w-0 break-all">
          {j.fromName} → {j.toName}
        </span>
        <span className="ml-auto flex items-center gap-2 text-xs text-slate-500">
          {new Date(j.startedAt).toLocaleTimeString(lang)}
          {j.state === 'running' && (
            <button type="button" className={btnNormal} onClick={onCancel}>
              <Ban className="size-3.5" />
              {t('xfer.cancel')}
            </button>
          )}
        </span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded bg-slate-100 dark:bg-slate-800">
        <div
          className={`h-full ${status === 'fail' ? 'bg-rose-500' : status === 'ok' ? 'bg-emerald-500' : 'bg-sky-500'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-slate-500 dark:text-slate-400">
        <span>{t('xfer.progress', { done: j.done, files: j.files, bytes: bytes(j.bytesDone), total: bytes(j.bytes) })}</span>
        {j.failed > 0 && <span className="text-rose-600 dark:text-rose-400">{t('xfer.failedN', { count: j.failed })}</span>}
        {j.folders > 0 && <span>{t('xfer.foldersN', { count: j.folders })}</span>}
        {j.skipped > 0 && <span>{t('xfer.skippedN', { count: j.skipped })}</span>}
        {j.current && <span className="break-all">{j.files === 0 ? j.current : t('xfer.current', { name: j.current })}</span>}
        {problems.length > 0 && (
          <button type="button" className="underline decoration-dotted" onClick={() => setOpen(!open)}>
            {t('xfer.details')}
          </button>
        )}
      </div>
      {open && (
        <ul className="mt-1.5 space-y-0.5 text-xs">
          {problems.map((r, i) => (
            <li key={`${r.name}-${i}`} className="flex items-start gap-1.5 break-all">
              <StatusIcon status="fail" className="mt-0.5 size-3 shrink-0" />
              <span>
                <span className="font-medium">{r.name}</span> — {r.error}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
