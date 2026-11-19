import { useState, type ReactNode } from 'react'
import { HardDrive, LogOut, ShieldAlert, ShieldCheck, Skull, Usb, X, Zap } from 'lucide-react'
import StatusIcon from '../components/StatusIcon'
import { Card, ErrorBox, RefreshButton } from '../components/ui'
import { useI18n, type MessageKey } from '../i18n'
import { api, type UsbActionResult, type UsbDevice, type UsbDisk, type UsbProc } from '../lib/api'
import { bytes, duration, rate } from '../lib/format'
import { useFetch } from '../lib/useFetch'
import { useInterval } from '../lib/useInterval'
import EventsPage from './EventsPage'

const th = 'px-3 py-2 font-medium'
const tableHead = 'border-b border-slate-200 text-left text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400'
const btn =
  'inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-50'
const btnNormal = `${btn} border-slate-200 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800`
const btnWarn = `${btn} border-amber-300 text-amber-800 hover:bg-amber-50 dark:border-amber-500/40 dark:text-amber-300 dark:hover:bg-amber-500/10`
const btnDanger = `${btn} border-rose-300 text-rose-700 hover:bg-rose-50 dark:border-rose-500/40 dark:text-rose-300 dark:hover:bg-rose-500/10`

function label(t: (k: MessageKey) => string, prefix: string, v: string) {
  const key = `${prefix}.${v}` as MessageKey
  const s = t(key)
  return s === key ? v : s
}

const hex4 = (n: number) => n.toString(16).padStart(4, '0')

type Run = (title: string, fn: () => Promise<UsbActionResult>) => Promise<void>

export default function UsbPage() {
  const { t, lang } = useI18n()
  const { data, error, loading, reload } = useFetch((s) => api.usbStatus(s), [])
  useInterval(reload, 10000)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ title: string; res?: UsbActionResult; error?: string } | null>(null)

  const run: Run = async (title, fn) => {
    setBusy(true)
    try {
      setResult({ title, res: await fn() })
    } catch (e) {
      setResult({ title, error: (e as Error).message })
    } finally {
      setBusy(false)
      setTimeout(reload, 800)
    }
  }

  const busyDisks = data?.disks.filter((k) => k.occupants.some((p) => !p.system)) ?? []
  const unknown = data?.devices.filter((d) => !d.known && !d.trusted) ?? []
  const alert = busyDisks.length > 0 || unknown.length > 0

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {data ? t('usb.collectedAt', { time: new Date(data.at).toLocaleTimeString(lang) }) : ''}
        </span>
        <span className="ml-auto">
          <RefreshButton onClick={reload} loading={loading} />
        </span>
      </div>

      {error && <ErrorBox error={error} />}

      {data && (
        <div
          className={`flex items-start gap-3 rounded-xl border px-4 py-3 ${
            alert
              ? 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200'
              : 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200'
          }`}
        >
          {alert ? <ShieldAlert className="mt-0.5 size-6 shrink-0" /> : <ShieldCheck className="mt-0.5 size-6 shrink-0" />}
          <div>
            <div className="font-semibold">
              {t('usb.summary', { devices: data.devices.length, disks: data.disks.length })}
              {busyDisks.length > 0 && ` · ${t('usb.busyDisks', { count: busyDisks.length })}`}
              {unknown.length > 0 && ` · ${t('usb.unknownDevices', { count: unknown.length })}`}
            </div>
            <div className="text-sm opacity-90">{t('usb.hint')}</div>
          </div>
        </div>
      )}

      {result && <ResultPanel {...result} onClose={() => setResult(null)} />}

      {data && data.notes.length > 0 && (
        <Card title={t('rec.notes')}>
          <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-400">
            {data.notes.map((n) => (
              <li key={n} className="flex items-start gap-1.5">
                <StatusIcon status="warn" className="mt-0.5 size-3.5 shrink-0" />
                {n}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {data && data.disks.length === 0 && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <HardDrive className="size-4" />
              {t('usb.disks')}
            </span>
          }
        >
          <p className="text-sm text-slate-500">{t('usb.noDisks')}</p>
        </Card>
      )}
      {data?.disks.map((k) => (
        <DiskCard key={k.disk} k={k} device={data.devices.find((d) => d.id === k.deviceId)} busy={busy} run={run} />
      ))}

      {data && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <Usb className="size-4" />
              {t('usb.devices', { count: data.devices.length })}
            </span>
          }
        >
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('usb.devicesHint')}</p>
          {data.devices.length === 0 ? (
            <p className="text-sm text-slate-500">{t('usb.noDevices')}</p>
          ) : (
            <Table head={[t('usb.device'), t('usb.kind'), 'VID:PID', t('usb.serial'), t('usb.connected'), t('usb.users')]}>
              {data.devices.map((d) => (
                <DeviceRow key={d.id} d={d} busy={busy} run={run} />
              ))}
            </Table>
          )}
        </Card>
      )}

      {data && (
        <Card title={t('usb.recent')}>
          <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">{t('usb.recentHint')}</p>
          {data.recent.length === 0 ? (
            <p className="text-sm text-slate-500">{t('rec.noRecent')}</p>
          ) : (
            <Table head={[t('usb.time'), t('usb.activity'), t('usb.target'), t('usb.detail')]}>
              {data.recent.map((r, i) => (
                <tr key={`${r.at}-${i}`}>
                  <td className="px-3 py-1.5 pl-4 text-xs whitespace-nowrap">{new Date(r.at).toLocaleString(lang)}</td>
                  <td className="px-3 py-1.5 whitespace-nowrap">
                    <StatusIcon status={r.ok ? 'ok' : 'fail'} className="mr-1 inline size-3.5" />
                    {label(t, 'usb.act', r.kind)}
                  </td>
                  <td className="px-3 py-1.5">{r.target}</td>
                  <td className="px-3 py-1.5 pr-4 text-xs break-all text-slate-600 dark:text-slate-400">{r.detail}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      <h2 className="pt-2 text-sm font-semibold">{t('usb.events')}</h2>
      <EventsPage detector="usb" />
    </div>
  )
}

function DiskCard({ k, device, busy, run }: { k: UsbDisk; device?: UsbDevice; busy: boolean; run: Run }) {
  const { t } = useI18n()
  const name = `${k.disk} · ${k.name || '-'}`
  const userOcc = k.occupants.filter((p) => !p.system)
  const eject = () => run(t('usb.eject') + ' ' + name, () => api.usbEject(k.disk))
  const releaseEject = () => {
    if (!confirm(t('usb.confirmRelease', { disk: name, count: k.occupants.length }))) return
    run(t('usb.releaseEject') + ' ' + name, () => api.usbRelease({ target: k.disk, signal: 'kill', eject: true }))
  }
  const force = () => {
    if (!confirm(t('usb.confirmForce', { disk: name }))) return
    run(t('usb.forceEject') + ' ' + name, () => api.usbEject(k.disk, true))
  }

  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-2">
          <HardDrive className="size-4" />
          {name}
          <span className="text-xs font-normal text-slate-500">
            {bytes(k.size)} · {k.bus || '-'}
            {device && ` · ${device.vendor || ''} ${hex4(device.vendorId)}:${hex4(device.productId)}`}
          </span>
          {userOcc.length > 0 ? <Badge tone="warn">{t('usb.inUse')}</Badge> : <Badge>{t('usb.idle')}</Badge>}
        </span>
      }
      actions={
        <span className="flex flex-wrap justify-end gap-1.5">
          <button type="button" className={btnNormal} disabled={busy} onClick={eject} title={t('usb.ejectHint')}>
            <LogOut className="size-3.5" />
            {t('usb.eject')}
          </button>
          <button type="button" className={btnWarn} disabled={busy} onClick={releaseEject} title={t('usb.releaseEjectHint')}>
            <Zap className="size-3.5" />
            {t('usb.releaseEject')}
          </button>
          <button type="button" className={btnDanger} disabled={busy} onClick={force} title={t('usb.forceEjectHint')}>
            <Skull className="size-3.5" />
            {t('usb.forceEject')}
          </button>
        </span>
      }
    >
      <div className="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
        {k.statsKnown ? (
          <>
            <span>{t('usb.write10m', { v: bytes(k.write10m) })}</span>
            <span>{t('usb.writeRate', { v: rate(k.writeBps) })}</span>
            <span>{t('usb.totalIO', { r: bytes(k.readBytes), w: bytes(k.writeBytes) })}</span>
          </>
        ) : (
          <span>{t('usb.noStats')}</span>
        )}
      </div>

      {k.volumes.length > 0 && (
        <Table head={[t('usb.volume'), t('usb.mount'), 'FS', t('usb.usage')]}>
          {k.volumes.map((v) => (
            <tr key={v.id}>
              <td className="px-3 py-1.5 pl-4">
                {v.name || '-'} <span className="font-mono text-xs text-slate-500">{v.id}</span>
              </td>
              <td className="px-3 py-1.5 font-mono text-xs break-all">{v.mountPoint || <span className="font-sans text-slate-500">{t('usb.notMounted')}</span>}</td>
              <td className="px-3 py-1.5 text-xs">
                {v.fs} {v.readOnly && <Badge>{t('usb.readOnly')}</Badge>}
              </td>
              <td className="px-3 py-1.5 pr-4 text-xs whitespace-nowrap">
                {v.mountPoint && v.size > 0 ? `${bytes(v.size - v.free)} / ${bytes(v.size)}` : bytes(v.size)}
              </td>
            </tr>
          ))}
        </Table>
      )}

      <div className="mt-4 mb-1 text-xs text-slate-500 dark:text-slate-400">{t('usb.occupants', { count: k.occupants.length })}</div>
      {k.occupants.length === 0 ? (
        <p className="text-sm text-slate-500">{t('usb.noOccupants')}</p>
      ) : (
        <ProcTable procs={k.occupants} target={k.disk} busy={busy} run={run} />
      )}
    </Card>
  )
}

function ProcTable({ procs, target, busy, run }: { procs: UsbProc[]; target: string; busy: boolean; run: Run }) {
  const { t } = useI18n()
  const kill = (p: UsbProc, hard: boolean) => {
    if (!confirm(t(hard ? 'usb.confirmKillHard' : 'usb.confirmKill', { name: p.name, pid: p.pid }))) return
    run(`${t(hard ? 'usb.killHard' : 'usb.kill')} ${p.name} (PID ${p.pid})`, () =>
      api.usbRelease({ target, pids: [p.pid], signal: hard ? 'kill' : 'term' }),
    )
  }
  return (
    <Table head={[t('usb.process'), 'PID', t('usb.user'), t('usb.files'), '']}>
      {procs.map((p) => (
        <tr key={p.pid} className={p.system ? '' : 'bg-amber-50/60 dark:bg-amber-500/5'}>
          <td className="px-3 py-1.5 pl-4">
            <div className="font-medium">
              {p.name} {p.system && <Badge>{t('usb.system')}</Badge>}
            </div>
            {p.exe && p.exe !== p.name && <div className="font-mono text-xs break-all text-slate-500">{p.exe}</div>}
          </td>
          <td className="px-3 py-1.5 tabular-nums">{p.pid}</td>
          <td className="px-3 py-1.5 text-xs">{p.user}</td>
          <td className="px-3 py-1.5 font-mono text-xs break-all whitespace-pre-line text-slate-600 dark:text-slate-400">
            {p.files.length > 0 ? p.files.join('\n') : '-'}
            {p.count > p.files.length && <span className="font-sans"> {t('usb.moreFiles', { count: p.count - p.files.length })}</span>}
          </td>
          <td className="px-3 py-1.5 pr-4 whitespace-nowrap">
            <span className="flex gap-1">
              <button type="button" className={btnWarn} disabled={busy} onClick={() => kill(p, false)} title="SIGTERM">
                {t('usb.kill')}
              </button>
              <button type="button" className={btnDanger} disabled={busy} onClick={() => kill(p, true)} title="SIGTERM → SIGKILL">
                {t('usb.killHard')}
              </button>
            </span>
          </td>
        </tr>
      ))}
    </Table>
  )
}

function DeviceRow({ d, busy, run }: { d: UsbDevice; busy: boolean; run: Run }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const releaseAll = () => {
    if (!confirm(t('usb.confirmReleaseDevice', { name: d.name, count: d.clients.length }))) return
    run(`${t('usb.releaseDevice')} ${d.name}`, () => api.usbRelease({ target: d.id, signal: 'kill' }))
  }
  return (
    <>
      <tr className={!d.known && !d.trusted ? 'bg-amber-50/60 dark:bg-amber-500/5' : ''}>
        <td className="px-3 py-1.5 pl-4">
          <div className="font-medium">
            {d.name || '-'} {!d.known && !d.trusted && <Badge tone="warn">{t('usb.new')}</Badge>}
            {d.trusted && <Badge>{t('rec.trusted')}</Badge>}
          </div>
          <div className="text-xs text-slate-500">
            {d.vendor}
            {d.speed && ` · ${d.speed}`}
            {d.disks.length > 0 && ` · ${d.disks.join(', ')}`}
          </div>
        </td>
        <td className="px-3 py-1.5">
          <span className="flex flex-wrap gap-1">
            {d.kinds.map((k) => (
              <Badge key={k} tone={k === 'keyboard' && !d.known ? 'danger' : undefined}>
                {label(t, 'usb.kind', k)}
              </Badge>
            ))}
          </span>
        </td>
        <td className="px-3 py-1.5 font-mono text-xs">
          {hex4(d.vendorId)}:{hex4(d.productId)}
        </td>
        <td className="px-3 py-1.5 font-mono text-xs break-all">{d.serial || '-'}</td>
        <td className="px-3 py-1.5 text-xs whitespace-nowrap">{t('rec.since', { time: duration(d.since) })}</td>
        <td className="px-3 py-1.5 pr-4">
          {d.clients.length === 0 ? (
            <span className="text-xs text-slate-500">-</span>
          ) : (
            <span className="flex flex-wrap items-center gap-1.5">
              <button type="button" className="text-xs underline decoration-dotted" onClick={() => setOpen(!open)}>
                {d.clients.map((p) => p.name).join(', ')}
              </button>
              <button type="button" className={btnDanger} disabled={busy} onClick={releaseAll}>
                {t('usb.releaseDevice')}
              </button>
            </span>
          )}
        </td>
      </tr>
      {open && d.clients.length > 0 && (
        <tr>
          <td colSpan={6} className="px-4 py-2">
            <ProcTable procs={d.clients} target={d.id} busy={busy} run={run} />
          </td>
        </tr>
      )}
    </>
  )
}

function ResultPanel({ title, res, error, onClose }: { title: string; res?: UsbActionResult; error?: string; onClose: () => void }) {
  const { t } = useI18n()
  const ok = !error && res?.ok
  return (
    <div
      className={`rounded-xl border px-4 py-3 text-sm ${
        ok
          ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-500/30 dark:bg-emerald-500/10'
          : 'border-rose-200 bg-rose-50 dark:border-rose-500/30 dark:bg-rose-500/10'
      }`}
    >
      <div className="mb-1 flex items-center gap-2 font-semibold">
        <StatusIcon status={ok ? 'ok' : 'fail'} className="size-4" />
        {title} — {ok ? t('usb.done') : t('usb.failed')}
        <button type="button" onClick={onClose} className="ml-auto rounded p-0.5 hover:bg-black/5 dark:hover:bg-white/10" aria-label="close">
          <X className="size-4" />
        </button>
      </div>
      {error && <p>{error}</p>}
      {res && (
        <ul className="space-y-0.5">
          {res.steps.map((s, i) => (
            <li key={i} className="flex items-start gap-1.5">
              <StatusIcon status={s.action === 'hint' ? 'warn' : s.ok ? 'ok' : 'fail'} className="mt-0.5 size-3.5 shrink-0" />
              <span>
                <span className="font-medium">{label(t, 'usb.step', s.action)}</span> {s.target}
                {s.detail && <span className="text-slate-600 dark:text-slate-400"> — {s.detail}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Badge({ children, tone }: { children: ReactNode; tone?: 'warn' | 'danger' }) {
  const cls =
    tone === 'danger'
      ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300'
      : tone === 'warn'
        ? 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300'
        : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
  return <span className={`rounded-md px-1.5 py-0.5 text-xs font-normal whitespace-nowrap ${cls}`}>{children}</span>
}

function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="-mx-4 overflow-x-auto">
      <table className="w-full min-w-[560px] text-sm">
        <thead>
          <tr className={tableHead}>
            {head.map((h, i) => (
              <th key={`${h}-${i}`} className={`${th} ${i === 0 ? 'pl-4' : ''} ${i === head.length - 1 ? 'pr-4' : ''}`}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
    </div>
  )
}
