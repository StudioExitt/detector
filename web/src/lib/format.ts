export function bytes(n: number, digits = 1): string {
  if (!Number.isFinite(n)) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : digits)} ${units[i]}`
}

export const rate = (bps: number) => `${bytes(bps)}/s`
export const pct = (v: number) => `${v.toFixed(v >= 10 ? 0 : 1)}%`

export function duration(fromIso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(fromIso).getTime()) / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}
