import { CircleCheck, CircleX, TriangleAlert } from 'lucide-react'
import type { CheckStatus } from '../lib/api'

export default function StatusIcon({ status, className = 'size-4' }: { status: CheckStatus; className?: string }) {
  switch (status) {
    case 'ok':
      return <CircleCheck className={`${className} shrink-0 text-emerald-500`} aria-label="ok" />
    case 'warn':
      return <TriangleAlert className={`${className} shrink-0 text-amber-500`} aria-label="warn" />
    default:
      return <CircleX className={`${className} shrink-0 text-rose-500`} aria-label="fail" />
  }
}
