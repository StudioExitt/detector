import { useEffect } from 'react'

export function useInterval(fn: () => void, ms: number) {
  useEffect(() => {
    const id = window.setInterval(fn, ms)
    return () => window.clearInterval(id)
  }, [fn, ms])
}
