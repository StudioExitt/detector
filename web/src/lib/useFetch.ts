import { useCallback, useEffect, useState } from 'react'

// 간단한 데이터 로딩 훅. deps 변경 시 이전 요청은 abort
export function useFetch<T>(fetcher: (signal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    fetcher(ac.signal)
      .then(setData)
      .catch((e: unknown) => {
        if (!ac.signal.aborted) setError(e instanceof Error ? e : new Error(String(e)))
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false)
      })
    return () => ac.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  const reload = useCallback(() => setNonce((n) => n + 1), [])
  return { data, error, loading, reload }
}
