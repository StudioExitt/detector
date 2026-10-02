import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { readStorage, writeStorage } from '../lib/storage'
import { messages, type Lang, type MessageKey } from './messages'

export { languages, type Lang, type MessageKey } from './messages'

const STORAGE_KEY = 'detector.lang'
const DEFAULT_LANG: Lang = 'ko'

type I18nContextValue = {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: MessageKey, vars?: Record<string, string | number>) => string
}

const I18nContext = createContext<I18nContextValue | null>(null)

function initialLang(): Lang {
  const saved = readStorage(STORAGE_KEY)
  return saved && saved in messages ? (saved as Lang) : DEFAULT_LANG
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(initialLang)

  useEffect(() => {
    document.documentElement.lang = lang
    writeStorage(STORAGE_KEY, lang)
  }, [lang])

  const t = useCallback<I18nContextValue['t']>(
    (key, vars) => {
      let s: string = messages[lang][key] ?? key
      if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v))
      return s
    },
    [lang],
  )

  const value = useMemo(() => ({ lang, setLang, t }), [lang, t])
  return <I18nContext value={value}>{children}</I18nContext>
}

export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}
