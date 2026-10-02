import { Languages, Moon, PanelLeftClose, PanelLeftOpen, Sun } from 'lucide-react'
import { languages, useI18n, type Lang } from '../i18n'
import { useTheme } from '../lib/theme'

type Props = {
  title: string
  sidebarOpen: boolean
  onToggleSidebar: () => void
}

const iconBtn =
  'inline-flex size-9 items-center justify-center rounded-lg text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100'

export default function Header({ title, sidebarOpen, onToggleSidebar }: Props) {
  const { t, lang, setLang } = useI18n()
  const { theme, toggleTheme } = useTheme()
  const ToggleIcon = sidebarOpen ? PanelLeftClose : PanelLeftOpen

  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b border-slate-200 bg-white px-3 dark:border-slate-800 dark:bg-slate-900">
      <button type="button" className={iconBtn} onClick={onToggleSidebar} title={t('header.toggleSidebar')} aria-label={t('header.toggleSidebar')}>
        <ToggleIcon className="size-5" />
      </button>
      <h1 className="min-w-0 flex-1 truncate text-base font-semibold">{title}</h1>

      <label className="relative inline-flex items-center" title={t('header.language')}>
        <Languages className="pointer-events-none absolute left-2.5 size-4 text-slate-500" />
        <select
          value={lang}
          onChange={(e) => setLang(e.target.value as Lang)}
          aria-label={t('header.language')}
          className="h-9 cursor-pointer appearance-none rounded-lg border border-slate-200 bg-transparent pr-3 pl-8 text-sm hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
        >
          {languages.map((l) => (
            <option key={l.code} value={l.code} className="bg-white dark:bg-slate-900">
              {l.flag} {l.label}
            </option>
          ))}
        </select>
      </label>

      <button
        type="button"
        className={iconBtn}
        onClick={toggleTheme}
        title={theme === 'dark' ? t('header.theme.light') : t('header.theme.dark')}
        aria-label={theme === 'dark' ? t('header.theme.light') : t('header.theme.dark')}
      >
        {theme === 'dark' ? <Sun className="size-5" /> : <Moon className="size-5" />}
      </button>
    </header>
  )
}
