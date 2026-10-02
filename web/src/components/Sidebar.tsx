import { NavLink } from 'react-router'
import { useI18n } from '../i18n'
import { menus } from '../menus'
import Logo from './Logo'

type Props = {
  /** false 이면 아이콘만 표시 (데스크톱 접힘 상태) */
  expanded: boolean
  onNavigate?: () => void
}

export default function Sidebar({ expanded, onNavigate }: Props) {
  const { t } = useI18n()

  return (
    <aside
      className={`flex h-full flex-col border-r border-slate-200 bg-white transition-[width] duration-200 dark:border-slate-800 dark:bg-slate-900 ${
        expanded ? 'w-60' : 'w-16'
      }`}
    >
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-slate-200 px-4 dark:border-slate-800">
        <Logo className="size-8 shrink-0" />
        {expanded && (
          <div className="min-w-0 leading-tight">
            <div className="truncate font-semibold">{t('app.title')}</div>
            <div className="truncate text-xs text-slate-500 dark:text-slate-400">{t('app.subtitle')}</div>
          </div>
        )}
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto p-2">
        {menus.map(({ path, labelKey, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === '/'}
            onClick={onNavigate}
            title={expanded ? undefined : t(labelKey)}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                expanded ? '' : 'justify-center'
              } ${
                isActive
                  ? 'bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-300'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100'
              }`
            }
          >
            <Icon className="size-5 shrink-0" />
            {expanded && <span className="truncate">{t(labelKey)}</span>}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
