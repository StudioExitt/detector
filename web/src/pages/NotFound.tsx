import { Link } from 'react-router'
import { useI18n } from '../i18n'

export default function NotFound() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center gap-3 py-20 text-center">
      <span className="text-5xl">🔍</span>
      <p className="text-slate-600 dark:text-slate-400">{t('notFound.title')}</p>
      <Link to="/" className="text-sm font-medium text-blue-600 hover:underline dark:text-blue-400">
        {t('notFound.home')}
      </Link>
    </div>
  )
}
