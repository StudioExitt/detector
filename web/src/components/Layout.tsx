import { useState } from 'react'
import { Outlet, useLocation } from 'react-router'
import { useI18n } from '../i18n'
import { readStorage, writeStorage } from '../lib/storage'
import { menus } from '../menus'
import Header from './Header'
import Sidebar from './Sidebar'

const SIDEBAR_KEY = 'detector.sidebar'
const isDesktop = () => window.matchMedia('(min-width: 768px)').matches

export default function Layout() {
  const { t } = useI18n()
  const { pathname } = useLocation()
  // 데스크톱: 펼침/아이콘 전환(저장됨), 모바일: 오버레이 드로어
  const [expanded, setExpanded] = useState(() => readStorage(SIDEBAR_KEY) !== 'collapsed')
  const [mobileOpen, setMobileOpen] = useState(false)

  const toggleSidebar = () => {
    if (isDesktop()) {
      setExpanded((v) => {
        writeStorage(SIDEBAR_KEY, v ? 'collapsed' : 'expanded')
        return !v
      })
    } else {
      setMobileOpen((v) => !v)
    }
  }

  const current = menus.find((m) => (m.path === '/' ? pathname === '/' : pathname.startsWith(m.path)))
  const title = current ? t(current.labelKey) : t('app.title')

  return (
    <div className="flex h-full">
      <div className="hidden md:block">
        <Sidebar expanded={expanded} />
      </div>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-slate-900/50" onClick={() => setMobileOpen(false)} />
          <div className="relative h-full w-fit">
            <Sidebar expanded onNavigate={() => setMobileOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Header title={title} sidebarOpen={mobileOpen || expanded} onToggleSidebar={toggleSidebar} />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
