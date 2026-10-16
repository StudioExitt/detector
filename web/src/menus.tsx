import type { ReactNode } from 'react'
import { Activity, BrickWall, Gauge, LayoutDashboard, ListTree, Network, Radar, ScanSearch, type LucideIcon } from 'lucide-react'
import type { MessageKey } from './i18n'
import Dashboard from './pages/Dashboard'
import DetectorsPage from './pages/DetectorsPage'
import EventsPage from './pages/EventsPage'
import FirewallPage from './pages/FirewallPage'
import NetworkPage from './pages/NetworkPage'
import SystemPage from './pages/SystemPage'

export type MenuItem = {
  /** 라우트 경로 (VITE_APP_BASE_URL 기준 상대 경로) */
  path: string
  labelKey: MessageKey
  icon: LucideIcon
  element: ReactNode
}

// 메뉴 등록: 여기에 항목을 추가하면 사이드바와 라우트에 함께 반영됨
export const menus: MenuItem[] = [
  { path: '/', labelKey: 'menu.dashboard', icon: LayoutDashboard, element: <Dashboard /> },
  { path: '/intrusion', labelKey: 'menu.intrusion', icon: Activity, element: <EventsPage category="intrusion" /> },
  { path: '/system', labelKey: 'menu.system', icon: Gauge, element: <SystemPage /> },
  { path: '/network', labelKey: 'menu.network', icon: Network, element: <NetworkPage /> },
  { path: '/firewall', labelKey: 'menu.firewall', icon: BrickWall, element: <FirewallPage /> },
  { path: '/vuln-scan', labelKey: 'menu.vulnScan', icon: ScanSearch, element: <EventsPage category="vulnerability_scan" /> },
  { path: '/events', labelKey: 'menu.events', icon: ListTree, element: <EventsPage /> },
  { path: '/detectors', labelKey: 'menu.detectors', icon: Radar, element: <DetectorsPage /> },
]
