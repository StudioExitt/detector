import { BrowserRouter, Route, Routes } from 'react-router'
import Layout from './components/Layout'
import { menus } from './menus'
import DetectorDetailPage from './pages/DetectorDetailPage'
import NotFound from './pages/NotFound'

const basename = (import.meta.env.VITE_APP_BASE_URL || '/').replace(/\/$/, '') || '/'

export default function App() {
  return (
    <BrowserRouter basename={basename}>
      <Routes>
        <Route element={<Layout />}>
          {menus.map((m) => (
            <Route key={m.path} path={m.path} element={m.element} />
          ))}
          <Route path="/detectors/:name" element={<DetectorDetailPage />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
