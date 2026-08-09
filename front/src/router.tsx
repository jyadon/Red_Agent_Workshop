import { createBrowserRouter } from 'react-router'
import { RootLayout } from './components/layout/RootLayout'
import { HomePage } from './pages/HomePage'
import { RetestPage } from './pages/RetestPage'
import { RTOPage } from './pages/RTOPage'
import { ConfigPage } from './pages/ConfigPage'
import { ErrorPage } from './pages/ErrorPage'
import { features } from './lib/features'

// Disabled features are not registered as routes at all, so they can't be reached even by direct URL.
const children = [
  { index: true, element: <HomePage /> },
  ...(features.retest
    ? [
        { path: 'retest', element: <RetestPage /> },
        { path: 'retest/:findingId', element: <RetestPage /> },
      ]
    : []),
  ...(features.rto ? [{ path: 'rto', element: <RTOPage /> }] : []),
  { path: 'config', element: <ConfigPage /> },
]

export const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    // Catches unmatched URLs (404) and runtime errors thrown during page render.
    errorElement: <ErrorPage />,
    children,
  },
])
