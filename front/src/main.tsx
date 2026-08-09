import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from 'react-router'
import './app.css'
import { router } from './router'
import { SocksProvider } from './contexts/SocksContext'
import { AuthProvider } from './contexts/AuthContext'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <SocksProvider>
        <RouterProvider router={router} />
      </SocksProvider>
    </AuthProvider>
  </StrictMode>,
)
