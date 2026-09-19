import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import { ToastProvider } from './components/ui/Toast'
import { initTheme } from './lib/theme'
import './index.css'

// The inline bootstrap in index.html already set the class pre-paint; this keeps
// the DOM and the theme contract in sync (and covers storage-blocked contexts).
initTheme()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 5_000, refetchInterval: 10_000 },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <App />
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
)
