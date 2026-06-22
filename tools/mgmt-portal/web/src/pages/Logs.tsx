import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, Trash2, Pause, Play } from 'lucide-react'
import { getServices } from '../lib/api'
import PageHeader from '../components/PageHeader'

const NF_CONTAINERS = ['nrf', 'amf', 'ausf', 'bsf', 'nef', 'nssf', 'pcf', 'smf', 'smsf', 'udm', 'udr', 'upf']

type LogLine = { raw: string; level: string; msg: string; ts: string }

function parseLogLine(raw: string): LogLine {
  try {
    const obj = JSON.parse(raw.trim())
    return {
      raw,
      level: (obj.level ?? '').toLowerCase(),
      msg: obj.msg ?? raw,
      ts: obj.time ?? '',
    }
  } catch {
    return { raw, level: 'info', msg: raw, ts: '' }
  }
}

const levelColor: Record<string, string> = {
  error: 'text-red-400',
  warn: 'text-yellow-400',
  warning: 'text-yellow-400',
  info: 'text-gray-300',
  debug: 'text-gray-500',
}

export default function Logs() {
  const [container, setContainer] = useState('amf')
  const [lines, setLines] = useState<LogLine[]>([])
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const pausedRef = useRef(false)

  pausedRef.current = paused

  const { data: services = [] } = useQuery({
    queryKey: ['services'],
    queryFn: getServices,
  })

  const containers = services
    .filter(s => NF_CONTAINERS.includes(s.name))
    .map(s => s.name)
    .sort()

  useEffect(() => {
    wsRef.current?.close()
    setLines([])

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=200`)
      wsRef.current = ws
      ws.onmessage = (e) => {
        if (pausedRef.current) return
        const parsed = parseLogLine(e.data as string)
        setLines(prev => {
          const next = [...prev, parsed]
          return next.length > 2000 ? next.slice(-2000) : next
        })
      }
      ws.onclose = () => {
        if (!dead) reconnectTimer = setTimeout(connect, 3000)
      }
    }

    connect()
    return () => {
      dead = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [container])

  // Auto-scroll
  useEffect(() => {
    if (!paused) {
      endRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, paused])

  const filtered = filter
    ? lines.filter(l => l.raw.toLowerCase().includes(filter.toLowerCase()))
    : lines

  const downloadLogs = () => {
    const blob = new Blob([lines.map(l => l.raw).join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${container}-logs.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="p-6 flex flex-col h-full">
      <PageHeader
        title="Logs"
        subtitle="Real-time log streaming via Docker API"
        action={
          <div className="flex items-center gap-2">
            <button onClick={downloadLogs}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md">
              <Download size={13} /> Export
            </button>
            <button onClick={() => setLines([])}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md">
              <Trash2 size={13} /> Clear
            </button>
            <button onClick={() => setPaused(p => !p)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md ${
                paused ? 'bg-yellow-600 hover:bg-yellow-700' : 'bg-gray-700 hover:bg-gray-600'
              } text-white`}>
              {paused ? <><Play size={13} /> Resume</> : <><Pause size={13} /> Pause</>}
            </button>
          </div>
        }
      />

      {/* Controls */}
      <div className="flex items-center gap-3 mb-4">
        <select
          value={container}
          onChange={e => setContainer(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white"
        >
          {(containers.length > 0 ? containers : NF_CONTAINERS).map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Filter logs…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white"
        />
        <span className="text-xs text-gray-500">{filtered.length} lines</span>
      </div>

      {/* Terminal */}
      <div className="flex-1 bg-gray-950 rounded-lg border border-gray-800 overflow-y-auto font-mono-terminal p-3 min-h-[400px] max-h-[600px]">
        {filtered.length === 0 ? (
          <p className="text-gray-600 text-xs">Waiting for log lines from <strong className="text-gray-400">{container}</strong>…</p>
        ) : (
          filtered.map((line, i) => (
            <div key={i} className={`${levelColor[line.level] ?? 'text-gray-300'} leading-relaxed`}>
              {line.ts && <span className="text-gray-600 mr-2 text-[0.7rem]">{new Date(line.ts).toISOString().slice(11, 23)}</span>}
              {line.level && line.level !== 'info' && (
                <span className={`mr-2 uppercase text-[0.65rem] font-bold ${levelColor[line.level]}`}>
                  {line.level}
                </span>
              )}
              <span>{line.msg}</span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}
