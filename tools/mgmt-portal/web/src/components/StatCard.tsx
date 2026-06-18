interface Props {
  title: string
  value: string | number
  sub?: string
  color?: string
}

export default function StatCard({ title, value, sub, color = 'text-white' }: Props) {
  return (
    <div className="bg-gray-900 rounded-lg p-5 border border-gray-800">
      <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">{title}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  )
}
