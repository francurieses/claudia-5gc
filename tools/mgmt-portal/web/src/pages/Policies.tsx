import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Send, ChevronDown, ChevronUp, BookOpen, Pencil, Zap, X } from 'lucide-react'
import {
  getPolicies, createPolicy, updatePolicy, deletePolicy, pushPolicies,
  getPolicyTemplates, createPolicyTemplate, updatePolicyTemplate, deletePolicyTemplate, applyPolicyTemplate,
  getUEContexts,
  Policy, URSPRule, RouteSelectionDescriptor,
  PolicyTemplate, ApplyTemplateResult,
} from '../lib/api'
import PageHeader from '../components/PageHeader'

// ---- Slice colours -------------------------------------------------------

const SLICE_HEADER: Record<string, string> = {
  internet: 'bg-blue-700',
  gold:     'bg-amber-600',
  silver:   'bg-slate-600',
  bronze:   'bg-orange-700',
}
const SLICE_BADGE: Record<string, string> = {
  internet: 'bg-blue-900/50 text-blue-300 border-blue-700',
  gold:     'bg-amber-900/50 text-amber-300 border-amber-700',
  silver:   'bg-slate-700/50 text-slate-300 border-slate-600',
  bronze:   'bg-orange-900/50 text-orange-300 border-orange-700',
}
const SLICE_LABEL: Record<string, string> = {
  internet: 'Internet (SST=1, SD=000001)',
  gold:     'Gold eMBB (SST=1, SD=000002)',
  silver:   'Silver URLLC (SST=2, SD=000001)',
  bronze:   'Bronze MIoT (SST=3, SD=000001)',
}
const SLICE_NAMES = ['internet', 'gold', 'silver', 'bronze']

// ---- Shared input class --------------------------------------------------

const INPUT = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500'
const TEXTAREA = `${INPUT} font-mono text-xs`

// ---- Spec Reference -------------------------------------------------------

function SpecReference({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <div className="border border-gray-700 rounded-lg bg-gray-900 text-xs overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-2.5 text-gray-400 hover:text-white hover:bg-gray-800/50 transition-colors"
      >
        <span className="flex items-center gap-2 font-medium">
          <BookOpen className="w-3.5 h-3.5 text-blue-400" />
          3GPP Spec Reference — URSP encoding &amp; delivery
        </span>
        {open ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
      </button>

      {open && (
        <div className="border-t border-gray-800 px-4 py-4 space-y-4 font-mono leading-relaxed">
          {/* Delivery path */}
          <div>
            <p className="text-gray-400 font-semibold mb-2 font-sans text-xs uppercase tracking-wider">Delivery path</p>
            <div className="space-y-1 text-gray-300">
              <p>
                <span className="text-green-400">PCF → AMF</span>
                <span className="text-gray-500 ml-2">(N15)</span>
                <span className="text-gray-400 ml-2">Npcf_UEPolicyControl POST /npcf-ue-policy-control/v1/ue-policies</span>
                <span className="text-gray-600 ml-2">— TS 29.525 §4.2.2</span>
              </p>
              <p>
                <span className="text-green-400">AMF → UE</span>
                <span className="text-gray-500 ml-2">(N1 NAS)</span>
                <span className="text-gray-400 ml-2">DL NAS Transport, payload container type 0x05 (UE policy container) → MANAGE UE POLICY COMMAND</span>
                <span className="text-gray-600 ml-2">— TS 24.501 §5.4.5 / Annex D</span>
              </p>
              <p className="text-gray-500 text-[10px] mt-1">
                PCF encodes rules → base64 blob → AMF decodes → NAS DL NAS Transport (payload container type 0x05) over-the-air to UE
              </p>
            </div>
          </div>

          {/* traffic_descriptor */}
          <div>
            <p className="text-gray-400 font-semibold mb-2 font-sans text-xs uppercase tracking-wider">
              traffic_descriptor — TS 24.526 §5.2 / TS 24.501 §9.11.4.15
            </p>
            <table className="w-full text-[11px]">
              <thead>
                <tr className="text-gray-600 border-b border-gray-800">
                  <th className="text-left py-1 pr-4 w-36">JSON field</th>
                  <th className="text-left py-1 pr-4 w-24">Component</th>
                  <th className="text-left py-1">Description</th>
                </tr>
              </thead>
              <tbody className="align-top">
                {[
                  ['match_all',     '0x01', 'Matches all UE traffic (no value bytes)'],
                  ['dnns[]',        '0x08', 'Data Network Name list'],
                  ['fqdns[]',       '0x21', 'FQDN match (application layer)'],
                  ['ipv4_addrs[]',  '0x23', 'Remote IPv4 address / prefix'],
                  ['protocol_ids[]','0x25', 'IP protocol (6=TCP, 17=UDP, …)'],
                  ['port_ranges[]', '0x26', 'Destination port range {low, high}'],
                ].map(([field, type, desc]) => (
                  <tr key={field} className="border-b border-gray-800/40">
                    <td className="py-1 pr-4 text-blue-300">{field}</td>
                    <td className="py-1 pr-4 text-purple-400">{type}</td>
                    <td className="py-1 text-gray-400">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* route_sel_descriptors */}
          <div>
            <p className="text-gray-400 font-semibold mb-2 font-sans text-xs uppercase tracking-wider">
              route_sel_descriptors[] — TS 24.526 §5.4
            </p>
            <table className="w-full text-[11px]">
              <thead>
                <tr className="text-gray-600 border-b border-gray-800">
                  <th className="text-left py-1 pr-4 w-36">JSON field</th>
                  <th className="text-left py-1 pr-4 w-24">Component</th>
                  <th className="text-left py-1">Description</th>
                </tr>
              </thead>
              <tbody className="align-top">
                {[
                  ['precedence',       'uint8', 'Lower = higher priority within rule'],
                  ['ssc_mode',         '0x01',  'Session continuity: 1=SSC-1, 2=SSC-2, 3=SSC-3'],
                  ['snssai.sst',       '0x02',  'Slice/Service Type (uint8)'],
                  ['snssai.sd',        '0x02',  'Slice Differentiator (24-bit hex string)'],
                  ['dnn',              '0x03',  'Data Network Name (APN)'],
                  ['pdu_session_type', '0x04',  '1=IPv4, 2=IPv6, 3=IPv4v6'],
                ].map(([field, type, desc]) => (
                  <tr key={field} className="border-b border-gray-800/40">
                    <td className="py-1 pr-4 text-blue-300">{field}</td>
                    <td className="py-1 pr-4 text-green-400">{type}</td>
                    <td className="py-1 text-gray-400">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="text-gray-600 text-[10px] italic">
            N15 payload: urspRules[].encodedUePolicy (base64) — TS 29.525 §4.2.2.2 / URSP rule precedence: 1=highest, 255=lowest
          </p>
        </div>
      )}
    </div>
  )
}

// ---- Apply Template Dialog -----------------------------------------------

interface ApplyDialogProps {
  template: PolicyTemplate
  onClose: () => void
  onSuccess: (result: ApplyTemplateResult) => void
}

function ApplyDialog({ template, onClose, onSuccess }: ApplyDialogProps) {
  const { data: ueContexts = [] } = useQuery({ queryKey: ['ue-contexts'], queryFn: getUEContexts })
  const [supi, setSupi] = useState('')
  const [customRules, setCustomRules] = useState(JSON.stringify(template.rules, null, 2))
  const [customize, setCustomize] = useState(false)
  const [specOpen, setSpecOpen] = useState(false)
  const [error, setError] = useState('')
  const [applying, setApplying] = useState(false)

  const effectiveRules = () => {
    if (!customize) return template.rules
    try { return JSON.parse(customRules) } catch { return null }
  }

  const handleApply = async () => {
    if (!supi) { setError('Select a UE first'); return }
    const rules = effectiveRules()
    if (rules === null) { setError('Invalid JSON in rules editor'); return }
    setApplying(true)
    setError('')
    try {
      let result: ApplyTemplateResult
      if (customize) {
        await createPolicy({ supi, precedence: template.precedence, rules })
        await pushPolicies(supi)
        result = { status: 'pushed' }
      } else {
        result = await applyPolicyTemplate(template.id, supi)
      }
      onSuccess(result)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setApplying(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Apply Template to UE</h2>
            <p className="text-xs text-gray-400 mt-0.5">{template.name}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SLICE_BADGE[template.slice_name] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}>
              {SLICE_LABEL[template.slice_name] ?? template.slice_name}
            </span>
            <button onClick={onClose} className="text-gray-500 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {/* UE selector */}
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Target UE (registered)</label>
            {ueContexts.length === 0 ? (
              <p className="text-xs text-amber-300 border border-amber-800 bg-amber-900/20 rounded px-3 py-2">
                No registered UEs found. Start UERANSIM first (<code className="font-mono">make ueransim</code>).
              </p>
            ) : (
              <select className={INPUT} value={supi} onChange={e => setSupi(e.target.value)}>
                <option value="">— select UE —</option>
                {ueContexts.map(ue => (
                  <option key={ue.supi} value={ue.supi}>{ue.supi}</option>
                ))}
              </select>
            )}
          </div>

          {/* JSON preview */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs text-gray-400">URSP Rules (JSON)</label>
              <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer hover:text-white">
                <input
                  type="checkbox"
                  checked={customize}
                  onChange={e => setCustomize(e.target.checked)}
                  className="rounded border-gray-600 bg-gray-800"
                />
                Customize before applying
              </label>
            </div>
            {customize ? (
              <textarea className={TEXTAREA} rows={12} value={customRules} onChange={e => setCustomRules(e.target.value)} />
            ) : (
              <pre className="bg-gray-800 border border-gray-700 rounded px-3 py-2.5 text-xs font-mono text-gray-300 overflow-x-auto max-h-48">
                {JSON.stringify(template.rules, null, 2)}
              </pre>
            )}
          </div>

          {/* Spec reference */}
          <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />

          {/* Delivery path info */}
          <div className="text-xs bg-blue-900/20 border border-blue-800 rounded px-3 py-2.5 space-y-1 text-blue-300">
            <p className="font-semibold text-blue-200">What will be sent:</p>
            <p>1. Portal → UDR: write per-subscriber policy to <code className="font-mono text-blue-300">subscription_policy</code></p>
            <p>2. Portal → AMF: <code className="font-mono">POST /amf/v1/ue-contexts/{'{supi}'}/push-policies</code></p>
            <p>3. AMF → PCF (N15): Npcf_UEPolicyControl — TS 29.525 §4.2.2</p>
            <p>4. AMF → UE (N1 NAS): DL NAS Transport, payload container type 0x05 → MANAGE UE POLICY COMMAND — TS 24.501 §5.4.5 / Annex D</p>
          </div>

          {error && (
            <p className="text-xs text-red-300 bg-red-900/20 border border-red-800 rounded px-3 py-2">{error}</p>
          )}
        </div>

        <div className="px-6 py-4 border-t border-gray-800 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 border border-gray-700 rounded hover:bg-gray-800 hover:text-white transition-colors">
            Cancel
          </button>
          <button
            onClick={handleApply}
            disabled={applying || !supi}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-green-700 hover:bg-green-600 text-white rounded disabled:opacity-40 transition-colors"
          >
            <Zap className="w-3.5 h-3.5" />
            {applying ? 'Applying…' : 'Apply & Push'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---- Template Editor Modal -----------------------------------------------

const EMPTY_RSD: RouteSelectionDescriptor = { precedence: 1, ssc_mode: 1, dnn: 'internet', snssai: { sst: 1, sd: '000001' }, pdu_session_type: 1 }
const EMPTY_RULE: URSPRule = { precedence: 255, traffic_descriptor: { match_all: true }, route_sel_descriptors: [EMPTY_RSD] }

interface TemplateEditorProps {
  editing: Partial<PolicyTemplate>
  onSave: () => void
  onClose: () => void
  onChange: (t: Partial<PolicyTemplate>) => void
  isPending: boolean
  saveError?: string
}

function TemplateEditor({ editing, onSave, onClose, onChange, isPending, saveError }: TemplateEditorProps) {
  const [specOpen, setSpecOpen] = useState(false)
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">{editing.id ? 'Edit Template' : 'New Template'}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Name</label>
              <input className={INPUT} value={editing.name ?? ''} onChange={e => onChange({ ...editing, name: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Slice</label>
              <select className={INPUT} value={editing.slice_name ?? 'internet'} onChange={e => onChange({ ...editing, slice_name: e.target.value })}>
                {SLICE_NAMES.map(s => <option key={s} value={s}>{SLICE_LABEL[s] ?? s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Description</label>
            <input className={INPUT} value={editing.description ?? ''} onChange={e => onChange({ ...editing, description: e.target.value })} />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Policy Precedence (1–255, lower = higher priority)</label>
            <input type="number" min={1} max={255} className={INPUT} value={editing.precedence ?? 100} onChange={e => onChange({ ...editing, precedence: +e.target.value })} />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">URSP Rules (JSON)</label>
            <textarea
              className={TEXTAREA}
              rows={16}
              value={JSON.stringify(editing.rules ?? [], null, 2)}
              onChange={e => {
                try { onChange({ ...editing, rules: JSON.parse(e.target.value) }) } catch { /* ignore while typing */ }
              }}
            />
          </div>
          <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />
          {saveError && (
            <p className="text-xs text-red-300 bg-red-900/20 border border-red-800 rounded px-3 py-2">{saveError}</p>
          )}
        </div>
        <div className="px-6 py-4 border-t border-gray-800 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 border border-gray-700 rounded hover:bg-gray-800 hover:text-white transition-colors">Cancel</button>
          <button onClick={onSave} disabled={isPending} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded disabled:opacity-40 transition-colors">Save</button>
        </div>
      </div>
    </div>
  )
}

// ---- Policy Editor Modal (per-subscriber) ---------------------------------

interface PolicyEditorProps {
  editing: Partial<Policy>
  onSave: () => void
  onClose: () => void
  onChange: (p: Partial<Policy>) => void
  isPending: boolean
  saveError?: string
}

function PolicyEditor({ editing, onSave, onClose, onChange, isPending, saveError }: PolicyEditorProps) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">{editing.id ? 'Edit Policy' : 'New Policy'}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">SUPI (leave empty for operator default)</label>
            <input
              className={INPUT}
              placeholder="imsi-001010000000001"
              value={editing.supi ?? ''}
              onChange={e => onChange({ ...editing, supi: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Policy Precedence (lower = higher priority)</label>
            <input
              type="number" min={1} max={255}
              className={INPUT}
              value={editing.precedence ?? 100}
              onChange={e => onChange({ ...editing, precedence: +e.target.value })}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1.5">URSP Rules (JSON)</label>
            <textarea
              className={TEXTAREA}
              rows={16}
              value={JSON.stringify(editing.rules ?? [], null, 2)}
              onChange={e => {
                try { onChange({ ...editing, rules: JSON.parse(e.target.value) }) } catch { /* ignore while typing */ }
              }}
            />
            <p className="mt-1.5 text-xs text-gray-600">
              precedence · traffic_descriptor (match_all / dnns / fqdns / ipv4_addrs) · route_sel_descriptors (ssc_mode, snssai, dnn, pdu_session_type)
            </p>
          </div>
          {saveError && (
            <p className="text-xs text-red-300 bg-red-900/20 border border-red-800 rounded px-3 py-2">{saveError}</p>
          )}
        </div>
        <div className="px-6 py-4 border-t border-gray-800 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 border border-gray-700 rounded hover:bg-gray-800 hover:text-white transition-colors">Cancel</button>
          <button onClick={onSave} disabled={isPending} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded disabled:opacity-40 transition-colors">Save</button>
        </div>
      </div>
    </div>
  )
}

// ---- Main Page ------------------------------------------------------------

const EMPTY_TEMPLATE: Omit<PolicyTemplate, 'id' | 'updated_at'> = {
  name: '', description: '', slice_name: 'internet', precedence: 100, rules: [{ ...EMPTY_RULE }],
}
const EMPTY_POLICY = { supi: '', precedence: 100, rules: [{ ...EMPTY_RULE }] }

export default function Policies() {
  const qc = useQueryClient()

  const { data: templates = [], isLoading: templatesLoading } =
    useQuery({ queryKey: ['policy-templates'], queryFn: getPolicyTemplates })
  const { data: policies = [], isLoading: policiesLoading } =
    useQuery({ queryKey: ['policies'], queryFn: getPolicies })

  // Template state
  const [editingTemplate, setEditingTemplate] = useState<Partial<PolicyTemplate> | null>(null)
  const [expandedTemplate, setExpandedTemplate] = useState<string | null>(null)
  const [specOpen, setSpecOpen] = useState(false)

  const createTplMut = useMutation({
    mutationFn: (t: typeof EMPTY_TEMPLATE) => createPolicyTemplate(t),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policy-templates'] }); setEditingTemplate(null) },
    onError: () => { /* error surfaced via createTplMut.error in TemplateEditor */ },
  })
  const updateTplMut = useMutation({
    mutationFn: ({ id, t }: { id: string; t: Partial<PolicyTemplate> }) => updatePolicyTemplate(id, t),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policy-templates'] }); setEditingTemplate(null) },
    onError: () => { /* error surfaced via updateTplMut.error in TemplateEditor */ },
  })
  const deleteTplMut = useMutation({
    mutationFn: (id: string) => deletePolicyTemplate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policy-templates'] }),
  })

  // Apply dialog
  const [applyTarget, setApplyTarget] = useState<PolicyTemplate | null>(null)
  const [applyResult, setApplyResult] = useState<ApplyTemplateResult | null>(null)

  const handleApplySuccess = (result: ApplyTemplateResult) => {
    setApplyTarget(null)
    setApplyResult(result)
    qc.invalidateQueries({ queryKey: ['policies'] })
  }

  // Per-subscriber policy state
  const [editingPolicy, setEditingPolicy] = useState<Partial<Policy> | null>(null)
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null)
  const [pushStatus, setPushStatus] = useState<Record<string, string>>({})

  const createPolMut = useMutation({
    mutationFn: (p: typeof EMPTY_POLICY) => createPolicy(p),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setEditingPolicy(null) },
    onError: () => { /* error surfaced via createPolMut.error in PolicyEditor */ },
  })
  const updatePolMut = useMutation({
    mutationFn: ({ id, p }: { id: string; p: Partial<Policy> }) => updatePolicy(id, p),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setEditingPolicy(null) },
    onError: () => { /* error surfaced via updatePolMut.error in PolicyEditor */ },
  })
  const deletePolMut = useMutation({
    mutationFn: (id: string) => deletePolicy(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }),
  })
  const pushMut = useMutation({
    mutationFn: (supi: string) => pushPolicies(supi),
    onSuccess: (_, supi) => setPushStatus(s => ({ ...s, [supi]: '✓ Sent' })),
    onError: (err: Error, supi) => setPushStatus(s => ({ ...s, [supi]: `✗ ${err.message}` })),
  })

  const saveTemplate = () => {
    if (!editingTemplate) return
    if (editingTemplate.id) updateTplMut.mutate({ id: editingTemplate.id, t: editingTemplate })
    else createTplMut.mutate(editingTemplate as typeof EMPTY_TEMPLATE)
  }

  const savePolicy = () => {
    if (!editingPolicy) return
    if (editingPolicy.id) updatePolMut.mutate({ id: editingPolicy.id, p: editingPolicy })
    else createPolMut.mutate(editingPolicy as typeof EMPTY_POLICY)
  }

  return (
    <div className="p-6 space-y-8">
      <PageHeader
        title="Policies"
        subtitle="URSP (UE Route Selection Policy) — TS 24.526 / TS 29.525"
      />

      {/* Apply result banner */}
      {applyResult && (
        <div className={`rounded-lg px-4 py-3 text-sm flex items-center justify-between border ${
          applyResult.status === 'pushed'
            ? 'bg-green-900/30 border-green-700 text-green-300'
            : 'bg-amber-900/30 border-amber-700 text-amber-300'
        }`}>
          <span>
            {applyResult.status === 'pushed'
              ? '✓ Policy pushed to UE via NAS ConfigurationUpdateCommand (TS 24.501 §8.2.29)'
              : `✓ Policy stored${applyResult.warning ? ' — ' + applyResult.warning : ''}`}
          </span>
          <button onClick={() => setApplyResult(null)} className="ml-4 opacity-60 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ── Section 1: Policy Templates ── */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            Policy Templates
          </h3>
          <button
            onClick={() => setEditingTemplate({ ...EMPTY_TEMPLATE, rules: [{ ...EMPTY_RULE }] })}
            className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-md transition-colors"
          >
            <Plus className="w-4 h-4" /> New Template
          </button>
        </div>

        <p className="text-xs text-gray-500">
          Pre-defined URSP rule sets for each network slice. Apply to any registered UE to steer its PDU sessions onto a specific slice.
        </p>

        <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />

        {templatesLoading ? (
          <div className="text-gray-500 text-sm py-4">Loading templates…</div>
        ) : templates.length === 0 ? (
          <div className="text-gray-500 text-sm p-4 border border-dashed border-gray-700 rounded-lg">
            No templates. Create one or restart the portal to re-seed defaults.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {templates.map(t => (
              <div key={t.id} className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                {/* Coloured slice header */}
                <div className={`px-4 py-3 ${SLICE_HEADER[t.slice_name] ?? 'bg-gray-700'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-semibold text-white text-sm leading-tight">{t.name}</span>
                    <span className="text-xs text-white/70 whitespace-nowrap">{SLICE_LABEL[t.slice_name] ?? t.slice_name}</span>
                  </div>
                  {t.description && (
                    <p className="text-xs text-white/60 mt-1 leading-snug">{t.description}</p>
                  )}
                </div>

                {/* Body */}
                <div className="px-4 py-3 space-y-3">
                  <div className="flex items-center gap-3 text-xs text-gray-500">
                    <span>Precedence <span className="text-gray-300 font-mono">{t.precedence}</span></span>
                    <span>·</span>
                    <span><span className="text-gray-300 font-mono">{(t.rules as URSPRule[])?.length ?? 0}</span> rule(s)</span>
                  </div>

                  {/* Toggle JSON */}
                  <button
                    onClick={() => setExpandedTemplate(expandedTemplate === t.id ? null : t.id)}
                    className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    {expandedTemplate === t.id ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    {expandedTemplate === t.id ? 'Hide' : 'Show'} JSON rules
                  </button>

                  {expandedTemplate === t.id && (
                    <pre className="bg-gray-800 border border-gray-700 rounded px-3 py-2.5 text-xs font-mono text-gray-300 overflow-x-auto max-h-52">
                      {JSON.stringify(t.rules, null, 2)}
                    </pre>
                  )}

                  {/* Action buttons */}
                  <div className="flex items-center gap-2 pt-1">
                    <button
                      onClick={() => setApplyTarget(t)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-green-700 hover:bg-green-600 text-white rounded transition-colors font-medium"
                    >
                      <Send className="w-3 h-3" /> Apply to UE
                    </button>
                    <button
                      onClick={() => setEditingTemplate(t)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded transition-colors"
                    >
                      <Pencil className="w-3 h-3" /> Edit
                    </button>
                    <button
                      onClick={() => deleteTplMut.mutate(t.id)}
                      className="ml-auto p-1.5 text-gray-600 hover:text-red-400 hover:bg-gray-800 rounded transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Section 2: Per-Subscriber Policies ── */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            Per-Subscriber Policies
          </h3>
          <button
            onClick={() => setEditingPolicy({ ...EMPTY_POLICY, rules: [{ ...EMPTY_RULE }] })}
            className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-md transition-colors"
          >
            <Plus className="w-4 h-4" /> New Policy
          </button>
        </div>

        <p className="text-xs text-gray-500">
          Active URSP overrides written to <code className="font-mono text-gray-400">subscription_policy</code>. Empty SUPI = operator default for all subscribers.
        </p>

        <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
          {policiesLoading ? (
            <div className="px-4 py-6 text-center text-gray-500 text-sm">Loading…</div>
          ) : policies.length === 0 ? (
            <div className="px-4 py-6 text-center text-gray-600 text-sm">
              No per-subscriber policies. Apply a template above or create a custom policy.
            </div>
          ) : (
            policies.map((p, i) => (
              <div key={p.id} className={i < policies.length - 1 ? 'border-b border-gray-800' : ''}>
                <div className="flex items-center justify-between px-4 py-3 hover:bg-gray-800/30 transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <button
                      onClick={() => setExpandedPolicy(expandedPolicy === p.id ? null : p.id)}
                      className="text-gray-500 hover:text-gray-300 flex-shrink-0"
                    >
                      {expandedPolicy === p.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                    <div className="min-w-0">
                      <span className="font-mono text-xs text-blue-300 truncate">
                        {p.supi || <span className="text-purple-400 not-italic font-sans text-xs">Default (all subscribers)</span>}
                      </span>
                      <span className="ml-2 text-xs text-gray-600">
                        precedence {p.precedence} · {(p.rules as URSPRule[])?.length ?? 0} rule(s)
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                    {p.supi && (
                      <button
                        onClick={() => pushMut.mutate(p.supi)}
                        disabled={pushMut.isPending}
                        className="flex items-center gap-1 px-2.5 py-1 text-xs bg-green-700 hover:bg-green-600 text-white rounded transition-colors"
                      >
                        <Send className="w-3 h-3" /> Push
                      </button>
                    )}
                    {pushStatus[p.supi] && (
                      <span className="text-xs text-gray-500">{pushStatus[p.supi]}</span>
                    )}
                    <button
                      onClick={() => setEditingPolicy(p)}
                      className="px-2.5 py-1 text-xs border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deletePolMut.mutate(p.id)}
                      className="p-1.5 text-gray-600 hover:text-red-400 hover:bg-gray-800 rounded transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                {expandedPolicy === p.id && (
                  <div className="border-t border-gray-800 px-4 py-3 bg-gray-800/40">
                    <pre className="text-xs font-mono text-gray-300 overflow-x-auto">
                      {JSON.stringify(p.rules, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      {/* Modals */}
      {editingTemplate !== null && (
        <TemplateEditor
          editing={editingTemplate}
          onChange={setEditingTemplate}
          onSave={saveTemplate}
          onClose={() => setEditingTemplate(null)}
          isPending={createTplMut.isPending || updateTplMut.isPending}
          saveError={(createTplMut.error ?? updateTplMut.error)?.message}
        />
      )}

      {editingPolicy !== null && (
        <PolicyEditor
          editing={editingPolicy}
          onChange={setEditingPolicy}
          onSave={savePolicy}
          onClose={() => setEditingPolicy(null)}
          isPending={createPolMut.isPending || updatePolMut.isPending}
          saveError={(createPolMut.error ?? updatePolMut.error)?.message}
        />
      )}

      {applyTarget !== null && (
        <ApplyDialog
          template={applyTarget}
          onClose={() => setApplyTarget(null)}
          onSuccess={handleApplySuccess}
        />
      )}
    </div>
  )
}
