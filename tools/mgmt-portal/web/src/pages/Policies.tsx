import { Fragment, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BookOpen, ChevronDown, ChevronUp, Pencil, Plus, RefreshCw, Send, Trash2, Zap } from 'lucide-react'
import {
  applyPolicyTemplate,
  createPolicy,
  createPolicyTemplate,
  deletePolicy,
  deletePolicyTemplate,
  getPolicies,
  getPolicyTemplates,
  getUEContexts,
  pushPolicies,
  updatePolicy,
  updatePolicyTemplate,
  type ApplyTemplateResult,
  type Policy,
  type PolicyTemplate,
  type RouteSelectionDescriptor,
  type URSPRule,
} from '../lib/api'
import {
  Badge, Button, Card, Checkbox, ConfirmDialog, Dialog, Disclosure, EmptyState, ErrorState, Field,
  IconButton, Input, Loading, PageHeader, Section, Select, Table, TableBody, TableCell,
  TableEmptyRow, TableHead, TableHeaderCell, TableRow, Textarea, useToast,
} from '../components/ui'
import type { BadgeVariant, SelectOption } from '../components/ui'

// ---- Slice identity -------------------------------------------------------
//
// The old page colour-coded each template header (blue/amber/slate/orange). The
// redesign expresses slice identity as a semantic Badge whose *label* carries
// the slice name, so the card stays readable when the hues are not.

const SLICE_LABEL: Record<string, string> = {
  internet: 'Internet (SST=1, SD=000001)',
  gold:     'Gold eMBB (SST=1, SD=000002)',
  silver:   'Silver URLLC (SST=2, SD=000001)',
  bronze:   'Bronze MIoT (SST=3, SD=000001)',
}
const SLICE_NAMES = ['internet', 'gold', 'silver', 'bronze']

const SLICE_VARIANT: Record<string, BadgeVariant> = {
  internet: 'info',
  gold:     'warning',
  silver:   'neutral',
  bronze:   'success',
}

function sliceVariant(name: string): BadgeVariant {
  return SLICE_VARIANT[name] ?? 'neutral'
}

const SLICE_OPTIONS: SelectOption[] = SLICE_NAMES.map(s => ({ value: s, label: SLICE_LABEL[s] ?? s }))

// ---- URSP JSON helpers ----------------------------------------------------

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Parse the rules editor text; `undefined` means "not a JSON array" (invalid). */
function parseRules(text: string): URSPRule[] | undefined {
  try {
    const parsed: unknown = JSON.parse(text)
    return Array.isArray(parsed) ? (parsed as URSPRule[]) : undefined
  } catch {
    return undefined
  }
}

const RULES_ERROR = 'Invalid JSON — fix it to save these rules.'

// ---- Spec reference -------------------------------------------------------

const TRAFFIC_DESCRIPTOR_ROWS: Array<[string, string, string]> = [
  ['match_all',      '0x01', 'Matches all UE traffic (no value bytes)'],
  ['dnns[]',         '0x08', 'Data Network Name list'],
  ['fqdns[]',        '0x21', 'FQDN match (application layer)'],
  ['ipv4_addrs[]',   '0x23', 'Remote IPv4 address / prefix'],
  ['protocol_ids[]', '0x25', 'IP protocol (6=TCP, 17=UDP, …)'],
  ['port_ranges[]',  '0x26', 'Destination port range {low, high}'],
]

const ROUTE_SEL_ROWS: Array<[string, string, string]> = [
  ['precedence',       'uint8', 'Lower = higher priority within rule'],
  ['ssc_mode',         '0x01',  'Session continuity: 1=SSC-1, 2=SSC-2, 3=SSC-3'],
  ['snssai.sst',       '0x02',  'Slice/Service Type (uint8)'],
  ['snssai.sd',        '0x02',  'Slice Differentiator (24-bit hex string)'],
  ['dnn',              '0x03',  'Data Network Name (APN)'],
  ['pdu_session_type', '0x04',  '1=IPv4, 2=IPv6, 3=IPv4v6'],
]

/** 3GPP reference panel (URSP encoding + delivery path) — a `Disclosure`. */
function SpecReference({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <Disclosure
      variant="sm"
      open={open}
      onOpenChange={onToggle}
      title="3GPP Spec Reference — URSP encoding & delivery"
      icon={<BookOpen size={14} />}
      bodyClassName="space-y-4"
    >
      {/* Delivery path */}
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-fg">Delivery path</p>
        <div className="space-y-1">
          <p>
            <span className="font-medium text-fg">PCF → AMF</span>
            <span className="ml-2 text-muted-fg">(N15)</span>
            <span className="ml-2 font-mono text-fg">Npcf_UEPolicyControl POST /npcf-ue-policy-control/v1/ue-policies</span>
            <span className="ml-2 italic text-muted-fg">— TS 29.525 §4.2.2</span>
          </p>
          <p>
            <span className="font-medium text-fg">AMF → UE</span>
            <span className="ml-2 text-muted-fg">(N1 NAS)</span>
            <span className="ml-2 font-mono text-fg">DL NAS Transport, payload container type 0x05 (UE policy container) → MANAGE UE POLICY COMMAND</span>
            <span className="ml-2 italic text-muted-fg">— TS 24.501 §5.4.5 / Annex D</span>
          </p>
          <p className="text-xs text-muted-fg">
            PCF encodes rules → base64 blob → AMF decodes → NAS DL NAS Transport (payload container type 0x05) over-the-air to UE
          </p>
        </div>
      </div>

      {/* traffic_descriptor */}
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-fg">
          traffic_descriptor — TS 24.526 §5.2 / TS 24.501 §9.11.4.15
        </p>
        <Table caption="traffic_descriptor JSON field encoding">
          <TableHead>
            <TableRow>
              <TableHeaderCell className="w-36">JSON field</TableHeaderCell>
              <TableHeaderCell className="w-24">Component</TableHeaderCell>
              <TableHeaderCell>Description</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {TRAFFIC_DESCRIPTOR_ROWS.map(([field, component, description]) => (
              <TableRow key={field}>
                <TableCell mono>{field}</TableCell>
                <TableCell mono className="text-muted-fg">{component}</TableCell>
                <TableCell className="text-muted-fg">{description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* route_sel_descriptors */}
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-fg">
          route_sel_descriptors[] — TS 24.526 §5.4
        </p>
        <Table caption="route_sel_descriptors JSON field encoding">
          <TableHead>
            <TableRow>
              <TableHeaderCell className="w-36">JSON field</TableHeaderCell>
              <TableHeaderCell className="w-24">Component</TableHeaderCell>
              <TableHeaderCell>Description</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {ROUTE_SEL_ROWS.map(([field, component, description]) => (
              <TableRow key={field}>
                <TableCell mono>{field}</TableCell>
                <TableCell mono className="text-muted-fg">{component}</TableCell>
                <TableCell className="text-muted-fg">{description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <p className="text-xs italic text-muted-fg">
        N15 payload: urspRules[].encodedUePolicy (base64) — TS 29.525 §4.2.2.2 / URSP rule precedence: 1=highest, 255=lowest
      </p>
    </Disclosure>
  )
}

// ---- Apply Template Dialog -----------------------------------------------

interface ApplyDialogProps {
  template: PolicyTemplate
  onClose: () => void
  onSuccess: (result: ApplyTemplateResult, supi: string) => void
}

function ApplyDialog({ template, onClose, onSuccess }: ApplyDialogProps) {
  const { toast } = useToast()
  const { data: ueContexts = [] } = useQuery({ queryKey: ['ue-contexts'], queryFn: getUEContexts })
  const [supi, setSupi] = useState('')
  const [customize, setCustomize] = useState(false)
  const [rulesText, setRulesText] = useState(() => JSON.stringify(template.rules, null, 2))
  const [specOpen, setSpecOpen] = useState(false)
  const [applying, setApplying] = useState(false)

  const rulesError = customize ? (parseRules(rulesText) ? undefined : RULES_ERROR) : undefined

  const ueOptions: SelectOption[] = [
    { value: '', label: '— select UE —' },
    ...ueContexts.map(ue => ({ value: ue.supi, label: ue.supi })),
  ]

  const handleApply = async () => {
    const rules = customize ? parseRules(rulesText) : template.rules
    if (!rules) return
    setApplying(true)
    try {
      let result: ApplyTemplateResult
      if (customize) {
        await createPolicy({ supi, precedence: template.precedence, rules })
        await pushPolicies(supi)
        result = { status: 'pushed' }
      } else {
        result = await applyPolicyTemplate(template.id, supi)
      }
      onSuccess(result, supi)
    } catch (e: unknown) {
      toast({ variant: 'error', title: 'Apply template failed', description: errMessage(e), duration: 0 })
    } finally {
      setApplying(false)
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Apply Template to UE"
      description={template.name}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={applying}>
            Cancel
          </Button>
          <Button
            icon={<Zap size={14} />}
            loading={applying}
            disabled={applying || !supi || ueContexts.length === 0 || !!rulesError}
            onClick={handleApply}
          >
            Apply &amp; Push
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge label={SLICE_LABEL[template.slice_name] ?? template.slice_name} variant={sliceVariant(template.slice_name)} />
          <span className="text-xs text-muted-fg">
            Steers the UE's PDU sessions onto this slice (URSP).
          </span>
        </div>

        {ueContexts.length === 0 ? (
          <EmptyState
            title="No registered UEs"
            description="Start UERANSIM first (make ueransim), then reopen this dialog."
          />
        ) : (
          <Field label="Target UE (registered)">
            {({ id }) => (
              <Select id={id} value={supi} options={ueOptions} onChange={e => setSupi(e.target.value)} />
            )}
          </Field>
        )}

        <Checkbox
          checked={customize}
          onChange={setCustomize}
          label="Customize before applying"
          labelClassName="text-xs text-muted-fg"
        />

        {customize ? (
          <Field label="URSP Rules (JSON)" error={rulesError}>
            {({ id, describedBy, invalid }) => (
              <Textarea
                id={id}
                aria-describedby={describedBy}
                invalid={invalid}
                rows={12}
                value={rulesText}
                onChange={e => setRulesText(e.target.value)}
              />
            )}
          </Field>
        ) : (
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-fg">URSP Rules (JSON)</p>
            <pre className="max-h-48 overflow-x-auto rounded-control border border-border bg-muted/40 px-3 py-2 font-mono text-xs text-fg">
              {JSON.stringify(template.rules, null, 2)}
            </pre>
          </div>
        )}

        <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />

        <Card>
          <div className="mb-2 flex items-center gap-2">
            <Badge label="Delivery path" variant="info" />
            <span className="text-xs font-semibold text-fg">What will be sent</span>
          </div>
          <ol className="list-decimal space-y-1 pl-5 text-xs text-muted-fg">
            <li>
              Portal → UDR: write per-subscriber policy to{' '}
              <code className="font-mono text-fg">subscription_policy</code>
            </li>
            <li>
              Portal → AMF:{' '}
              <code className="font-mono text-fg">POST /amf/v1/ue-contexts/{'{supi}'}/push-policies</code>
            </li>
            <li>AMF → PCF (N15): Npcf_UEPolicyControl — TS 29.525 §4.2.2</li>
            <li>AMF → UE (N1 NAS): DL NAS Transport, payload container type 0x05 → MANAGE UE POLICY COMMAND — TS 24.501 §5.4.5 / Annex D</li>
          </ol>
        </Card>
      </div>
    </Dialog>
  )
}

// ---- Template Editor Dialog ----------------------------------------------

const EMPTY_RSD: RouteSelectionDescriptor = { precedence: 1, ssc_mode: 1, dnn: 'internet', snssai: { sst: 1, sd: '000001' }, pdu_session_type: 1 }
const EMPTY_RULE: URSPRule = { precedence: 255, traffic_descriptor: { match_all: true }, route_sel_descriptors: [EMPTY_RSD] }

interface TemplateEditorProps {
  editing: Partial<PolicyTemplate>
  onSave: () => void
  onClose: () => void
  onChange: (t: Partial<PolicyTemplate>) => void
  isPending: boolean
}

function TemplateEditor({ editing, onSave, onClose, onChange, isPending }: TemplateEditorProps) {
  const [specOpen, setSpecOpen] = useState(false)
  // The rules text is held locally so a half-typed (invalid) JSON document is
  // visible instead of snapping back to the last valid value; only successfully
  // parsed rules are propagated upward, and Save stays blocked while invalid.
  const [rulesText, setRulesText] = useState(() => JSON.stringify(editing.rules ?? [], null, 2))
  const rulesError = parseRules(rulesText) ? undefined : RULES_ERROR

  const handleRulesChange = (value: string) => {
    setRulesText(value)
    const parsed = parseRules(value)
    if (parsed) onChange({ ...editing, rules: parsed })
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={editing.id ? 'Edit Template' : 'New Template'}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={onSave} loading={isPending} disabled={isPending || !!rulesError}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name">
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                invalid={invalid}
                value={editing.name ?? ''}
                onChange={e => onChange({ ...editing, name: e.target.value })}
              />
            )}
          </Field>
          <Field label="Slice">
            {({ id }) => (
              <Select
                id={id}
                value={editing.slice_name ?? 'internet'}
                options={SLICE_OPTIONS}
                onChange={e => onChange({ ...editing, slice_name: e.target.value })}
              />
            )}
          </Field>
        </div>

        <Field label="Description">
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              value={editing.description ?? ''}
              onChange={e => onChange({ ...editing, description: e.target.value })}
            />
          )}
        </Field>

        <Field label="Policy Precedence" hint="1–255, lower = higher priority">
          {({ id }) => (
            <Input
              id={id}
              type="number"
              min={1}
              max={255}
              value={editing.precedence ?? 100}
              onChange={e => onChange({ ...editing, precedence: +e.target.value })}
            />
          )}
        </Field>

        <Field label="URSP Rules (JSON)" error={rulesError} hint="Parsed as you type — invalid JSON is never saved.">
          {({ id, describedBy, invalid }) => (
            <Textarea
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              rows={16}
              value={rulesText}
              onChange={e => handleRulesChange(e.target.value)}
            />
          )}
        </Field>

        <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />
      </div>
    </Dialog>
  )
}

// ---- Policy Editor Dialog (per-subscriber) --------------------------------

interface PolicyEditorProps {
  editing: Partial<Policy>
  onSave: () => void
  onClose: () => void
  onChange: (p: Partial<Policy>) => void
  isPending: boolean
}

function PolicyEditor({ editing, onSave, onClose, onChange, isPending }: PolicyEditorProps) {
  const [rulesText, setRulesText] = useState(() => JSON.stringify(editing.rules ?? [], null, 2))
  const rulesError = parseRules(rulesText) ? undefined : RULES_ERROR

  const handleRulesChange = (value: string) => {
    setRulesText(value)
    const parsed = parseRules(value)
    if (parsed) onChange({ ...editing, rules: parsed })
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={editing.id ? 'Edit Policy' : 'New Policy'}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={onSave} loading={isPending} disabled={isPending || !!rulesError}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="SUPI" hint="Leave empty for the operator default (applies to all subscribers).">
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              placeholder="imsi-001010000000001"
              value={editing.supi ?? ''}
              onChange={e => onChange({ ...editing, supi: e.target.value })}
              className="font-mono text-xs"
            />
          )}
        </Field>

        <Field label="Policy Precedence" hint="1–255, lower = higher priority">
          {({ id }) => (
            <Input
              id={id}
              type="number"
              min={1}
              max={255}
              value={editing.precedence ?? 100}
              onChange={e => onChange({ ...editing, precedence: +e.target.value })}
            />
          )}
        </Field>

        <Field
          label="URSP Rules (JSON)"
          error={rulesError}
          hint="precedence · traffic_descriptor (match_all / dnns / fqdns / ipv4_addrs) · route_sel_descriptors (ssc_mode, snssai, dnn, pdu_session_type)"
        >
          {({ id, describedBy, invalid }) => (
            <Textarea
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              rows={16}
              value={rulesText}
              onChange={e => handleRulesChange(e.target.value)}
            />
          )}
        </Field>
      </div>
    </Dialog>
  )
}

// ---- Main Page ------------------------------------------------------------

const EMPTY_TEMPLATE: Omit<PolicyTemplate, 'id' | 'updated_at'> = {
  name: '', description: '', slice_name: 'internet', precedence: 100, rules: [{ ...EMPTY_RULE }],
}
const EMPTY_POLICY: Omit<Policy, 'id' | 'updated_at'> = { supi: '', precedence: 100, rules: [{ ...EMPTY_RULE }] }

export default function Policies() {
  const qc = useQueryClient()
  const { toast } = useToast()

  const {
    data: templates = [],
    isLoading: templatesLoading,
    isError: templatesError,
    error: templatesErr,
    refetch: refetchTemplates,
  } = useQuery({ queryKey: ['policy-templates'], queryFn: getPolicyTemplates })

  const {
    data: policies = [],
    isLoading: policiesLoading,
    isError: policiesError,
    error: policiesErr,
    refetch: refetchPolicies,
  } = useQuery({ queryKey: ['policies'], queryFn: getPolicies })

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  // Template state
  const [editingTemplate, setEditingTemplate] = useState<Partial<PolicyTemplate> | null>(null)
  const [expandedTemplate, setExpandedTemplate] = useState<string | null>(null)
  const [deleteTemplateTarget, setDeleteTemplateTarget] = useState<PolicyTemplate | null>(null)
  const [specOpen, setSpecOpen] = useState(false)

  const createTplMut = useMutation({
    mutationFn: (t: typeof EMPTY_TEMPLATE) => createPolicyTemplate(t),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policy-templates'] })
      setEditingTemplate(null)
      toast({ variant: 'success', title: 'Template created' })
    },
    onError: actionFailed('Create template'),
  })
  const updateTplMut = useMutation({
    mutationFn: ({ id, t }: { id: string; t: Partial<PolicyTemplate> }) => updatePolicyTemplate(id, t),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policy-templates'] })
      setEditingTemplate(null)
      toast({ variant: 'success', title: 'Template updated' })
    },
    onError: actionFailed('Update template'),
  })
  const deleteTplMut = useMutation({
    mutationFn: (id: string) => deletePolicyTemplate(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policy-templates'] })
      setDeleteTemplateTarget(null)
      toast({ variant: 'success', title: 'Template deleted' })
    },
    onError: actionFailed('Delete template'),
  })

  // Apply dialog
  const [applyTarget, setApplyTarget] = useState<PolicyTemplate | null>(null)

  const handleApplySuccess = (result: ApplyTemplateResult, supi: string) => {
    setApplyTarget(null)
    qc.invalidateQueries({ queryKey: ['policies'] })
    if (result.status === 'pushed') {
      toast({
        variant: 'success',
        title: `Template applied to ${supi}`,
        description: 'Policy pushed via NAS ConfigurationUpdateCommand (TS 24.501 §8.2.29).',
      })
    } else {
      toast({
        variant: 'warning',
        title: `Template stored for ${supi}`,
        description: result.warning
          ? `Policy stored — ${result.warning}`
          : 'UE is not registered — the policy is stored and applies on its next registration.',
        duration: result.warning ? 0 : undefined,
      })
    }
  }

  // Per-subscriber policy state
  const [editingPolicy, setEditingPolicy] = useState<Partial<Policy> | null>(null)
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null)
  const [deletePolicyTarget, setDeletePolicyTarget] = useState<Policy | null>(null)

  const createPolMut = useMutation({
    mutationFn: (p: typeof EMPTY_POLICY) => createPolicy(p),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policies'] })
      setEditingPolicy(null)
      toast({ variant: 'success', title: 'Policy created' })
    },
    onError: actionFailed('Create policy'),
  })
  const updatePolMut = useMutation({
    mutationFn: ({ id, p }: { id: string; p: Partial<Policy> }) => updatePolicy(id, p),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policies'] })
      setEditingPolicy(null)
      toast({ variant: 'success', title: 'Policy updated' })
    },
    onError: actionFailed('Update policy'),
  })
  const deletePolMut = useMutation({
    mutationFn: (id: string) => deletePolicy(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policies'] })
      setDeletePolicyTarget(null)
      toast({ variant: 'success', title: 'Policy deleted' })
    },
    onError: actionFailed('Delete policy'),
  })
  const pushMut = useMutation({
    mutationFn: (supi: string) => pushPolicies(supi),
    onSuccess: (_, supi) =>
      toast({
        variant: 'success',
        title: `Policies pushed to ${supi}`,
        description: 'Delivered in a NAS ConfigurationUpdateCommand (TS 24.501 §8.2.29).',
      }),
    onError: actionFailed('Push policies'),
  })

  const newTemplate = () => setEditingTemplate({ ...EMPTY_TEMPLATE, rules: [{ ...EMPTY_RULE }] })
  const newPolicy = () => setEditingPolicy({ ...EMPTY_POLICY, rules: [{ ...EMPTY_RULE }] })

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
    <div className="space-y-8 p-6">
      <PageHeader
        eyebrow="Data & Config"
        title="Policies"
        subtitle="URSP (UE Route Selection Policy) — TS 24.526 / TS 29.525"
      />

      {/* ── Section 1: Policy Templates ── */}
      <Section
        bare
        title="Policy Templates"
        description="Pre-defined URSP rule sets for each network slice. Apply to any registered UE to steer its PDU sessions onto a specific slice."
        actions={
          <Button size="sm" icon={<Plus size={14} />} onClick={newTemplate}>
            New Template
          </Button>
        }
      >
        <div className="space-y-4">
          <SpecReference open={specOpen} onToggle={() => setSpecOpen(o => !o)} />

          {templatesError ? (
            <ErrorState
              title="Failed to load policy templates"
              description={errMessage(templatesErr)}
              action={
                <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchTemplates()}>
                  Retry
                </Button>
              }
            />
          ) : templatesLoading ? (
            <Loading label="Loading templates…" />
          ) : templates.length === 0 ? (
            <EmptyState
              title="No policy templates"
              description="Create one, or restart the portal to re-seed the four slice defaults (Internet / Gold / Silver / Bronze)."
              action={<Button size="sm" icon={<Plus size={14} />} onClick={newTemplate}>New Template</Button>}
            />
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {templates.map(t => (
                <Card key={t.id} interactive className="flex flex-col">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-fg">{t.name}</p>
                      {t.description && (
                        <p className="mt-0.5 text-xs leading-snug text-muted-fg">{t.description}</p>
                      )}
                    </div>
                    <Badge
                      label={SLICE_LABEL[t.slice_name] ?? t.slice_name}
                      variant={sliceVariant(t.slice_name)}
                    />
                  </div>

                  <p className="mt-3 text-xs text-muted-fg">
                    Precedence <span className="font-mono text-fg">{t.precedence}</span>
                    {' · '}
                    <span className="font-mono text-fg">{(t.rules as URSPRule[])?.length ?? 0}</span> rule(s)
                  </p>

                  <button
                    type="button"
                    onClick={() => setExpandedTemplate(expandedTemplate === t.id ? null : t.id)}
                    aria-expanded={expandedTemplate === t.id}
                    aria-controls={`tpl-rules-${t.id}`}
                    className="mt-2 flex items-center gap-1.5 self-start text-xs text-muted-fg transition-colors hover:text-fg"
                  >
                    {expandedTemplate === t.id
                      ? <ChevronUp size={14} aria-hidden="true" />
                      : <ChevronDown size={14} aria-hidden="true" />}
                    {expandedTemplate === t.id ? 'Hide' : 'Show'} JSON rules
                  </button>

                  <pre
                    id={`tpl-rules-${t.id}`}
                    hidden={expandedTemplate !== t.id}
                    className="mt-2 max-h-52 overflow-x-auto rounded-control border border-border bg-muted/40 px-3 py-2 font-mono text-xs text-fg"
                  >
                    {JSON.stringify(t.rules, null, 2)}
                  </pre>

                  <div className="mt-3 flex items-center gap-2">
                    <Button size="sm" icon={<Send size={12} />} onClick={() => setApplyTarget(t)}>
                      Apply to UE
                    </Button>
                    <Button size="sm" variant="secondary" icon={<Pencil size={12} />} onClick={() => setEditingTemplate(t)}>
                      Edit
                    </Button>
                    <IconButton
                      label={`Delete template ${t.name}`}
                      variant="ghost"
                      className="ml-auto"
                      onClick={() => setDeleteTemplateTarget(t)}
                    >
                      <Trash2 size={14} />
                    </IconButton>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </Section>

      {/* ── Section 2: Per-Subscriber Policies ── */}
      <Section
        bare
        title="Per-Subscriber Policies"
        description="Active URSP overrides written to subscription_policy. Empty SUPI = operator default for all subscribers."
        actions={
          <Button size="sm" icon={<Plus size={14} />} onClick={newPolicy}>
            New Policy
          </Button>
        }
      >
        {policiesError ? (
          <ErrorState
            title="Failed to load policies"
            description={errMessage(policiesErr)}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchPolicies()}>
                Retry
              </Button>
            }
          />
        ) : (
          <Table caption="Per-subscriber URSP policies">
            <TableHead>
              <TableRow>
                <TableHeaderCell className="w-12">
                  <span className="sr-only">Rules</span>
                </TableHeaderCell>
                <TableHeaderCell>SUPI</TableHeaderCell>
                <TableHeaderCell>Precedence</TableHeaderCell>
                <TableHeaderCell>Rules</TableHeaderCell>
                <TableHeaderCell className="text-right">Actions</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {policiesLoading ? (
                <TableEmptyRow colSpan={5}>
                  <Loading rows={3} label="Loading policies…" />
                </TableEmptyRow>
              ) : policies.length === 0 ? (
                <TableEmptyRow colSpan={5}>
                  No per-subscriber policies. Apply a template above or create a custom policy.
                </TableEmptyRow>
              ) : (
                policies.map(p => {
                  const expanded = expandedPolicy === p.id
                  const label = p.supi || 'the operator default policy'
                  return (
                    <Fragment key={p.id}>
                      <TableRow>
                        <TableCell>
                          <IconButton
                            label={`${expanded ? 'Hide' : 'Show'} URSP rules for ${label}`}
                            variant="ghost"
                            aria-expanded={expanded}
                            aria-controls={expanded ? `pol-rules-${p.id}` : undefined}
                            onClick={() => setExpandedPolicy(expanded ? null : p.id)}
                          >
                            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                          </IconButton>
                        </TableCell>
                        <TableCell mono>
                          {p.supi || <span className="font-sans text-muted-fg">Default (all subscribers)</span>}
                        </TableCell>
                        <TableCell mono>{p.precedence}</TableCell>
                        <TableCell className="text-xs text-muted-fg">
                          {(p.rules as URSPRule[])?.length ?? 0}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            {p.supi && (
                              <Button
                                size="sm"
                                icon={<Send size={12} />}
                                disabled={pushMut.isPending}
                                loading={pushMut.isPending && pushMut.variables === p.supi}
                                onClick={() => pushMut.mutate(p.supi)}
                              >
                                Push
                              </Button>
                            )}
                            <Button size="sm" variant="secondary" icon={<Pencil size={12} />} onClick={() => setEditingPolicy(p)}>
                              Edit
                            </Button>
                            <IconButton
                              label={`Delete policy for ${label}`}
                              variant="ghost"
                              onClick={() => setDeletePolicyTarget(p)}
                            >
                              <Trash2 size={14} />
                            </IconButton>
                          </div>
                        </TableCell>
                      </TableRow>
                      {expanded && (
                        <TableRow>
                          <TableCell colSpan={5} id={`pol-rules-${p.id}`} className="bg-muted/40">
                            <pre className="overflow-x-auto font-mono text-xs text-fg">
                              {JSON.stringify(p.rules, null, 2)}
                            </pre>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  )
                })
              )}
            </TableBody>
          </Table>
        )}
      </Section>

      {/* Template editor */}
      {editingTemplate !== null && (
        <TemplateEditor
          editing={editingTemplate}
          onChange={setEditingTemplate}
          onSave={saveTemplate}
          onClose={() => setEditingTemplate(null)}
          isPending={createTplMut.isPending || updateTplMut.isPending}
        />
      )}

      {/* Per-subscriber policy editor */}
      {editingPolicy !== null && (
        <PolicyEditor
          editing={editingPolicy}
          onChange={setEditingPolicy}
          onSave={savePolicy}
          onClose={() => setEditingPolicy(null)}
          isPending={createPolMut.isPending || updatePolMut.isPending}
        />
      )}

      {/* Apply template to UE */}
      {applyTarget !== null && (
        <ApplyDialog
          template={applyTarget}
          onClose={() => setApplyTarget(null)}
          onSuccess={handleApplySuccess}
        />
      )}

      {/* Delete template — removes it from the portal template store */}
      <ConfirmDialog
        open={deleteTemplateTarget !== null}
        destructive
        title="Delete policy template?"
        description={
          deleteTemplateTarget
            ? `"${deleteTemplateTarget.name}" will be removed from the portal template store. This cannot be undone — policies already applied to a UE are kept.`
            : undefined
        }
        confirmLabel="Delete template"
        loading={deleteTplMut.isPending}
        onConfirm={() => {
          if (deleteTemplateTarget) deleteTplMut.mutate(deleteTemplateTarget.id)
        }}
        onCancel={() => setDeleteTemplateTarget(null)}
      />

      {/* Delete policy — removes the row, does not push anything to the UE */}
      <ConfirmDialog
        open={deletePolicyTarget !== null}
        destructive
        title="Delete URSP policy?"
        description={
          deletePolicyTarget
            ? `The policy for ${deletePolicyTarget.supi || 'all subscribers (operator default)'} will be removed from subscription_policy. Nothing is pushed to the UE — it keeps its current policy until the next update. This cannot be undone.`
            : undefined
        }
        confirmLabel="Delete policy"
        loading={deletePolMut.isPending}
        onConfirm={() => {
          if (deletePolicyTarget) deletePolMut.mutate(deletePolicyTarget.id)
        }}
        onCancel={() => setDeletePolicyTarget(null)}
      />
    </div>
  )
}
