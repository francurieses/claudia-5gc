import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Play, Plus, RefreshCw, Undo2 } from 'lucide-react'
import {
  applySliceQoS, deleteSliceQoS, getDNNs, getQoSSessions, getSlices, getSliceQoS, putSliceQoS,
  type SessionAmbr, type SliceDnnQoS,
} from '../lib/api'
import {
  Badge, Button, Card, Checkbox, ConfirmDialog, ErrorState, Input, Loading, Section, Select,
  Table, TableBody, TableCell, TableEmptyRow, TableHead, TableHeaderCell, TableRow, useToast,
} from './ui'
import type { SelectOption } from './ui'

/**
 * Session-AMBR tab of the Slices page (UDR-003).
 *
 * Edits the subscribed per-(S-NSSAI, DNN) Session-AMBR stored in the UDR
 * (TS 23.501 §5.7.2.6, TS 29.503 §6.1.6.2.9 sessionAmbr). New PDU sessions pick
 * the value up from sm-data; existing sessions keep theirs until the operator
 * presses "Apply to active sessions" (NW-initiated modification, TS 23.502 §4.3.3.2).
 */

const SST_NAMES: Record<number, string> = { 1: 'eMBB', 2: 'URLLC', 3: 'MIoT', 4: 'V2X' }

/** TS 29.571 §5.5.2 BitRate pattern. */
const BITRATE = /^(\d+(?:\.\d+)?) (bps|Kbps|Mbps|Gbps|Tbps)$/
const UNIT_BPS: Record<string, number> = { bps: 1, Kbps: 1e3, Mbps: 1e6, Gbps: 1e9, Tbps: 1e12 }
/** Upper bound accepted by the SMF/UDR: 1 Pbps. */
const MAX_BPS = 1e15
const EXAMPLE_HINT = 'e.g. 20 Mbps'

/** Returns an error message, or undefined when `v` is a valid, positive BitRate. */
export function validateBitRate(v: string): string | undefined {
  const m = BITRATE.exec(v.trim())
  if (!m) return `Use "<number> <unit>", ${EXAMPLE_HINT} (bps, Kbps, Mbps, Gbps, Tbps)`
  const bps = parseFloat(m[1]) * UNIT_BPS[m[2]]
  if (!(bps > 0)) return 'Must be greater than 0'
  if (bps > MAX_BPS) return 'Must not exceed 1 Pbps'
  return undefined
}

/** True when the value is not a whole number of Mbps (SMF mgmt API granularity). */
function fractionalMbps(v: string): boolean {
  const m = BITRATE.exec(v.trim())
  if (!m) return false
  const mbps = (parseFloat(m[1]) * UNIT_BPS[m[2]]) / 1e6
  return mbps !== Math.ceil(mbps)
}

const rowKey = (sst: number, sd: string | undefined, dnn: string) =>
  `${sst}:${(sd ?? '').toLowerCase()}:${dnn.toLowerCase()}`
const itemKey = (i: SliceDnnQoS) => rowKey(i.snssai.sst, i.snssai.sd, i.dnn)
const sliceLabel = (sst: number, sd?: string) =>
  `${sst}${SST_NAMES[sst] ? ` (${SST_NAMES[sst]})` : ''}${sd ? ` / ${sd}` : ''}`
const errMessage = (e: unknown) => (e instanceof Error ? e.message : String(e))

const SOURCE_BADGE: Record<string, { label: string; variant: 'neutral' | 'info' | 'warning' }> = {
  default: { label: 'default', variant: 'neutral' },
  operator: { label: 'operator.yaml', variant: 'info' },
  edited: { label: 'edited', variant: 'warning' },
}

export default function SessionAmbrPanel() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [drafts, setDrafts] = useState<Record<string, SessionAmbr>>({})
  const [applyTarget, setApplyTarget] = useState<SliceDnnQoS | null>(null)
  const [includeOverridden, setIncludeOverridden] = useState(false)
  const [addChoice, setAddChoice] = useState('')
  const [addAmbr, setAddAmbr] = useState<SessionAmbr>({ uplink: '', downlink: '' })

  const { data, isLoading, isError, error, refetch } = useQuery({ queryKey: ['slice-qos'], queryFn: getSliceQoS })
  const items = data?.items ?? []
  const { data: slices = [] } = useQuery({ queryKey: ['slices'], queryFn: getSlices })
  const { data: dnnResp } = useQuery({ queryKey: ['dnns'], queryFn: getDNNs })

  // Live sessions (only while the Apply dialog is open) for the confirmation count.
  const { data: live } = useQuery({
    queryKey: ['qos-sessions', 'apply-count'],
    queryFn: getQoSSessions,
    enabled: applyTarget !== null,
  })
  const matching = useMemo(() => {
    if (!applyTarget || !live) return null
    return live.sessions.filter(s =>
      s.sNssai.sst === applyTarget.snssai.sst &&
      (s.sNssai.sd ?? '').toLowerCase() === (applyTarget.snssai.sd ?? '').toLowerCase() &&
      s.dnn.toLowerCase() === applyTarget.dnn.toLowerCase()).length
  }, [applyTarget, live])

  const addOptions: SelectOption[] = useMemo(() => {
    const listed = new Set(items.map(itemKey))
    const out: SelectOption[] = []
    for (const s of slices) {
      for (const d of dnnResp?.dnns ?? []) {
        if (listed.has(rowKey(s.sst, s.sd, d.name))) continue
        out.push({ value: `${s.sst}|${s.sd ?? ''}|${d.name}`, label: `${sliceLabel(s.sst, s.sd)} — ${d.name}` })
      }
    }
    return out
  }, [items, slices, dnnResp])

  const clearDraft = (k: string) =>
    setDrafts(d => {
      const { [k]: _removed, ...rest } = d
      return rest
    })

  const saveMut = useMutation({
    mutationFn: (v: { item: Pick<SliceDnnQoS, 'snssai' | 'dnn'>; ambr: SessionAmbr }) =>
      putSliceQoS(v.item.snssai.sst, v.item.snssai.sd, v.item.dnn, v.ambr),
    onSuccess: (res, v) => {
      qc.invalidateQueries({ queryKey: ['slice-qos'] })
      clearDraft(rowKey(v.item.snssai.sst, v.item.snssai.sd, v.item.dnn))
      const n = res.resync?.synced
      const failed = res.resync?.failed?.length ?? 0
      toast({
        variant: failed ? 'warning' : 'success',
        title: 'Session-AMBR saved',
        description:
          `${n !== undefined ? `${n} subscriber(s) resynced${failed ? `, ${failed} failed` : ''}. ` : ''}` +
          'New PDU sessions use the new value; active sessions keep theirs until "Apply to active sessions".',
        duration: failed ? 0 : undefined,
      })
    },
    onError: (e) => toast({ variant: 'error', title: 'Save failed', description: errMessage(e), duration: 0 }),
  })

  const revertMut = useMutation({
    mutationFn: (i: SliceDnnQoS) => deleteSliceQoS(i.snssai.sst, i.snssai.sd, i.dnn),
    onSuccess: (_r, i) => {
      qc.invalidateQueries({ queryKey: ['slice-qos'] })
      clearDraft(itemKey(i))
      toast({
        variant: 'success',
        title: 'Reverted to default',
        description: 'Active sessions keep their current value until "Apply to active sessions".',
      })
    },
    onError: (e) => toast({ variant: 'error', title: 'Revert failed', description: errMessage(e), duration: 0 }),
  })

  const applyMut = useMutation({
    mutationFn: (v: { item: SliceDnnQoS; include: boolean }) =>
      applySliceQoS(v.item.snssai.sst, v.item.snssai.sd, v.item.dnn, v.include),
    onSuccess: (r) => {
      setApplyTarget(null)
      const bad = r.failed.length > 0
      toast({
        variant: bad ? 'warning' : 'success',
        title: `Applied ${r.applied.length}, skipped ${r.skipped.length}, failed ${r.failed.length}`,
        description:
          `Target ${r.applied_mbps.ul}/${r.applied_mbps.dl} Mbps UL/DL.` +
          (bad ? ` Failed: ${r.failed.map(f => `${f.supi}#${f.pduSessionId} (${f.cause ?? f.status})`).join(', ')}.` : ''),
        duration: bad ? 0 : undefined,
      })
    },
    onError: (e) => toast({ variant: 'error', title: 'Apply failed', description: errMessage(e), duration: 0 }),
  })

  const addErrors = {
    uplink: addAmbr.uplink ? validateBitRate(addAmbr.uplink) : undefined,
    downlink: addAmbr.downlink ? validateBitRate(addAmbr.downlink) : undefined,
  }
  const canAdd = addChoice !== '' && addAmbr.uplink !== '' && addAmbr.downlink !== '' &&
    !validateBitRate(addAmbr.uplink) && !validateBitRate(addAmbr.downlink)

  const submitAdd = () => {
    const [sst, sd, dnn] = addChoice.split('|')
    saveMut.mutate(
      { item: { snssai: { sst: Number(sst), sd: sd || undefined }, dnn }, ambr: { uplink: addAmbr.uplink.trim(), downlink: addAmbr.downlink.trim() } },
      { onSuccess: () => { setAddChoice(''); setAddAmbr({ uplink: '', downlink: '' }) } },
    )
  }

  if (isError) {
    return (
      <ErrorState
        title="Failed to load Session-AMBR"
        description={errMessage(error)}
        action={<Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>Retry</Button>}
      />
    )
  }

  return (
    <div className="space-y-6">
      <Section
        title="Subscribed Session-AMBR per slice and DNN"
        description={`Stored in the UDR and served as sm-data (TS 29.503 §6.1.6.2.9). Format ${EXAMPLE_HINT}. New PDU sessions pick the value up automatically; existing sessions keep theirs until you apply it. A PCF per-UE override still takes precedence.`}
      >
        <Table caption="Session-AMBR per S-NSSAI and DNN">
          <TableHead>
            <TableRow>
              <TableHeaderCell>S-NSSAI</TableHeaderCell>
              <TableHeaderCell>DNN</TableHeaderCell>
              <TableHeaderCell>Session-AMBR UL</TableHeaderCell>
              <TableHeaderCell>Session-AMBR DL</TableHeaderCell>
              <TableHeaderCell>Source</TableHeaderCell>
              <TableHeaderCell>Default (UL / DL)</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={7}><Loading rows={3} label="Loading Session-AMBR…" /></TableEmptyRow>
            ) : items.length === 0 ? (
              <TableEmptyRow colSpan={7}>No slice/DNN Session-AMBR entries</TableEmptyRow>
            ) : (
              items.map(item => {
                const k = itemKey(item)
                const draft = drafts[k] ?? item.sessionAmbr
                const ulErr = validateBitRate(draft.uplink)
                const dlErr = validateBitRate(draft.downlink)
                const dirty = draft.uplink.trim() !== item.sessionAmbr.uplink || draft.downlink.trim() !== item.sessionAmbr.downlink
                const badge = SOURCE_BADGE[item.source] ?? SOURCE_BADGE.default
                const saving = saveMut.isPending && saveMut.variables &&
                  rowKey(saveMut.variables.item.snssai.sst, saveMut.variables.item.snssai.sd, saveMut.variables.item.dnn) === k
                const coarse = fractionalMbps(item.sessionAmbr.uplink) || fractionalMbps(item.sessionAmbr.downlink)
                const label = `${sliceLabel(item.snssai.sst, item.snssai.sd)} ${item.dnn}`
                return (
                  <TableRow key={k}>
                    <TableCell mono>{sliceLabel(item.snssai.sst, item.snssai.sd)}</TableCell>
                    <TableCell mono>{item.dnn}</TableCell>
                    <TableCell>
                      <Input
                        aria-label={`Session-AMBR UL for ${label}`}
                        invalid={!!ulErr}
                        value={draft.uplink}
                        placeholder={EXAMPLE_HINT}
                        onChange={e => setDrafts(d => ({ ...d, [k]: { ...draft, uplink: e.target.value } }))}
                        className="w-32 font-mono"
                      />
                      {ulErr && dirty && <p role="alert" className="mt-1 text-xs text-danger-fg">{ulErr}</p>}
                    </TableCell>
                    <TableCell>
                      <Input
                        aria-label={`Session-AMBR DL for ${label}`}
                        invalid={!!dlErr}
                        value={draft.downlink}
                        placeholder={EXAMPLE_HINT}
                        onChange={e => setDrafts(d => ({ ...d, [k]: { ...draft, downlink: e.target.value } }))}
                        className="w-32 font-mono"
                      />
                      {dlErr && dirty && <p role="alert" className="mt-1 text-xs text-danger-fg">{dlErr}</p>}
                    </TableCell>
                    <TableCell>
                      <Badge variant={badge.variant} label={badge.label} />
                      {coarse && (
                        <p className="mt-1 text-xs text-muted-fg">Enforced in whole Mbps (rounded up) via a PCF or Apply.</p>
                      )}
                    </TableCell>
                    <TableCell mono className="text-muted-fg">
                      {item.defaultSessionAmbr.uplink} / {item.defaultSessionAmbr.downlink}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <Button
                          size="sm"
                          icon={<Check size={14} />}
                          disabled={!dirty || !!ulErr || !!dlErr || !!saving}
                          loading={!!saving}
                          onClick={() => saveMut.mutate({ item, ambr: { uplink: draft.uplink.trim(), downlink: draft.downlink.trim() } })}
                        >
                          Save
                        </Button>
                        {item.source === 'edited' && (
                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<Undo2 size={14} />}
                            loading={revertMut.isPending && revertMut.variables === item}
                            disabled={revertMut.isPending}
                            onClick={() => revertMut.mutate(item)}
                          >
                            Revert
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="secondary"
                          icon={<Play size={14} />}
                          disabled={dirty}
                          onClick={() => { setIncludeOverridden(false); setApplyTarget(item) }}
                        >
                          Apply to active sessions
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      </Section>

      <Card className="max-w-2xl">
        <h2 className="mb-3 text-sm font-semibold text-fg">Add slice/DNN entry</h2>
        <div className="flex flex-wrap items-start gap-3">
          <Select
            aria-label="Slice and DNN to add"
            value={addChoice}
            onChange={e => setAddChoice(e.target.value)}
            options={[{ value: '', label: addOptions.length ? 'Select slice / DNN…' : 'All slice/DNN pairs are listed' }, ...addOptions]}
            disabled={addOptions.length === 0}
          />
          <div>
            <Input
              aria-label="Session-AMBR UL for the new entry"
              placeholder={`UL, ${EXAMPLE_HINT}`}
              invalid={!!addErrors.uplink}
              value={addAmbr.uplink}
              onChange={e => setAddAmbr(a => ({ ...a, uplink: e.target.value }))}
              className="w-36 font-mono"
            />
            {addErrors.uplink && <p role="alert" className="mt-1 text-xs text-danger-fg">{addErrors.uplink}</p>}
          </div>
          <div>
            <Input
              aria-label="Session-AMBR DL for the new entry"
              placeholder={`DL, ${EXAMPLE_HINT}`}
              invalid={!!addErrors.downlink}
              value={addAmbr.downlink}
              onChange={e => setAddAmbr(a => ({ ...a, downlink: e.target.value }))}
              className="w-36 font-mono"
            />
            {addErrors.downlink && <p role="alert" className="mt-1 text-xs text-danger-fg">{addErrors.downlink}</p>}
          </div>
          <Button icon={<Plus size={14} />} disabled={!canAdd || saveMut.isPending} onClick={submitAdd}>
            Add
          </Button>
        </div>
      </Card>

      <ConfirmDialog
        open={applyTarget !== null}
        title="Apply Session-AMBR to active sessions?"
        description={
          applyTarget
            ? `${applyTarget.sessionAmbr.uplink} UL / ${applyTarget.sessionAmbr.downlink} DL will be pushed to ${
                matching === null ? 'the matching' : matching
              } active PDU session(s) on ${sliceLabel(applyTarget.snssai.sst, applyTarget.snssai.sd)} / ${applyTarget.dnn} as a network-initiated modification (no UE re-registration). The SMF takes whole Mbps, rounded up.`
            : undefined
        }
        confirmLabel="Apply"
        loading={applyMut.isPending}
        onConfirm={() => applyTarget && applyMut.mutate({ item: applyTarget, include: includeOverridden })}
        onCancel={() => setApplyTarget(null)}
      >
        <Checkbox
          checked={includeOverridden}
          onChange={setIncludeOverridden}
          label="Also override sessions with a higher-precedence QoS source (PCF override, policy data, manual)"
        />
      </ConfirmDialog>
    </div>
  )
}
