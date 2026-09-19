import { useState, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, Ban, CheckCircle2, Clock, RefreshCw, RotateCw, Send, WifiOff, XCircle,
} from 'lucide-react'
import {
  pwsBroadcast,
  pwsCancel,
  pwsResend,
  getPWSBroadcasts,
  type PWSBroadcastRequest,
  type PWSBroadcastStatus,
  type PWSGNBStatus,
} from '../lib/api'
import {
  Badge, Button, Card, ConfirmDialog, EmptyState, ErrorState, Field, Input, Loading,
  PageHeader, Section, Select, Textarea, useToast,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'

// The DCS and language are derived from the Alphabet + Language selectors
// (see computeDcs); the form itself carries the other IEs.
type PWSFormFields = Required<
  Omit<PWSBroadcastRequest, 'warningAreaTacs' | 'dataCodingScheme' | 'language'>
>

// 3GPP-legal defaults for every Write-Replace Warning IE (TS 38.413 §8.9.1,
// TS 23.041). The AMF applies the same defaults for any omitted field; these
// mirror them so the operator sees exactly what will be broadcast.
const DEFAULTS: PWSFormFields = {
  messageIdentifier: 4370, // 0x1112 — ETWS-scoped test identifier
  serialNumber: 1,
  repetitionPeriod: 4096, // TS 38.413 §9.3.1.50
  numberOfBroadcastsRequested: 1,
  warningType: '0000', // 2-octet: warning-type "Other" (TS 23.041 §9.4.1.2.6)
  messageText: 'Emergency alert: this is a test of the Public Warning System.',
}

// Human-readable warning-type presets (TS 23.041 §9.4.1.2.6 warning-type value).
const WARNING_TYPES: { label: string; value: string }[] = [
  { label: 'Earthquake', value: '0000' },
  { label: 'Tsunami', value: '0001' },
  { label: 'Earthquake and Tsunami', value: '0002' },
  { label: 'Test', value: '0003' },
  { label: 'Other', value: '0004' },
]

// The 3 alphabets the AMF encoder supports (TS 23.038 §5). The message text is
// packed/encoded to match; picking GSM 7-bit for CJK text makes the AMF fall
// unmappable characters back to '?'.
type Alphabet = 'gsm7' | 'ucs2' | '8bit'
const ALPHABETS: { label: string; value: Alphabet }[] = [
  { label: 'GSM 7-bit', value: 'gsm7' },
  { label: 'UCS2 / Unicode', value: 'ucs2' },
  { label: '8-bit data', value: '8bit' },
]

// Cell Broadcast languages (TS 23.038 §5). `gsm7Dcs` is the DCS byte that names
// this language directly in the GSM 7-bit language coding groups (0000/0010) —
// languages without one (CJK) can only be tagged under UCS2, where the language
// travels as a 2-char ISO 639 prefix inside the message (DCS 0x11).
type Language = { name: string; iso: string; gsm7Dcs?: number }
const LANGUAGES: Language[] = [
  { name: 'Unspecified', iso: '' },
  { name: 'German', iso: 'de', gsm7Dcs: 0x00 },
  { name: 'English', iso: 'en', gsm7Dcs: 0x01 },
  { name: 'Italian', iso: 'it', gsm7Dcs: 0x02 },
  { name: 'French', iso: 'fr', gsm7Dcs: 0x03 },
  { name: 'Spanish', iso: 'es', gsm7Dcs: 0x04 },
  { name: 'Dutch', iso: 'nl', gsm7Dcs: 0x05 },
  { name: 'Swedish', iso: 'sv', gsm7Dcs: 0x06 },
  { name: 'Danish', iso: 'da', gsm7Dcs: 0x07 },
  { name: 'Portuguese', iso: 'pt', gsm7Dcs: 0x08 },
  { name: 'Finnish', iso: 'fi', gsm7Dcs: 0x09 },
  { name: 'Norwegian', iso: 'no', gsm7Dcs: 0x0a },
  { name: 'Greek', iso: 'el', gsm7Dcs: 0x0b },
  { name: 'Turkish', iso: 'tr', gsm7Dcs: 0x0c },
  { name: 'Hungarian', iso: 'hu', gsm7Dcs: 0x0d },
  { name: 'Polish', iso: 'pl', gsm7Dcs: 0x0e },
  { name: 'Czech', iso: 'cs', gsm7Dcs: 0x20 },
  { name: 'Hebrew', iso: 'he', gsm7Dcs: 0x21 },
  { name: 'Arabic', iso: 'ar', gsm7Dcs: 0x22 },
  { name: 'Russian', iso: 'ru', gsm7Dcs: 0x23 },
  { name: 'Icelandic', iso: 'is', gsm7Dcs: 0x24 },
  { name: 'Japanese', iso: 'ja' },
  { name: 'Chinese', iso: 'zh' },
  { name: 'Korean', iso: 'ko' },
]

// languagesFor returns the languages selectable under an alphabet: GSM 7-bit
// only the coding-group ones (+ Unspecified), UCS2 all of them (via prefix),
// 8-bit none (raw data carries no language).
function languagesFor(alphabet: Alphabet): Language[] {
  if (alphabet === '8bit') return [LANGUAGES[0]]
  if (alphabet === 'gsm7') return LANGUAGES.filter((l) => l.iso === '' || l.gsm7Dcs !== undefined)
  return LANGUAGES
}

// computeDcs derives the CBS Data Coding Scheme byte from the alphabet +
// language (TS 23.038 §5): GSM 7-bit uses the language coding group (0x0F when
// unspecified), UCS2 uses 0x11 (language prefix) when a language is chosen else
// 0x48, 8-bit is always 0xF4.
function computeDcs(alphabet: Alphabet, iso: string): number {
  if (alphabet === '8bit') return 0xf4
  if (alphabet === 'gsm7') {
    const l = LANGUAGES.find((x) => x.iso === iso)
    return l && l.gsm7Dcs !== undefined ? l.gsm7Dcs : 0x0f
  }
  return iso ? 0x11 : 0x48
}

// broadcastStatus derives the lifecycle badge for a broadcast (TS 38.413 §8.9).
// "Completed" means every targeted gNB acknowledged the Write-Replace Warning
// (the alert is being broadcast over the air until cancelled); it is still
// cancellable. A broadcast accepted with no gNB connected (gnbs_targeted 0)
// can never complete, so it gets its own state. A stored warning the AMF no
// longer has runtime state for (live:false — after an AMF restart) is "Stored"
// and can be re-driven (resend) to re-establish it at the gNBs.
//
// The colour is never the only cue: each state carries a distinct icon AND a
// label that spells the state (WCAG 1.4.1), so the lifecycle survives greyscale.
type BroadcastState = 'cancelled' | 'stored' | 'no-gnb' | 'completed' | 'pending'

const BROADCAST_STATUS: Record<BroadcastState, { label: string; variant: BadgeVariant; icon: ReactNode }> = {
  cancelled: { label: 'Cancelled', variant: 'neutral', icon: <Ban size={12} /> },
  stored: {
    label: 'Stored — AMF restarted, resend to re-establish',
    variant: 'warning',
    icon: <RotateCw size={12} />,
  },
  'no-gnb': { label: 'No gNB connected', variant: 'warning', icon: <WifiOff size={12} /> },
  completed: { label: 'Completed — broadcasting', variant: 'success', icon: <CheckCircle2 size={12} /> },
  pending: { label: 'Pending gNB ack', variant: 'warning', icon: <Clock size={12} /> },
}

function broadcastStatus(
  b: PWSBroadcastStatus,
): { state: BroadcastState; label: string; variant: BadgeVariant; icon: ReactNode } {
  let state: BroadcastState
  if (b.cancelled) state = 'cancelled'
  else if (b.stored && b.live === false) state = 'stored'
  else if (b.gnbs_targeted === 0) state = 'no-gnb'
  else if (b.gnbs_completed >= b.gnbs_targeted) state = 'completed'
  else state = 'pending'
  return { state, ...BROADCAST_STATUS[state] }
}

// Per-gNB outcome (Write-Replace Warning Response / PWS Cancel Response). The
// state word is always rendered, so the colour/icon is a reinforcement only.
type GNBState = 'completed' | 'cancelled' | 'failed' | 'pending'

const GNB_STATUS: Record<GNBState, { label: string; icon: ReactNode; textClass: string }> = {
  completed: { label: 'completed', icon: <CheckCircle2 size={12} />, textClass: 'text-success-fg' },
  cancelled: { label: 'cancelled', icon: <Ban size={12} />, textClass: 'text-muted-fg' },
  failed: { label: 'failed', icon: <XCircle size={12} />, textClass: 'text-danger-fg' },
  pending: { label: 'pending', icon: <Clock size={12} />, textClass: 'text-warning-fg' },
}

function gnbStatus(g: PWSGNBStatus): { label: string; icon: ReactNode; textClass: string } {
  const state: GNBState = g.completed ? 'completed' : g.cancelled ? 'cancelled' : g.failed ? 'failed' : 'pending'
  return GNB_STATUS[state]
}

// The first action the operator asked for; drives the shared ConfirmDialog.
type ConfirmTarget = { kind: 'cancel' | 'resend'; mid: number; sn: number }

export default function PublicWarning() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [form, setForm] = useState<PWSFormFields>({ ...DEFAULTS })
  const [alphabet, setAlphabet] = useState<Alphabet>('gsm7')
  const [language, setLanguage] = useState<string>('') // ISO 639 code; '' = unspecified
  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null)

  const dataCodingScheme = computeDcs(alphabet, language)

  // Keep the language valid for the selected alphabet (e.g. switching to 8-bit,
  // or to GSM 7-bit while Japanese is picked, falls back to Unspecified).
  const onAlphabetChange = (a: Alphabet) => {
    setAlphabet(a)
    if (!languagesFor(a).some((l) => l.iso === language)) setLanguage('')
  }

  const {
    data: broadcasts = [],
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery({
    queryKey: ['pws-broadcasts'],
    queryFn: getPWSBroadcasts,
    refetchInterval: 3000,
  })

  const broadcastMut = useMutation({
    mutationFn: () => pwsBroadcast({ ...form, dataCodingScheme, language }),
    onSuccess: (ack) => {
      toast({
        variant: 'success',
        title: 'Broadcast sent',
        description: `messageId ${ack.messageIdentifier}, serial ${ack.serialNumber}, ${ack.gnbs_targeted} gNB(s) targeted.`,
      })
      qc.invalidateQueries({ queryKey: ['pws-broadcasts'] })
    },
    onError: (e: Error) =>
      toast({ variant: 'error', title: 'Broadcast failed', description: e.message, duration: 0 }),
  })

  const cancelMut = useMutation({
    mutationFn: ({ mid, sn }: { mid: number; sn: number }) => pwsCancel(mid, sn),
    onSuccess: (ack) => {
      setConfirmTarget(null)
      toast({
        variant: 'success',
        title: 'Cancel sent',
        description: `messageId ${ack.messageIdentifier}, serial ${ack.serialNumber}, ${ack.gnbs_targeted} gNB(s) targeted.`,
      })
      qc.invalidateQueries({ queryKey: ['pws-broadcasts'] })
    },
    onError: (e: Error) =>
      toast({ variant: 'error', title: 'Cancel failed', description: e.message, duration: 0 }),
  })

  const resendMut = useMutation({
    mutationFn: ({ mid, sn }: { mid: number; sn: number }) => pwsResend(mid, sn),
    onSuccess: (ack) => {
      setConfirmTarget(null)
      toast({
        variant: 'success',
        title: 'Re-broadcast',
        description: `messageId ${ack.messageIdentifier}, serial ${ack.serialNumber}, ${ack.gnbs_targeted} gNB(s) targeted.`,
      })
      qc.invalidateQueries({ queryKey: ['pws-broadcasts'] })
    },
    onError: (e: Error) =>
      toast({ variant: 'error', title: 'Re-broadcast failed', description: e.message, duration: 0 }),
  })

  const set = <K extends keyof PWSFormFields>(k: K, v: PWSFormFields[K]) =>
    setForm((f) => ({ ...f, [k]: v }))

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Safety"
        title="Public Warning System"
        subtitle="Cell Broadcast Centre (CBC) — NGAP Write-Replace Warning / PWS Cancel (TS 38.413 §8.9, TS 23.041)"
        action={
          <Button
            size="sm"
            variant="secondary"
            icon={<RefreshCw size={14} />}
            loading={isFetching}
            onClick={() => refetch()}
          >
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* ---- Compose form ---- */}
        <Section
          title="Compose Warning"
          description="Sends a Write-Replace Warning to every configured TAC — the alert goes on the air as soon as it is sent."
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="Message Identifier">
                {({ id }) => (
                  <Input
                    id={id}
                    type="number"
                    value={form.messageIdentifier}
                    onChange={(e) => set('messageIdentifier', Number(e.target.value))}
                  />
                )}
              </Field>
              <Field label="Serial Number">
                {({ id }) => (
                  <Input
                    id={id}
                    type="number"
                    value={form.serialNumber}
                    onChange={(e) => set('serialNumber', Number(e.target.value))}
                  />
                )}
              </Field>
              <Field label="Warning Type">
                {({ id }) => (
                  <Select
                    id={id}
                    value={form.warningType}
                    onChange={(e) => set('warningType', e.target.value)}
                    options={WARNING_TYPES.map((wt) => ({
                      value: wt.value,
                      label: `${wt.label} (0x${wt.value})`,
                    }))}
                  />
                )}
              </Field>
              <Field label="Alphabet">
                {({ id }) => (
                  <Select
                    id={id}
                    value={alphabet}
                    onChange={(e) => onAlphabetChange(e.target.value as Alphabet)}
                    options={ALPHABETS.map((a) => ({ value: a.value, label: a.label }))}
                  />
                )}
              </Field>
              <Field
                label="Language"
                hint={
                  alphabet === '8bit'
                    ? '8-bit data carries no language.'
                    : undefined
                }
              >
                {({ id, describedBy }) => (
                  <Select
                    id={id}
                    aria-describedby={describedBy}
                    value={language}
                    disabled={alphabet === '8bit'}
                    onChange={(e) => setLanguage(e.target.value)}
                    options={languagesFor(alphabet).map((l) => ({
                      value: l.iso,
                      label: `${l.name}${l.iso ? ` (${l.iso})` : ''}`,
                    }))}
                  />
                )}
              </Field>
              <Field label="Repetition Period (s)">
                {({ id }) => (
                  <Input
                    id={id}
                    type="number"
                    value={form.repetitionPeriod}
                    onChange={(e) => set('repetitionPeriod', Number(e.target.value))}
                  />
                )}
              </Field>
              <Field label="Number of Broadcasts">
                {({ id }) => (
                  <Input
                    id={id}
                    type="number"
                    value={form.numberOfBroadcastsRequested}
                    onChange={(e) => set('numberOfBroadcastsRequested', Number(e.target.value))}
                  />
                )}
              </Field>
            </div>

            <Field label="Warning Message Contents">
              {({ id }) => (
                <Textarea
                  id={id}
                  rows={3}
                  value={form.messageText}
                  onChange={(e) => set('messageText', e.target.value)}
                  className="resize-none"
                />
              )}
            </Field>

            <p className="text-xs text-muted-fg">
              Data Coding Scheme{' '}
              <span className="font-mono text-fg">
                0x{dataCodingScheme.toString(16).padStart(2, '0').toUpperCase()}
              </span>{' '}
              derived from Alphabet + Language (TS 23.038 §5). GSM 7-bit carries the language in the DCS
              byte; UCS2 with a language uses DCS 0x11 (ISO 639 prefix inside the message). Warning Area
              defaults to a TAI list over every configured TAC. Warning Security Info is a zero-filled dev
              placeholder (not real ETWS security).
            </p>

            <Button
              className="w-full"
              icon={<Send size={15} />}
              loading={broadcastMut.isPending}
              onClick={() => broadcastMut.mutate()}
            >
              {broadcastMut.isPending ? 'Sending…' : 'Send Broadcast'}
            </Button>
          </div>
        </Section>

        {/* ---- Active broadcasts (CBC store ⊕ AMF live status) ---- */}
        <Section
          title="Broadcasts"
          description="Merged view — CBC store of record ⊕ AMF live per-gNB status (refreshes every 3 s, survives an AMF restart)."
        >
          {isLoading ? (
            <Loading rows={3} label="Loading broadcasts…" />
          ) : error ? (
            <ErrorState
              title="Failed to load broadcasts"
              description={(error as Error).message}
              action={
                <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
                  Retry
                </Button>
              }
            />
          ) : broadcasts.length === 0 ? (
            <EmptyState
              icon={<AlertTriangle size={28} />}
              title="No broadcasts yet"
              description="Compose a warning on the left and send it to create the first Cell Broadcast."
            />
          ) : (
            <div className="space-y-3">
              {broadcasts.map((b: PWSBroadcastStatus) => {
                const status = broadcastStatus(b)
                return (
                  <Card key={`${b.message_identifier}-${b.serial_number}`}>
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0 text-sm text-fg">
                        msgId <span className="font-mono">{b.message_identifier}</span> · serial{' '}
                        <span className="font-mono">{b.serial_number}</span>{' '}
                        <Badge label={status.label} variant={status.variant} icon={status.icon} />
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {status.state === 'stored' && (
                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<RotateCw size={12} />}
                            loading={resendMut.isPending}
                            title="Re-broadcast this stored warning to re-establish it at the gNBs (CBC re-drive after AMF restart)"
                            onClick={() =>
                              setConfirmTarget({
                                kind: 'resend',
                                mid: b.message_identifier,
                                sn: b.serial_number,
                              })
                            }
                          >
                            Resend
                          </Button>
                        )}
                        {!b.cancelled && (
                          <Button
                            size="sm"
                            variant="destructive"
                            icon={<Ban size={12} />}
                            loading={cancelMut.isPending}
                            title="Send PWS Cancel Request (TS 38.413 §8.9.2)"
                            onClick={() =>
                              setConfirmTarget({
                                kind: 'cancel',
                                mid: b.message_identifier,
                                sn: b.serial_number,
                              })
                            }
                          >
                            Stop Broadcast
                          </Button>
                        )}
                      </div>
                    </div>
                    {b.message_text && (
                      <div className="mt-1.5 truncate text-xs text-muted-fg">
                        <span className="text-fg">“{b.message_text}”</span>
                        {b.language && b.language !== 'unspecified' && (
                          <span className="ml-1">· {b.language}</span>
                        )}
                        {typeof b.data_coding_scheme === 'number' && (
                          <span className="ml-1 font-mono">
                            DCS 0x{b.data_coding_scheme.toString(16).padStart(2, '0').toUpperCase()}
                          </span>
                        )}
                      </div>
                    )}
                    <div className="mt-2 text-xs text-muted-fg">
                      gNBs: {b.gnbs_completed}/{b.gnbs_targeted} completed
                      {b.gnbs_cancelled > 0 && ` · ${b.gnbs_cancelled} cancelled`}
                    </div>
                    {b.per_gnb && b.per_gnb.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {b.per_gnb.map((g, i) => {
                          const gs = gnbStatus(g)
                          return (
                            <div key={i} className={`flex items-center gap-2 text-xs ${gs.textClass}`}>
                              <span aria-hidden="true" className="flex-shrink-0">
                                {gs.icon}
                              </span>
                              <span className="font-mono text-fg">{g.gnb_name || g.gnb_addr || 'gNB'}</span>
                              <span>{gs.label}</span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </Card>
                )
              })}
            </div>
          )}
        </Section>
      </div>

      {/* Cancel and Resend both reach the RAN — confirm before driving the network. */}
      <ConfirmDialog
        open={confirmTarget !== null}
        destructive={confirmTarget?.kind === 'cancel'}
        title={confirmTarget?.kind === 'resend' ? 'Re-broadcast stored warning?' : 'Stop this broadcast?'}
        description={
          confirmTarget?.kind === 'resend'
            ? `msgId ${confirmTarget.mid} · serial ${confirmTarget.sn} will be re-driven to the RAN — gNBs that no longer hold it start broadcasting again (CBC re-drive, TS 23.007 §16).`
            : confirmTarget
              ? `A PWS Cancel Request is sent for msgId ${confirmTarget.mid} · serial ${confirmTarget.sn} — every targeted gNB stops the broadcast (TS 38.413 §8.9.2).`
              : undefined
        }
        confirmLabel={confirmTarget?.kind === 'resend' ? 'Re-broadcast' : 'Send cancel'}
        loading={cancelMut.isPending || resendMut.isPending}
        onCancel={() => setConfirmTarget(null)}
        onConfirm={() => {
          if (!confirmTarget) return
          if (confirmTarget.kind === 'resend') {
            resendMut.mutate({ mid: confirmTarget.mid, sn: confirmTarget.sn })
          } else {
            cancelMut.mutate({ mid: confirmTarget.mid, sn: confirmTarget.sn })
          }
        }}
      />
    </div>
  )
}
