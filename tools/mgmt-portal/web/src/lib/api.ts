const BASE = '/api/v1'

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    const e = err as { error?: string; detail?: string }
    throw new Error(e.error || e.detail || res.statusText)
  }
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

// ---- Types ---------------------------------------------------------------

export interface SNSSAI { sst: number; sd: string; dnn?: string }

export interface Subscriber {
  supi: string
  k: string
  opc: string
  amf: string
  sqn: string
  slices: SNSSAI[]
  ambr_ul: number
  ambr_dl: number
}

export interface Service {
  id: string
  name: string
  image: string
  status: string
  state: string
  created: number
  uptime: string
}

export interface NFStatus {
  name: string
  registered: boolean
  healthz_ok: boolean
  metrics_ok: boolean
}

export interface PDUSession {
  ref: string
  supi: string
  dnn: string
  ue_ip: string
  ul_teid: number
  sst: number
  sd: string
  created_at: string
}

export interface UEContext {
  supi: string
  tmsi: number
  gmm_state: number
  created_at: string
}

export interface MetricsSummary {
  ue_registered: number
  pdu_sessions: number
  /**
   * Instant 5-minute success rates (PORTAL-UI-21). `null` means the window had
   * no data (or the ratio was NaN) — render "—", never a fake 0%/100%.
   */
  registration_success_pct: number | null
  pdu_session_establishment_success_pct: number | null
  procedure_rates: Record<string, number>
  nf_up: Record<string, boolean>
}

export interface PCAPStatus {
  nf: string
  container: string
  capturing: boolean
  paused: boolean
  files: number
}

export interface PCAPFile {
  name: string
  size_bytes: number
  mod_time: string
}

// ---- Subscribers ---------------------------------------------------------

export const getSubscribers = () => request<Subscriber[]>('GET', '/subscribers')
export const getSubscriber = (supi: string) => request<Subscriber>('GET', `/subscribers/${encodeURIComponent(supi)}`)
export const createSubscriber = (sub: Omit<Subscriber, 'sqn' | 'amf'> & { sqn?: string; amf?: string }) =>
  request<{ supi: string }>('POST', '/subscribers', sub)
export interface UpdateSubscriberResult { supi: string; deregistered: boolean }

export const updateSubscriber = (supi: string, sub: Partial<Subscriber>) =>
  request<UpdateSubscriberResult>('PUT', `/subscribers/${encodeURIComponent(supi)}`, sub)
export const deleteSubscriber = (supi: string) =>
  request<void>('DELETE', `/subscribers/${encodeURIComponent(supi)}`)

// ---- Per-subscriber RFSP (Radio Frequency Selection Priority) -------------
// RFSP index (1-256) sent to the gNB in the NGAP InitialContextSetupRequest
// (TS 38.413 §9.3.1.27). "override" = per-subscriber value set here; "default" = operator default.
export interface SubscriberRFSP {
  supi: string
  rfsp: number
  source: 'override' | 'default'
  deregistered?: boolean
}

export const getSubscriberRFSP = (supi: string) =>
  request<SubscriberRFSP>('GET', `/subscribers/${encodeURIComponent(supi)}/rfsp`)
export const setSubscriberRFSP = (supi: string, rfsp: number) =>
  request<SubscriberRFSP>('PUT', `/subscribers/${encodeURIComponent(supi)}/rfsp`, { rfsp })
export const resetSubscriberRFSP = (supi: string) =>
  request<SubscriberRFSP>('DELETE', `/subscribers/${encodeURIComponent(supi)}/rfsp`)

// ---- Slices --------------------------------------------------------------

export interface AddSliceResult { slice: SNSSAI; restarted: string[] }
export interface DeleteSliceResult { restarted: string[] }

export const getSlices = () => request<SNSSAI[]>('GET', '/slices')
export const addSlice = (slice: SNSSAI, restart = false) =>
  request<AddSliceResult>('POST', '/slices', { ...slice, restart })
export const deleteSlice = (sst: number, sd: string, restart = false) =>
  request<DeleteSliceResult>('DELETE', `/slices/${sst}/${sd}?restart=${restart}`)

// ---- Slice/DNN Session-AMBR (UDR-003, TS 23.501 §5.7.2.6) -----------------

export interface SessionAmbr { uplink: string; downlink: string }
export type SliceQoSSource = 'default' | 'operator' | 'edited'

/** UDR SliceDnnQos object (non-3GPP internal API, relayed by the portal). */
export interface SliceDnnQoS {
  snssai: { sst: number; sd?: string }
  dnn: string
  sessionAmbr: SessionAmbr
  source: SliceQoSSource
  defaultSessionAmbr: SessionAmbr
  defaultSource: 'default' | 'operator'
  updatedAt: string
}

export interface SliceQoSResync {
  affectedSubscribers: number
  synced: number
  failed?: { supi: string; error: string }[]
}
export interface SliceQoSWriteResult { item: SliceDnnQoS; changed: boolean; resync?: SliceQoSResync }

export interface SliceQoSApplyResult {
  sessionAmbr: SessionAmbr
  applied_mbps: { ul: number; dl: number }
  matched: number
  applied: { supi: string; pduSessionId: number }[]
  skipped: { supi: string; pduSessionId: number; qosSource?: string; reason: string }[]
  failed: { supi: string; pduSessionId: number; status: number; cause?: string; detail?: string }[]
}

/** Path segment for an S-NSSAI: SD lower-case hex, "-" when there is no SD. */
const qosPath = (sst: number, sd: string | undefined, dnn: string) =>
  `/slices/qos/${sst}/${sd ? sd : '-'}/${encodeURIComponent(dnn)}`

export const getSliceQoS = () => request<{ items: SliceDnnQoS[] }>('GET', '/slices/qos')
export const putSliceQoS = (sst: number, sd: string | undefined, dnn: string, ambr: SessionAmbr) =>
  request<SliceQoSWriteResult>('PUT', qosPath(sst, sd, dnn), { sessionAmbr: ambr })
export const deleteSliceQoS = (sst: number, sd: string | undefined, dnn: string) =>
  request<SliceQoSWriteResult>('DELETE', qosPath(sst, sd, dnn))
export const applySliceQoS = (sst: number, sd: string | undefined, dnn: string, includeOverridden = false) =>
  request<SliceQoSApplyResult>('POST', `${qosPath(sst, sd, dnn)}/apply`, { include_overridden: includeOverridden })

// ---- Services ------------------------------------------------------------

export const getServices = () => request<Service[]>('GET', '/services')
export const startService = (name: string) => request<{ status: string }>('POST', `/services/${name}/start`)
export const stopService = (name: string) => request<{ status: string }>('POST', `/services/${name}/stop`)
export const restartService = (name: string) => request<{ status: string }>('POST', `/services/${name}/restart`)

// ---- NF Status -----------------------------------------------------------

export const getNFStatus = () => request<NFStatus[]>('GET', '/nf-status')

// ---- Sessions ------------------------------------------------------------

export const getSessions = () => request<PDUSession[]>('GET', '/sessions')
export const getUEContexts = () => request<UEContext[]>('GET', '/ue-contexts')

// ---- UE Location (Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2) ----

export interface UELocation {
  supi: string
  gmm_state: number
  reachable: boolean
  latitude?: number
  longitude?: number
  accuracy_m?: number
  nr_cell_id?: string
  tac?: string
  plmn?: string
  cause?: string
  timestamp: string
}

export const getLocationSummary = () => request<UELocation[]>('GET', '/location/summary')
export const getUELocation = (supi: string) =>
  request<UELocation>('GET', `/location/ue/${encodeURIComponent(supi)}`)

// ---- Deployment mode + gNBs (RAN) ----------------------------------------

export type DeploymentMode = 'standalone' | 'ueransim' | 'packetrusher' | 'both'
export type RanTool = 'ueransim' | 'packetrusher'

export interface RanToolState {
  deployed: boolean
  running: boolean
  containers: { name: string; state: string; running: boolean }[]
}

export interface Deployment {
  mode: DeploymentMode
  ueransim: RanToolState
  packetrusher: RanToolState
  source: 'docker' | 'override' | 'unavailable'
  detected_at: string
}

export type GnbState = 'NG_READY' | 'SCTP_UP' | 'DISCONNECTED'

export interface RanGnb {
  id: string
  amf_name: string
  ran_node: {
    type: string
    plmn: { mcc: string; mnc: string }
    gnb_id: number
    gnb_id_hex: string
    gnb_id_bit_length: number
  }
  ran_node_name: string
  sctp: { remote_addrs: string[]; remote_port: number }
  state: GnbState
  connected_at: string
  ng_setup_at?: string
  disconnected_at?: string
  disconnect_reason?: string
  supported_tas: {
    tac: number
    broadcast_plmns: { mcc: string; mnc: string; slices: { sst: number; sd: string }[] }[]
  }[]
  ues: { connected: number; idle: number }
  last_ng_reset_at?: string
  ng_reset_count: number
  amf?: { url: string; name: string }
}

export interface RanSource {
  amf_url: string
  amf_name?: string
  n2_addr?: string
  ok: boolean
  error?: string
}

export interface RanGnbsResponse {
  gnbs: RanGnb[]
  sources: RanSource[]
  generated_at: string
}

export const getDeployment = () => request<Deployment>('GET', '/deployment')
export const getRanGnbs = () => request<RanGnbsResponse>('GET', '/ran/gnbs')

// ---- Metrics -------------------------------------------------------------

export const getMetricsSummary = () => request<MetricsSummary>('GET', '/metrics/summary')

/**
 * Curated time-series metrics (PORTAL-UI-17). The keys MUST mirror the backend
 * whitelist in `internal/api/metrics.go` (`rangeMetrics`) — the endpoint accepts
 * one of these identifiers, never arbitrary PromQL.
 */
export type MetricsMetric =
  | 'ue_registered'
  | 'ue_registered_by_slice'
  | 'amf_registrations'
  | 'registration_success_rate'
  | 'procedure_rates_by_result'
  | 'sbi_request_rate'
  | 'sbi_latency_p99'
  | 'pdu_sessions_active'
  | 'authentication_rate'
  | 'upf_gtp_throughput'

/** One `[unix_seconds, value]` sample of a range series. */
export type MetricsRangePoint = [number, number]

export interface MetricsRangeSeries {
  /** Prometheus-style name, e.g. `procedure_rates_by_result{result="OK"}`. */
  name: string
  points: MetricsRangePoint[]
}

export interface MetricsRange {
  metric: MetricsMetric
  /** Effective downsample step in seconds (server-computed when omitted). */
  step: number
  series: MetricsRangeSeries[]
}

/**
 * Range query over the curated metrics backend. `from`/`to` are sent as
 * RFC3339; the server computes a downsampled step when none is given.
 * Rejections are HTTP errors: 400 (unknown metric / malformed range / beyond
 * retention), 502 (Prometheus error), 503 (Prometheus not configured).
 */
export const getMetricsRange = (metric: MetricsMetric, from: Date, to: Date, step?: number) => {
  const params = new URLSearchParams({ metric, from: from.toISOString(), to: to.toISOString() })
  if (step !== undefined) params.set('step', String(step))
  return request<MetricsRange>('GET', `/metrics/range?${params.toString()}`)
}

// ---- PCAP ----------------------------------------------------------------

export const getPCAPStatus = () => request<PCAPStatus[]>('GET', '/pcap/status')
export const pcapStart = (nf: string) => request<{ status: string }>('POST', `/pcap/${nf}/start`)
export const pcapStop = (nf: string) => request<{ status: string }>('POST', `/pcap/${nf}/stop`)
export const pcapPause = (nf: string) => request<{ status: string }>('POST', `/pcap/${nf}/pause`)
export const pcapResume = (nf: string) => request<{ status: string }>('POST', `/pcap/${nf}/resume`)
export const pcapRotate = (nf: string) => request<{ status: string }>('POST', `/pcap/${nf}/rotate`)
export const getPCAPFiles = (nf: string) => request<PCAPFile[]>('GET', `/pcap/${nf}/files`)
export const pcapDownloadURL = (nf: string, filename: string) =>
  `${BASE}/pcap/${encodeURIComponent(nf)}/files/${encodeURIComponent(filename)}`
export const pcapDeleteFile = (nf: string, filename: string) =>
  request<{ deleted: string }>('DELETE', `/pcap/${encodeURIComponent(nf)}/files/${encodeURIComponent(filename)}`)
export const pcapBulkDelete = (nf: string, files: string[]) =>
  request<{ deleted: number }>('DELETE', `/pcap/${encodeURIComponent(nf)}/files`, { files })
export const pcapBulkDownload = async (nf: string, files: string[]): Promise<void> => {
  const res = await fetch(`${BASE}/pcap/${encodeURIComponent(nf)}/files/zip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ files }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    const e = err as { error?: string; detail?: string }
    throw new Error(e.error || e.detail || res.statusText)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${nf}-pcaps.zip`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ---- UERANSIM ------------------------------------------------------------

export interface UEContainer {
  name: string
  state: string
  status: string
  uptime: string
  role: 'gnb' | 'ue'
}

export interface UEEntry {
  supi: string
  tmsi: number
  gmm_state: number
  created_at: string
  sessions: PDUSession[]
  container: string
}

export interface UERANSIMStatus {
  containers: UEContainer[]
  ues: UEEntry[]
}

export interface NRCLIResult {
  exit_code: number
  output: string
}

export const getUERANSIMStatus = () => request<UERANSIMStatus>('GET', '/ueransim/status')
export const nrCLI = (container: string, supi: string, command: string) =>
  request<NRCLIResult>('POST', '/ueransim/nr-cli', { container, supi, command })
export const pingUE = (container: string, ue_ip: string, target: string, count: number) =>
  request<NRCLIResult>('POST', '/ueransim/ping', { container, ue_ip, target, count })

export interface IperfParams {
  container: string
  ue_ip: string
  network: string // N6 Docker network: 5gc-n6 | 5gc-n6-ims
  protocol: 'tcp' | 'udp'
  direction: 'ul' | 'dl'
  duration: number
  streams: number
  bandwidth?: string // target bitrate (-b), e.g. "10M"; empty on TCP = unlimited
  server_ip?: string // external iperf3 server (IPv4); empty = auto throw-away container
  server_port?: number // default 5201
}

export interface IperfSummary {
  mbps: number // delivered rate
  offered_mbps?: number // UDP uplink: rate the client sent
  retransmits?: number
  jitter_ms?: number
  loss_percent?: number
  packets?: number
  seconds: number
}

export interface IperfResult {
  ok: boolean
  error?: string
  container: string
  ue_ip: string
  network: string
  server_ip: string
  server_port?: number
  server_mode?: 'auto' | 'external'
  protocol: string
  direction: string
  duration: number
  streams: number
  bandwidth?: string
  summary?: IperfSummary
  upf_n6_ip?: string
  server_peer?: string
  path_checked: boolean
  path_ok: boolean
  client_mode?: string
  raw_output?: string
}

export const iperfUE = (p: IperfParams) => request<IperfResult>('POST', '/ueransim/iperf', p)

export interface ScenarioContainerState {
  name: string
  state: string
}

export interface UERANSIMScenarioState {
  name: string
  label: string
  hint: string
  containers: ScenarioContainerState[]
  state: 'running' | 'partial' | 'stopped' | 'not_found'
}

export interface UERANSIMScenariosResponse {
  scenarios: UERANSIMScenarioState[]
}

export const getUERANSIMScenarios = () =>
  request<UERANSIMScenariosResponse>('GET', '/ueransim/scenarios')
export const startUERANSIMScenario = (scenario: string) =>
  request<{ status: string; scenario: string }>('POST', `/ueransim/scenarios/${scenario}/start`)
export const stopUERANSIMScenario = (scenario: string) =>
  request<{ status: string; scenario: string }>('POST', `/ueransim/scenarios/${scenario}/stop`)

// ---- PacketRusher ------------------------------------------------------------

export interface PacketRusherScenarioState {
  scenario: 'xn' | 'n2'
  container: string
  state: 'running' | 'paused' | 'exited' | 'not_found' | 'unknown'
  status: string
  uptime?: string
}

export interface PacketRusherStatus {
  scenarios: PacketRusherScenarioState[]
}

export const getPacketRusherStatus = () => request<PacketRusherStatus>('GET', '/packetrusher/status')
export const prStart  = (scenario: string) => request<{ status: string; container: string }>('POST', `/packetrusher/${scenario}/start`)
export const prStop   = (scenario: string) => request<{ status: string; container: string }>('POST', `/packetrusher/${scenario}/stop`)
export const prPause  = (scenario: string) => request<{ status: string; container: string }>('POST', `/packetrusher/${scenario}/pause`)
export const prResume = (scenario: string) => request<{ status: string; container: string }>('POST', `/packetrusher/${scenario}/resume`)

// ---- Policies (URSP — TS 24.526 / TS 29.525) ---------------------------

export interface PortRange { low: number; high: number }

export interface TrafficDescriptor {
  match_all?: boolean
  dnns?: string[]
  fqdns?: string[]
  ipv4_addrs?: string[]
  protocol_ids?: number[]
  port_ranges?: PortRange[]
}

export interface RouteSelectionDescriptor {
  precedence: number
  ssc_mode?: number
  snssai?: { sst: number; sd: string }
  dnn?: string
  pdu_session_type?: number
}

export interface URSPRule {
  precedence: number
  traffic_descriptor: TrafficDescriptor
  route_sel_descriptors: RouteSelectionDescriptor[]
}

export interface Policy {
  id: string
  supi: string          // empty = operator default
  precedence: number
  rules: URSPRule[]
  updated_at: string
}

export const getPolicies = () => request<Policy[]>('GET', '/policies')
export const getPolicy = (id: string) => request<Policy>('GET', `/policies/${id}`)
export const createPolicy = (p: Omit<Policy, 'id' | 'updated_at'>) =>
  request<void>('POST', '/policies', p)
export const updatePolicy = (id: string, p: Partial<Policy>) =>
  request<void>('PUT', `/policies/${id}`, p)
export const deletePolicy = (id: string) => request<void>('DELETE', `/policies/${id}`)
export const pushPolicies = (supi: string) =>
  request<void>('POST', `/policies/push/${supi}`)

// ---- Policy Templates (portal-managed slice defaults) --------------------

export interface PolicyTemplate {
  id: string
  name: string
  description: string
  slice_name: string   // internet | gold | silver | bronze
  precedence: number
  rules: URSPRule[]
  updated_at: string
}

export interface ApplyTemplateResult {
  status: 'pushed' | 'stored'
  warning?: string
}

export const getPolicyTemplates = () => request<PolicyTemplate[]>('GET', '/policy-templates')
export const createPolicyTemplate = (t: Omit<PolicyTemplate, 'id' | 'updated_at'>) =>
  request<void>('POST', '/policy-templates', t)
export const updatePolicyTemplate = (id: string, t: Partial<PolicyTemplate>) =>
  request<void>('PUT', `/policy-templates/${id}`, t)
export const deletePolicyTemplate = (id: string) =>
  request<void>('DELETE', `/policy-templates/${id}`)
export const applyPolicyTemplate = (id: string, supi: string) =>
  request<ApplyTemplateResult>('POST', `/policy-templates/${id}/apply`, { supi })

// ---- DNNs ----------------------------------------------------------------

export interface DNNInfo {
  name: string
  ue_ip_pool: string
  n6_network?: string
  description?: string
  tun_name?: string
  tun_addr?: string
  gateway_ip?: string
  docker_network?: string
  ue_ipv6_prefix?: string
}

export interface DNNListResponse {
  dnns: DNNInfo[]
  next_ue_pool: string
  next_n6_network: string
  next_tun_index: number
}

export interface AddDNNResult {
  dnn: DNNInfo
  docker_net: string
  restarted: string[]
  docker_errors: string[]
}

export interface DeleteDNNResult {
  name: string
  restarted: string[]
  docker_errors: string[]
}

export interface UpdateDNNResult {
  name: string
  restarted: string[]
  docker_errors: string[]
}

export const getDNNs = () => request<DNNListResponse>('GET', '/dnns')
export const addDNN = (dnn: Omit<DNNInfo, 'tun_name' | 'tun_addr' | 'gateway_ip' | 'docker_network'>, restart = false) =>
  request<AddDNNResult>('POST', '/dnns', { ...dnn, restart })
export const updateDNN = (name: string, body: { description: string; ue_ipv6_prefix: string; restart: boolean }) =>
  request<UpdateDNNResult>('PUT', `/dnns/${encodeURIComponent(name)}`, body)
export const deleteDNN = (name: string, restart = false) =>
  request<DeleteDNNResult>('DELETE', `/dnns/${encodeURIComponent(name)}?restart=${restart}`)

// ---- QoS / PDU sessions (SMF management API + UDM SDM) --------------------

export interface QoSSession {
  smContextRef: string
  supi: string
  pduSessionId: number
  dnn: string
  sNssai: { sst: number; sd?: string }
  current5qi: number
  arpPriorityLevel?: number
  qosSource: string
  sessionAmbrUlMbps: number
  sessionAmbrDlMbps: number
  ueIp: string
  upfTeid: number
  seid: number
  sessionState: string
  createdAt?: string
}

export interface QoSSessionDetail {
  session: QoSSession
  qosFlows: { qfi: number; fiveQi: number; gbr: boolean }[]
  pfcpQer: {
    qerId: number
    qfi: number
    gateUl: string
    gateDl: string
    mbrUlKbps: number
    mbrDlKbps: number
    seid: number
  }
}

export interface QoSModifyResult {
  result: string
  supi: string
  pduSessionId: number
  previous5qi: number
  new5qi: number
  ambrDlMbps: number
  ambrUlMbps: number
  reason: string
  modifiedAt: string
}

// SessionManagementSubscriptionData entry (TS 29.503 §6.1.6.2.7)
export interface SMSubscriptionEntry {
  singleNssai: { sst: number; sd?: string }
  dnnConfigurations: Record<
    string,
    {
      pduSessionTypes: { defaultSessionType: string }
      '5gQosProfile': {
        '5qi': number
        arp: { priorityLevel: number; preemptCap: string; preemptVuln: string }
        priorityLevel?: number
      }
      sessionAmbr: { uplink: string; downlink: string }
    }
  >
}

export const getQoSSessions = () =>
  request<{ sessions: QoSSession[]; count: number }>('GET', '/qos/sessions')
export const getQoSSession = (psi: number, supi?: string) =>
  request<QoSSessionDetail>(
    'GET',
    `/qos/sessions/${psi}${supi ? `?supi=${encodeURIComponent(supi)}` : ''}`,
  )
export const modifySessionQoS = (
  psi: number,
  body: { '5qi': number; reason: string; supi?: string; ambr_dl_mbps?: number; ambr_ul_mbps?: number },
) => request<QoSModifyResult>('POST', `/qos/sessions/${psi}/modify`, body)
export const getSubscriptionQoS = (supi: string) =>
  request<SMSubscriptionEntry[]>('GET', `/qos/subscription/${encodeURIComponent(supi)}`)

// ---- NW-triggered additional PDU session (URSP-based — TS 23.503 §6.6.2) ---

export type PDUSessionType = 'IPv4' | 'IPv6' | 'IPv4v6'

export interface NWSessionRequest {
  supi: string
  app: string
  app_fqdns?: string[]
  dnn: string
  sst: number
  sd?: string
  '5qi': number
  ambr_uplink?: string
  ambr_downlink?: string
  pdu_session_type?: PDUSessionType
}

export interface NWSessionStep {
  step: string
  success: boolean
  duration_ms: number
  detail?: string
}

export interface NWSessionResult {
  success: boolean
  steps: NWSessionStep[]
  pdu_session_id?: number
  ue_ip?: string
  '5qi'?: number
  qos_source?: string
  error?: string
}

export const triggerNWSession = (body: NWSessionRequest) =>
  request<NWSessionResult>('POST', '/qos/nw-sessions', body)

// ---- Public Warning System (ETWS/CMAS — TS 38.413 §8.9, TS 23.041) --------

export interface PWSBroadcastRequest {
  messageIdentifier?: number
  serialNumber?: number
  repetitionPeriod?: number
  numberOfBroadcastsRequested?: number
  warningType?: string // 2-octet hex, e.g. "0000"
  dataCodingScheme?: number
  language?: string // ISO 639 code for the UCS2 language-indication prefix (DCS 0x11); ignored for GSM7 coding-group DCS
  messageText?: string
  warningAreaTacs?: number[]
}

export interface PWSBroadcastAck {
  messageIdentifier: number
  serialNumber: number
  gnbs_targeted: number
}

export interface PWSArea {
  mcc: string
  mnc: string
  tac: number
}

export interface PWSGNBStatus {
  gnb_addr?: string
  gnb_name?: string
  completed?: boolean
  cancelled?: boolean
  failed?: boolean
  areas?: PWSArea[]
}

export interface PWSBroadcastStatus {
  message_identifier: number
  serial_number: number
  data_coding_scheme?: number
  language?: string
  warning_type?: string
  message_text?: string
  gnbs_targeted: number
  gnbs_completed: number
  gnbs_cancelled: number
  cancelled: boolean
  live?: boolean // AMF currently has runtime state for this warning (false after an AMF restart)
  stored?: boolean // persisted in the CBC store of record
  created_at?: string
  per_gnb?: PWSGNBStatus[]
}

export const pwsBroadcast = (body: PWSBroadcastRequest) =>
  request<PWSBroadcastAck>('POST', '/pws/broadcast', body)
export const pwsCancel = (messageIdentifier: number, serialNumber: number) =>
  request<PWSBroadcastAck>('POST', '/pws/cancel', { messageIdentifier, serialNumber })
export const pwsResend = (messageIdentifier: number, serialNumber: number) =>
  request<PWSBroadcastAck>('POST', '/pws/resend', { messageIdentifier, serialNumber })
export const getPWSBroadcasts = () => request<PWSBroadcastStatus[]>('GET', '/pws/broadcast')
