const BASE = '/api/v1'

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error((err as { error: string }).error || res.statusText)
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

// ---- Slices --------------------------------------------------------------

export interface AddSliceResult { slice: SNSSAI; restarted: string[] }
export interface DeleteSliceResult { restarted: string[] }

export const getSlices = () => request<SNSSAI[]>('GET', '/slices')
export const addSlice = (slice: SNSSAI, restart = false) =>
  request<AddSliceResult>('POST', '/slices', { ...slice, restart })
export const deleteSlice = (sst: number, sd: string, restart = false) =>
  request<DeleteSliceResult>('DELETE', `/slices/${sst}/${sd}?restart=${restart}`)

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

// ---- Metrics -------------------------------------------------------------

export const getMetricsSummary = () => request<MetricsSummary>('GET', '/metrics/summary')

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
    throw new Error((err as { error: string }).error || res.statusText)
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

export const getDNNs = () => request<DNNListResponse>('GET', '/dnns')
export const addDNN = (dnn: Omit<DNNInfo, 'tun_name' | 'tun_addr' | 'gateway_ip' | 'docker_network'>, restart = false) =>
  request<AddDNNResult>('POST', '/dnns', { ...dnn, restart })
export const updateDNN = (name: string, description: string) =>
  request<{ name: string }>('PUT', `/dnns/${encodeURIComponent(name)}`, { description })
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
