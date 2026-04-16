import { createPublicClient, http, keccak256, toHex, type Hex } from 'viem'
import {
  API_BASE,
  AUTOMATA_NETWORKS,
  DCAP_VERIFY_ABI,
  DEFAULT_MODEL,
  NVIDIA_NRAS_URL,
  PHALA_TDX_VERIFIER_URL,
  SIGSTORE_SEARCH_BASE,
} from './constants.js'
import type {
  AttestationReport,
  AttestationResult,
  ComposeResult,
  GpuResult,
  NetworkKey,
  OnchainVerifyResult,
  RawAttestation,
  ReportDataResult,
  SigstoreLink,
  TcbInfo,
  TdxResult,
  TdxVerifyResponse,
  VerifyAttestationOptions,
} from './types.js'
import { decodeJwtPayload, randomNonce, selectAttestation, sha256 } from './utils.js'

/**
 * Fetch attestation report from the RedPill API (public, no auth needed).
 */
export async function fetchReport(model: string, nonce: string): Promise<AttestationReport> {
  const url = `${API_BASE}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}`
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) })
  return res.json()
}

/**
 * Verify Intel TDX quote via Phala's verification service.
 */
export async function checkTdxQuote(attestation: RawAttestation): Promise<TdxResult> {
  const res = await fetch(PHALA_TDX_VERIFIER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hex: attestation.intel_quote }),
    signal: AbortSignal.timeout(30_000),
  })
  const data: TdxVerifyResponse = await res.json()
  const quote = data.quote
  return {
    verified: quote?.verified ?? false,
    message: quote?.message ?? data.message,
    quote,
  }
}

/**
 * Verify TDX report data binds the signing address and request nonce.
 */
export function checkReportData(
  attestation: RawAttestation,
  nonce: string,
  reportDataHex: string,
): ReportDataResult {
  const hex = reportDataHex.replace(/^0x/, '')
  const reportData = Uint8Array.from(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)))

  const signingAlgo = (attestation.signing_algo ?? 'ecdsa').toLowerCase()
  const addrHex = attestation.signing_address.replace(/^0x/, '')
  const addrBytes = Uint8Array.from(addrHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)))

  // First 32 bytes: signing address (left-padded with zeros)
  const embedded = reportData.slice(0, 32)
  const padded = new Uint8Array(32)
  padded.set(addrBytes)
  const bindsAddress = embedded.every((b, i) => b === padded[i])

  // Last 32 bytes: nonce
  const embeddedNonce = Array.from(reportData.slice(32))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const embedsNonce = embeddedNonce === nonce

  return { bindsAddress, embedsNonce, signingAlgo }
}

/**
 * Verify GPU attestation evidence via NVIDIA NRAS.
 */
export async function checkGpu(attestation: RawAttestation, nonce: string): Promise<GpuResult> {
  const payloadRaw = attestation.nvidia_payload
  if (!payloadRaw) throw new Error('No nvidia_payload in attestation')

  const payload = typeof payloadRaw === 'string' ? JSON.parse(payloadRaw) : payloadRaw
  const nonceMatches = (payload.nonce as string).toLowerCase() === nonce.toLowerCase()

  const res = await fetch(NVIDIA_NRAS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30_000),
  })
  const body = await res.json()
  const jwt = body[0][1] as string
  const claims = decodeJwtPayload(jwt)
  const verdict = String(claims['x-nvidia-overall-att-result'] ?? 'unknown')

  return { nonceMatches, verdict }
}

/**
 * Verify Docker compose manifest matches mr_config from the TDX quote.
 */
export async function checkCompose(
  attestation: RawAttestation,
  mrConfig: string,
): Promise<ComposeResult | null> {
  let tcbInfo: TcbInfo
  const raw = attestation.info?.tcb_info
  if (!raw) return null
  tcbInfo = typeof raw === 'string' ? JSON.parse(raw) : raw

  const appCompose = tcbInfo.app_compose
  if (!appCompose) return null

  const composeHash = await sha256(appCompose)
  const expected = `0x01${composeHash}`.toLowerCase()
  const hashMatches = mrConfig.toLowerCase().startsWith(expected)

  let manifest: string | undefined
  try {
    manifest = JSON.parse(appCompose).docker_compose_file
  } catch {
    // app_compose may not contain docker_compose_file
  }

  return { hashMatches, composeHash, mrConfig, manifest }
}

/**
 * Check Sigstore provenance for container images in the compose manifest.
 */
export async function checkSigstore(attestation: RawAttestation): Promise<SigstoreLink[]> {
  let tcbInfo: TcbInfo
  const raw = attestation.info?.tcb_info
  if (!raw) return []
  tcbInfo = typeof raw === 'string' ? JSON.parse(raw) : raw

  const compose = tcbInfo.app_compose
  if (!compose) return []

  const digests = [...new Set(compose.match(/@sha256:([0-9a-f]{64})/g) ?? [])]
    .map((m) => m.replace('@sha256:', ''))

  const results: SigstoreLink[] = []
  for (const digest of digests.slice(0, 5)) {
    const url = `${SIGSTORE_SEARCH_BASE}sha256:${digest}`
    try {
      const res = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(10_000) })
      results.push({ url, accessible: res.status < 400, status: res.status })
    } catch {
      results.push({ url, accessible: false, status: 0 })
    }
  }
  return results
}

/**
 * Verify TDX quote on-chain via Automata's DCAP verifier (view call, free).
 */
export async function verifyOnchain(
  attestation: RawAttestation,
  networkKey: NetworkKey = 'automata-mainnet',
): Promise<OnchainVerifyResult> {
  const network = AUTOMATA_NETWORKS[networkKey]

  const client = createPublicClient({
    transport: http(network.rpc, { timeout: 120_000 }),
  })

  const quoteHex = attestation.intel_quote.replace(/^0x/, '')
  const quoteBytes = `0x${quoteHex}` as Hex
  const quoteHash = keccak256(quoteBytes)

  const [isValid] = await client.readContract({
    address: network.contract,
    abi: DCAP_VERIFY_ABI,
    functionName: 'verifyAndAttestOnChain',
    args: [quoteBytes],
  })

  return {
    verified: isValid,
    quoteHash,
    network: network.name,
    contract: network.contract,
    explorer: `${network.explorer}/address/${network.contract}`,
  }
}

/**
 * Run the full attestation verification pipeline.
 */
export async function verifyAttestation(
  options: VerifyAttestationOptions = {},
): Promise<AttestationResult> {
  const model = options.model ?? DEFAULT_MODEL
  const networkKey = options.network ?? 'automata-mainnet'
  const nonce = randomNonce(32)

  // Fetch report
  const report = await fetchReport(model, nonce)
  if (report.error) throw new Error(`Attestation API error: ${JSON.stringify(report.error)}`)

  const attestation = selectAttestation(report)
  if (!attestation.signing_address) {
    throw new Error(`No signing_address in attestation. Keys: ${Object.keys(report).join(', ')}`)
  }

  // TDX quote
  const tdx = await checkTdxQuote(attestation)

  // Report data binding
  let reportData: ReportDataResult | null = null
  const rdHex = tdx.quote?.body?.reportdata
  if (rdHex) {
    reportData = checkReportData(attestation, nonce, rdHex)
  }

  // GPU attestation
  let gpu: GpuResult | null = null
  if (attestation.nvidia_payload) {
    try {
      gpu = await checkGpu(attestation, nonce)
    } catch {
      // GPU verification may fail for non-GPU models
    }
  }

  // Compose manifest
  let compose: ComposeResult | null = null
  const mrConfig = tdx.quote?.body?.mrconfig
  if (mrConfig) {
    compose = await checkCompose(attestation, mrConfig)
  }

  // Sigstore
  const sigstore = await checkSigstore(attestation)

  // On-chain DCAP
  let onchain: OnchainVerifyResult | null = null
  if (!options.skipOnchain) {
    onchain = await verifyOnchain(attestation, networkKey)
  }

  return {
    signingAddress: attestation.signing_address,
    nonce,
    tdx,
    reportData,
    gpu,
    compose,
    sigstore,
    onchain,
  }
}
