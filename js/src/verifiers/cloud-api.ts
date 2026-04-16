/**
 * Light verification via cloud APIs.
 * Verifies TDX quotes via Phala's verification service and GPU via NVIDIA NRAS.
 * Trust: Phala's API + NVIDIA NRAS. No Docker needed.
 */

import { NVIDIA_NRAS_URL, PHALA_TDX_VERIFIER_URL } from '../constants.js'
import { decodeJwtPayload, sha256 } from '../utils.js'
import type { RawAttestation, TdxResult, GpuResult, ReportDataResult, ComposeResult, SigstoreLink, TcbInfo } from '../types.js'
import { SIGSTORE_SEARCH_BASE } from '../constants.js'

/**
 * Detect if a string is base64 encoded (vs hex) and convert to hex if needed.
 */
function toHexQuote(quote: string): string {
  const clean = quote.replace(/^0x/, '')
  // If it contains non-hex characters, it's base64
  if (/[^0-9a-fA-F]/.test(clean)) {
    const bytes = Uint8Array.from(atob(quote), (c) => c.charCodeAt(0))
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  }
  return clean
}

export async function checkTdxQuote(intelQuote: string): Promise<TdxResult> {
  const hexQuote = toHexQuote(intelQuote)
  const res = await fetch(PHALA_TDX_VERIFIER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hex: hexQuote }),
    signal: AbortSignal.timeout(30_000),
  })
  const data = await res.json() as Record<string, unknown>
  const quote = (data.quote ?? {}) as Record<string, unknown>
  return {
    verified: quote.verified as boolean ?? false,
    message: (quote.message ?? data.message) as string | undefined,
    quote: quote as TdxResult['quote'],
  }
}

export function checkReportData(
  signingAddress: string,
  signingAlgo: string,
  nonce: string,
  reportDataHex: string,
): ReportDataResult {
  const hex = reportDataHex.replace(/^0x/, '')
  const reportData = Uint8Array.from(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)))
  const addrHex = signingAddress.replace(/^0x/, '')
  const addrBytes = Uint8Array.from(addrHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)))

  const embedded = reportData.slice(0, 32)
  const padded = new Uint8Array(32)
  padded.set(addrBytes)
  const bindsAddress = embedded.every((b, i) => b === padded[i])

  const embeddedNonce = Array.from(reportData.slice(32))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const embedsNonce = embeddedNonce === nonce

  return { bindsAddress, embedsNonce, signingAlgo: signingAlgo.toLowerCase() }
}

export async function checkGpu(nvidiaPayload: unknown, nonce: string): Promise<GpuResult> {
  const payload = typeof nvidiaPayload === 'string' ? JSON.parse(nvidiaPayload) : nvidiaPayload
  const nonceMatches = ((payload as Record<string, string>).nonce ?? '').toLowerCase() === nonce.toLowerCase()

  const res = await fetch(NVIDIA_NRAS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30_000),
  })
  const body = await res.json() as [unknown, string][]
  const jwt = body[0][1]
  const claims = decodeJwtPayload(jwt)
  const verdict = String(claims['x-nvidia-overall-att-result'] ?? 'unknown')

  return { nonceMatches, verdict }
}

export async function checkCompose(appCompose: string, mrConfig: string): Promise<ComposeResult> {
  const composeHash = await sha256(appCompose)
  const expected = `0x01${composeHash}`.toLowerCase()
  const hashMatches = mrConfig.toLowerCase().startsWith(expected)

  let manifest: string | undefined
  try { manifest = JSON.parse(appCompose).docker_compose_file } catch {}

  return { hashMatches, composeHash, mrConfig, manifest }
}

export async function checkSigstore(appCompose: string): Promise<SigstoreLink[]> {
  const digests = [...new Set(appCompose.match(/@sha256:([0-9a-f]{64})/g) ?? [])]
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
