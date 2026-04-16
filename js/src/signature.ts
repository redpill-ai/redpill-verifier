import { recoverMessageAddress, type Hex } from 'viem'
import { API_BASE, DEFAULT_MODEL } from './constants.js'
import type {
  AttestationResult,
  NetworkKey,
  SignaturePayload,
  SignatureResult,
  VerifySignatureOptions,
} from './types.js'
import { sha256 } from './utils.js'
import { verifyAttestation } from './attestation.js'

/**
 * Send a chat completion to the RedPill API.
 * Returns the chat ID, serialized request body, and raw response text.
 */
export async function chat(
  model: string,
  message: string,
  apiKey: string,
): Promise<{ chatId: string; requestBody: string; responseText: string }> {
  const body = {
    model,
    messages: [{ role: 'user', content: message }],
    stream: false,
    max_tokens: 32,
  }
  const requestBody = JSON.stringify(body)

  let res: Response | undefined
  for (let attempt = 0; attempt < 3; attempt++) {
    res = await fetch(`${API_BASE}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: requestBody,
      signal: AbortSignal.timeout(60_000),
    })
    if (res.status === 429) {
      await new Promise((r) => setTimeout(r, 2 ** attempt * 5_000))
      continue
    }
    break
  }
  if (!res || !res.ok) {
    throw new Error(`Chat completion failed: ${res?.status} ${res?.statusText}`)
  }

  const responseText = await res.text()
  const chatId = JSON.parse(responseText).id as string
  return { chatId, requestBody, responseText }
}

/**
 * Fetch the ECDSA signature for a chat completion.
 */
export async function fetchSignature(
  chatId: string,
  model: string,
  apiKey: string,
): Promise<SignaturePayload> {
  const url = `${API_BASE}/v1/signature/${chatId}?model=${encodeURIComponent(model)}`
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${apiKey}` },
    signal: AbortSignal.timeout(30_000),
  })
  return res.json()
}

/**
 * Recover the Ethereum address from an ECDSA signature (EIP-191).
 */
export async function recoverSigner(text: string, signature: Hex): Promise<string> {
  return recoverMessageAddress({ message: text, signature })
}

/**
 * Run the full signature verification pipeline:
 * chat → fetch signature → verify hashes → recover signer → attestation.
 */
export async function verifySignature(options: VerifySignatureOptions): Promise<SignatureResult> {
  const model = options.model ?? DEFAULT_MODEL
  const message = options.message ?? 'Say hello in one sentence.'

  // Step 1: Chat
  const { chatId, requestBody, responseText } = await chat(model, message, options.apiKey)

  // Step 2: Fetch signature
  const sig = await fetchSignature(chatId, model, options.apiKey)
  if (sig.error) throw new Error(`Signature error: ${sig.error}`)

  // Step 3: Parse signature text (may be "req:resp" or "model:req:resp")
  const parts = sig.text.split(':')
  let reqHashServer: string
  let respHashServer: string
  if (parts.length === 3) {
    reqHashServer = parts[1]
    respHashServer = parts[2]
  } else if (parts.length === 2) {
    reqHashServer = parts[0]
    respHashServer = parts[1]
  } else {
    throw new Error(`Unexpected signature text format: ${sig.text.slice(0, 60)}`)
  }

  // Step 4: Verify hashes
  const reqHashLocal = await sha256(requestBody)
  const respHashLocal = await sha256(responseText)
  const requestHashMatch = reqHashLocal === reqHashServer
  const responseHashMatch = respHashLocal === respHashServer

  // Step 5: Recover signer
  const recovered = await recoverSigner(sig.text, sig.signature as Hex)
  const signatureValid = recovered.toLowerCase() === sig.signing_address.toLowerCase()

  // Step 6: Attestation (optional)
  let attestation: AttestationResult | null = null
  if (!options.skipAttestation) {
    attestation = await verifyAttestation({
      model,
      network: options.network,
      skipOnchain: options.skipOnchain,
    })
  }

  return {
    chatId,
    requestHashMatch,
    responseHashMatch,
    signatureValid,
    recoveredAddress: recovered,
    signingAddress: sig.signing_address,
    attestation,
  }
}
