import type { Address, Hex } from 'viem'
import {
  verify,
  verifyModel,
  isDstackAvailable,
  storeProof as storeProofOnchain,
  lookupProof as lookupProofOnchain,
} from '../src/index.js'
import type { NetworkKey } from '../src/types.js'
import type { VerifyModelResult } from '../src/verify.js'

const HELP = `
redpill-verifier — Verify Confidential AI responses from RedPill / Phala

Commands:
  verify <chatId>     Verify an existing chat response (the main command)
  attestation         Verify TEE attestation for a model (no API key needed)
  store               Store proof on-chain (requires --private-key)
  lookup              Look up a stored proof by quote hash

Options:
  --model MODEL          Model to verify (default: phala/gpt-oss-120b)
  --api-key KEY          RedPill API key
  --deep                 Force deep verification (dstack-verifier Docker)
  --light                Force light verification (cloud APIs only, no Docker)
  --network NETWORK      automata-mainnet|automata-testnet|sepolia|holesky
  --skip-onchain         Skip on-chain DCAP verification
  --private-key KEY      Ethereum private key (for store)
  --proof-store ADDR     RedpillProofStore contract address
  --quote-hash HASH      Quote hash to look up
  --help                 Show this help

Examples:
  # Verify your chat response (main use case)
  npx redpill-verifier verify chatcmpl-xxx --api-key sk-xxx --model phala/gpt-oss-120b

  # Check model attestation (no API key)
  npx redpill-verifier attestation --model phala/gpt-oss-120b

  # Deep mode (requires Docker running dstack-verifier)
  npx redpill-verifier attestation --model phala/gpt-oss-20b --deep

  # Store proof on Sepolia
  npx redpill-verifier store --private-key 0x... --proof-store 0x... --network sepolia
`

function parseArgs(argv: string[]) {
  const args: Record<string, string | boolean> = {}
  const positional: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      const next = argv[i + 1]
      if (next && !next.startsWith('--')) { args[key] = next; i++ }
      else { args[key] = true }
    } else {
      positional.push(arg)
    }
  }
  return { args, positional }
}

function ok(msg: string) { console.log(`  \x1b[92mOK\x1b[0m    ${msg}`) }
function fail(msg: string) { console.log(`  \x1b[91mFAIL\x1b[0m  ${msg}`) }
function info(msg: string) { console.log(`  \x1b[2m...\x1b[0m   ${msg}`) }
function warn(msg: string) { console.log(`  \x1b[93mWARN\x1b[0m  ${msg}`) }
function step(n: number, title: string) {
  console.log(`\n\x1b[1m\x1b[94m[Step ${n}]\x1b[0m \x1b[1m${title}\x1b[0m`)
}

function printModelResult(r: VerifyModelResult, startStep = 1) {
  let s = startStep

  // Light mode
  step(s++, 'Intel TDX Quote')
  r.light.tdx?.verified ? ok('TDX quote verified') : fail(`TDX failed: ${r.light.tdx?.message ?? 'no quote'}`)

  if (r.light.reportData) {
    step(s++, 'Report Data Binding')
    r.light.reportData.bindsAddress ? ok('Signing key bound to TEE hardware') : fail('Key binding failed')
    r.light.reportData.embedsNonce ? ok('Nonce embedded in report data') : fail('Nonce mismatch')
  }

  if (r.light.gpu) {
    step(s++, 'GPU Attestation')
    r.light.gpu.nonceMatches ? ok('GPU nonce matches') : fail('GPU nonce mismatch')
    ok(`NVIDIA verdict: ${r.light.gpu.verdict}`)
  }

  if (r.light.compose) {
    step(s++, 'Compose Manifest')
    r.light.compose.hashMatches ? ok('Compose hash matches mr_config') : fail('Compose hash mismatch')
  }

  if (r.light.sigstore.length > 0) {
    step(s++, 'Sigstore Provenance')
    for (const link of r.light.sigstore) {
      const digest = link.url.split('sha256:')[1]?.slice(0, 16) ?? ''
      link.accessible ? ok(`${digest}... (HTTP ${link.status})`) : warn(`${digest}... (HTTP ${link.status})`)
    }
  }

  // Deep mode
  if (r.deep) {
    step(s++, `Deep Verification (dstack)`)
    if (!r.deep.available) {
      info('dstack-verifier not available — skipped (run: docker compose up -d)')
    } else if (r.deep.components.length === 0) {
      warn('No components verified')
    } else {
      for (const c of r.deep.components) {
        const label = `${c.name}: quote=${c.result.quoteVerified} eventLog=${c.result.eventLogVerified} osImage=${c.result.osImageHashVerified}`
        c.result.isValid ? ok(label) : fail(`${label} — ${c.result.reason}`)
      }
      r.deep.allValid ? ok('All components valid') : fail('Some components failed')
    }
  }

  // On-chain
  if (r.onchain) {
    step(s++, 'On-Chain DCAP')
    r.onchain.verified ? ok(`VALID on ${r.onchain.network}`) : fail('INVALID')
    info(`Contract: ${r.onchain.contract}`)
  }

  // Errors
  if (r.errors.length > 0) {
    console.log(`\n  \x1b[93mWarnings:\x1b[0m`)
    for (const e of r.errors) warn(e)
  }

  return s
}

async function cmdVerify(args: Record<string, string | boolean>, positional: string[]) {
  const chatId = positional[1]
  const apiKey = args['api-key'] as string
  if (!chatId) { console.error('Error: chatId required. Usage: verify <chatId> --api-key sk-xxx'); process.exit(1) }
  if (!apiKey) { console.error('Error: --api-key required'); process.exit(1) }

  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const deep = args.deep === true ? true : args.light === true ? false : undefined

  console.log(`\n\x1b[1m\x1b[96mRedPill Verifier — Verify Chat Response\x1b[0m`)
  console.log(`  Chat ID: ${chatId}`)
  console.log(`  Model:   ${model}`)

  const result = await verify(chatId, {
    model,
    apiKey,
    deep,
    network: args.network as NetworkKey,
    skipOnchain: !!args['skip-onchain'],
  })

  step(1, 'ECDSA Signature')
  result.signature.valid
    ? ok(`Signature valid — signer: ${result.signingAddress}`)
    : fail(`Signer mismatch: recovered ${result.signature.recoveredAddress}`)

  printModelResult(result, 2)

  console.log(`\n  \x1b[1m${result.verified ? '\x1b[92mVERIFIED' : '\x1b[91mNOT VERIFIED'}\x1b[0m`)
  console.log(`  Provider: ${result.provider} | Hardware: ${result.hardware.join(', ') || 'unknown'}\n`)
}

async function cmdAttestation(args: Record<string, string | boolean>) {
  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const deep = args.deep === true ? true : args.light === true ? false : undefined

  console.log(`\n\x1b[1m\x1b[96mRedPill Verifier — TEE Attestation\x1b[0m`)
  console.log(`  Model: ${model}`)

  const result = await verifyModel({
    model,
    deep,
    network: args.network as NetworkKey,
    skipOnchain: !!args['skip-onchain'],
  })

  printModelResult(result)

  console.log(`\n  \x1b[1m${result.verified ? '\x1b[92mVERIFIED' : '\x1b[91mNOT VERIFIED'}\x1b[0m`)
  console.log(`  Provider: ${result.provider} | Hardware: ${result.hardware.join(', ') || 'unknown'}`)
  console.log(`  Signer: ${result.signingAddress}\n`)
}

async function cmdStore(args: Record<string, string | boolean>) {
  const privateKey = args['private-key'] as string
  const proofStoreAddr = args['proof-store'] as string
  if (!privateKey) { console.error('Error: --private-key required'); process.exit(1) }
  if (!proofStoreAddr) { console.error('Error: --proof-store required'); process.exit(1) }

  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'sepolia'

  console.log(`\n\x1b[1m\x1b[96mStore Proof On-Chain\x1b[0m`)

  // First verify to get the attestation
  const result = await verifyModel({ model, skipOnchain: true, deep: false })
  if (!result.signingAddress || !result.light.tdx?.quote) {
    console.error('Error: could not get attestation'); process.exit(1)
  }

  // Get the intel_quote from the attestation (re-fetch since we need the raw hex)
  const { randomNonce, selectAttestation } = await import('../src/utils.js')
  const nonce = randomNonce(32)
  const { API_BASE } = await import('../src/constants.js')
  const report = await (await fetch(`${API_BASE}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}`)).json()
  const att = selectAttestation(report)

  const tx = await storeProofOnchain(
    att.intel_quote,
    result.signingAddress as Address,
    proofStoreAddr as Address,
    privateKey as Hex,
    network,
  )

  tx.isValid ? ok('Proof stored') : fail('Transaction reverted')
  info(`Tx: ${tx.explorer}`)
  info(`Quote hash: ${tx.quoteHash}`)
  info(`Gas: ${tx.gasUsed}`)
  console.log()
}

async function cmdLookup(args: Record<string, string | boolean>) {
  const quoteHash = args['quote-hash'] as string
  const proofStoreAddr = args['proof-store'] as string
  if (!quoteHash) { console.error('Error: --quote-hash required'); process.exit(1) }
  if (!proofStoreAddr) { console.error('Error: --proof-store required'); process.exit(1) }

  const network = (args.network as NetworkKey) ?? 'sepolia'
  const proof = await lookupProofOnchain(quoteHash as Hex, proofStoreAddr as Address, network)

  if (!proof) { console.log(`No proof found for ${quoteHash}`); return }

  console.log(`\nProof found:`)
  console.log(`  Quote hash:      ${proof.quoteHash}`)
  console.log(`  Signing address: ${proof.signingAddress}`)
  console.log(`  Valid:           ${proof.isValid}`)
  console.log(`  Timestamp:       ${proof.timestamp}`)
  console.log(`  Block:           ${proof.blockNumber}`)
  console.log(`  Submitter:       ${proof.submitter}\n`)
}

async function main() {
  const { args, positional } = parseArgs(process.argv.slice(2))
  if (args.help || positional.length === 0) { console.log(HELP); process.exit(0) }

  try {
    switch (positional[0]) {
      case 'verify': await cmdVerify(args, positional); break
      case 'attestation': await cmdAttestation(args); break
      case 'store': await cmdStore(args); break
      case 'lookup': await cmdLookup(args); break
      default: console.error(`Unknown: ${positional[0]}`); console.log(HELP); process.exit(1)
    }
  } catch (err) {
    console.error(`\n\x1b[91mError:\x1b[0m ${err instanceof Error ? err.message : err}`)
    process.exit(1)
  }
}

main()
