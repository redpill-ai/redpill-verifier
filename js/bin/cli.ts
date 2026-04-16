import type { Address, Hex } from 'viem'
import { verifyAttestation, verifyResponse, verifySignature, verifyOnchainFull, storeProof, lookupProof } from '../src/index.js'
import type { NetworkKey } from '../src/types.js'

const HELP = `
redpill-verifier — Cryptographic verification for RedPill Confidential AI

Commands:
  attestation   Verify TEE attestation (no API key needed)
  verify        Verify an existing chat response by chatId (requires --api-key --chat-id)
  signature     Demo: make a chat call + verify signature (requires --api-key)
  onchain       Verify TDX quote on-chain via Automata DCAP
  store         Store proof on-chain (requires --private-key)
  lookup        Look up a stored proof by quote hash

Options:
  --model MODEL          Model to verify (default: phala/gpt-oss-120b)
  --network NETWORK      automata-mainnet|automata-testnet|sepolia|holesky
  --skip-onchain         Skip on-chain DCAP verification
  --api-key KEY          RedPill API key (for verify/signature commands)
  --chat-id ID           Chat completion ID to verify (for verify command)
  --private-key KEY      Ethereum private key (for store command)
  --proof-store ADDR     RedpillProofStore contract address
  --quote-hash HASH      Quote hash to look up
  --help                 Show this help

Examples:
  npx redpill-verifier attestation
  npx redpill-verifier signature --api-key sk-xxx
  npx redpill-verifier onchain --network sepolia
  npx redpill-verifier store --private-key 0x... --proof-store 0x... --network sepolia
  npx redpill-verifier lookup --quote-hash 0x... --proof-store 0x... --network sepolia
`

function parseArgs(argv: string[]) {
  const args: Record<string, string | boolean> = {}
  const positional: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      const next = argv[i + 1]
      if (next && !next.startsWith('--')) {
        args[key] = next
        i++
      } else {
        args[key] = true
      }
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

async function cmdAttestation(args: Record<string, string | boolean>) {
  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'automata-mainnet'
  const skipOnchain = !!args['skip-onchain']

  console.log(`\n\x1b[1m\x1b[96mRedPill TEE Attestation Verification\x1b[0m`)
  console.log(`  Model:   ${model}`)
  if (!skipOnchain) console.log(`  Network: ${network}`)

  const result = await verifyAttestation({ model, network, skipOnchain })

  step(1, 'Intel TDX Quote')
  result.tdx.verified ? ok('TDX quote verified') : fail(`TDX verification failed: ${result.tdx.message}`)

  step(2, 'TDX Report Data')
  if (result.reportData) {
    result.reportData.bindsAddress ? ok('Report data binds signing address') : fail('Report data does NOT bind signing address')
    result.reportData.embedsNonce ? ok('Report data embeds request nonce') : fail('Report data nonce mismatch')
    info(`Signing algorithm: ${result.reportData.signingAlgo}`)
  } else {
    warn('Could not extract report data')
  }

  step(3, 'GPU Attestation')
  if (result.gpu) {
    result.gpu.nonceMatches ? ok('GPU nonce matches') : fail('GPU nonce mismatch')
    ok(`NVIDIA verdict: ${result.gpu.verdict}`)
  } else {
    info('No GPU attestation (model may not use GPU TEE)')
  }

  if (result.compose) {
    step(4, 'Compose Manifest')
    result.compose.hashMatches ? ok('Compose hash matches mr_config') : fail('Compose hash mismatch')
  }

  if (result.sigstore.length > 0) {
    step(5, 'Sigstore Provenance')
    for (const link of result.sigstore) {
      link.accessible ? ok(`${link.url.split('sha256:')[1]?.slice(0, 16)}... (HTTP ${link.status})`) : warn(`${link.url.split('sha256:')[1]?.slice(0, 16)}... (HTTP ${link.status})`)
    }
  }

  if (result.onchain) {
    step(6, 'On-Chain DCAP Verification')
    result.onchain.verified
      ? ok(`On-chain DCAP: \x1b[92m\x1b[1mVALID\x1b[0m`)
      : fail('On-chain DCAP: INVALID')
    info(`Contract: ${result.onchain.contract}`)
    info(`Explorer: ${result.onchain.explorer}`)
  }

  console.log(`\n  Signing address: ${result.signingAddress}`)
  console.log(`  Nonce: ${result.nonce}\n`)
}

async function cmdSignature(args: Record<string, string | boolean>) {
  const apiKey = args['api-key'] as string
  if (!apiKey) { console.error('Error: --api-key is required'); process.exit(1) }

  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'automata-mainnet'

  console.log(`\n\x1b[1m\x1b[96mRedPill Signature Verification\x1b[0m`)
  console.log(`  Model: ${model}`)

  const result = await verifySignature({
    model,
    apiKey,
    network,
    skipOnchain: !!args['skip-onchain'],
  })

  step(1, 'Chat Completion')
  ok(`Chat ID: ${result.chatId}`)

  step(2, 'ECDSA Signature')
  result.requestHashMatch ? ok('Request hash matches') : warn('Request hash differs (gateway may rewrite model name)')
  result.responseHashMatch ? ok('Response hash matches') : fail('Response hash mismatch')
  result.signatureValid
    ? ok(`Recovered signer ${result.recoveredAddress.slice(0, 10)}... matches`)
    : fail(`Signer mismatch: ${result.recoveredAddress}`)

  if (result.attestation) {
    step(3, 'TEE Attestation')
    result.attestation.tdx.verified ? ok('TDX quote verified') : fail('TDX failed')
    if (result.attestation.reportData) {
      result.attestation.reportData.bindsAddress ? ok('Report data binds signing address') : fail('Binding failed')
    }
    if (result.attestation.gpu) {
      ok(`GPU verdict: ${result.attestation.gpu.verdict}`)
    }
    if (result.attestation.onchain) {
      result.attestation.onchain.verified ? ok('On-chain DCAP: VALID') : fail('On-chain DCAP: INVALID')
    }
  }
  console.log()
}

async function cmdVerify(args: Record<string, string | boolean>) {
  const apiKey = args['api-key'] as string
  const chatId = args['chat-id'] as string
  if (!apiKey) { console.error('Error: --api-key is required'); process.exit(1) }
  if (!chatId) { console.error('Error: --chat-id is required'); process.exit(1) }

  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'automata-mainnet'

  console.log(`\n\x1b[1m\x1b[96mVerify Existing Chat Response\x1b[0m`)
  console.log(`  Chat ID: ${chatId}`)
  console.log(`  Model:   ${model}`)

  const result = await verifyResponse({
    chatId,
    model,
    apiKey,
    network,
    skipOnchain: !!args['skip-onchain'],
  })

  step(1, 'ECDSA Signature')
  result.signatureValid
    ? ok(`Signature valid — signer: ${result.signingAddress}`)
    : fail(`Signer mismatch: recovered ${result.recoveredAddress}, expected ${result.signingAddress}`)

  if (result.attestation) {
    step(2, 'TEE Attestation')
    result.attestation.tdx.verified ? ok('TDX quote verified') : fail('TDX failed')
    if (result.attestation.reportData) {
      result.attestation.reportData.bindsAddress ? ok('Signing key bound to TEE hardware') : fail('Key binding failed')
    }
    if (result.attestation.gpu) {
      ok(`GPU attestation: ${result.attestation.gpu.verdict}`)
    }
    if (result.attestation.onchain) {
      result.attestation.onchain.verified ? ok('On-chain DCAP: VALID') : fail('On-chain DCAP: INVALID')
    }
  }
  console.log()
}

async function cmdOnchain(args: Record<string, string | boolean>) {
  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'automata-mainnet'

  console.log(`\n\x1b[1m\x1b[96mOn-Chain DCAP Verification\x1b[0m`)
  info(`Model: ${model}`)
  info(`Network: ${network}`)

  const result = await verifyOnchainFull({ model, network })

  result.verified
    ? ok(`On-chain DCAP: \x1b[92m\x1b[1mVALID\x1b[0m`)
    : fail('On-chain DCAP: INVALID')
  info(`Quote hash: ${result.quoteHash}`)
  info(`Contract: ${result.contract}`)
  info(`Explorer: ${result.explorer}`)
  console.log()
}

async function cmdStore(args: Record<string, string | boolean>) {
  const privateKey = args['private-key'] as string
  const proofStoreAddr = args['proof-store'] as string
  if (!privateKey) { console.error('Error: --private-key is required'); process.exit(1) }
  if (!proofStoreAddr) { console.error('Error: --proof-store is required'); process.exit(1) }

  const model = (args.model as string) ?? 'phala/gpt-oss-120b'
  const network = (args.network as NetworkKey) ?? 'automata-mainnet'

  console.log(`\n\x1b[1m\x1b[96mStore Proof On-Chain\x1b[0m`)

  const result = await storeProof({
    model,
    network,
    proofStore: proofStoreAddr as Address,
    privateKey: privateKey as Hex,
  })

  result.isValid ? ok('Proof stored successfully') : fail('Transaction reverted')
  info(`Tx hash: ${result.txHash}`)
  info(`Quote hash: ${result.quoteHash}`)
  info(`Block: ${result.blockNumber}`)
  info(`Gas used: ${result.gasUsed}`)
  info(`Explorer: ${result.explorer}`)
  console.log()
}

async function cmdLookup(args: Record<string, string | boolean>) {
  const quoteHash = args['quote-hash'] as string
  const proofStoreAddr = args['proof-store'] as string
  if (!quoteHash) { console.error('Error: --quote-hash is required'); process.exit(1) }
  if (!proofStoreAddr) { console.error('Error: --proof-store is required'); process.exit(1) }

  const network = (args.network as NetworkKey) ?? 'automata-mainnet'

  const proof = await lookupProof({
    quoteHash: quoteHash as Hex,
    proofStore: proofStoreAddr as Address,
    network,
  })

  if (!proof) {
    console.log(`No proof found for quote hash ${quoteHash}`)
    return
  }

  console.log(`\nProof found:`)
  console.log(`  Quote hash:       ${proof.quoteHash}`)
  console.log(`  Signing address:  ${proof.signingAddress}`)
  console.log(`  Valid:            ${proof.isValid}`)
  console.log(`  Timestamp:        ${proof.timestamp}`)
  console.log(`  Block number:     ${proof.blockNumber}`)
  console.log(`  Submitter:        ${proof.submitter}`)
  console.log()
}

async function main() {
  const { args, positional } = parseArgs(process.argv.slice(2))

  if (args.help || positional.length === 0) {
    console.log(HELP)
    process.exit(0)
  }

  const command = positional[0]
  try {
    switch (command) {
      case 'attestation': await cmdAttestation(args); break
      case 'verify': await cmdVerify(args); break
      case 'signature': await cmdSignature(args); break
      case 'onchain': await cmdOnchain(args); break
      case 'store': await cmdStore(args); break
      case 'lookup': await cmdLookup(args); break
      default:
        console.error(`Unknown command: ${command}`)
        console.log(HELP)
        process.exit(1)
    }
  } catch (err) {
    console.error(`\n\x1b[91mError:\x1b[0m ${err instanceof Error ? err.message : err}`)
    process.exit(1)
  }
}

main()
