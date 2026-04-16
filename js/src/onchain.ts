import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  type Account,
  type Address,
  type Chain,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { AUTOMATA_NETWORKS, DCAP_VERIFY_ABI, DEFAULT_MODEL, PROOF_STORE_ABI } from './constants.js'
import type {
  LookupProofOptions,
  NetworkKey,
  OnchainVerifyResult,
  ProofRecord,
  StoreProofOptions,
  StoreProofResult,
  VerifyOnchainOptions,
} from './types.js'
import { randomNonce, selectAttestation } from './utils.js'
import { fetchReport } from './attestation.js'

function getChain(networkKey: NetworkKey): Chain {
  const net = AUTOMATA_NETWORKS[networkKey]
  return {
    id: net.chainId,
    name: net.name,
    nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [net.rpc] } },
  }
}

/**
 * Fetch a fresh attestation and verify its TDX quote on-chain (free view call).
 */
export async function verifyOnchainFull(
  options: VerifyOnchainOptions = {},
): Promise<OnchainVerifyResult> {
  const model = options.model ?? DEFAULT_MODEL
  const networkKey = options.network ?? 'automata-mainnet'
  const network = AUTOMATA_NETWORKS[networkKey]
  const nonce = randomNonce(32)

  const report = await fetchReport(model, nonce)
  if (report.error) throw new Error(`Attestation API error: ${JSON.stringify(report.error)}`)

  const attestation = selectAttestation(report)

  const client = createPublicClient({
    transport: http(network.rpc, { timeout: 120_000 }),
  })

  const quoteHex = `0x${attestation.intel_quote.replace(/^0x/, '')}` as Hex
  const quoteHash = keccak256(quoteHex)

  const [isValid] = await client.readContract({
    address: network.contract,
    abi: DCAP_VERIFY_ABI,
    functionName: 'verifyAndAttestOnChain',
    args: [quoteHex],
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
 * Verify and store a TDX quote proof on-chain (requires wallet + gas).
 */
export async function storeProof(options: StoreProofOptions): Promise<StoreProofResult> {
  const model = options.model ?? DEFAULT_MODEL
  const networkKey = options.network ?? 'automata-mainnet'
  const network = AUTOMATA_NETWORKS[networkKey]
  const chain = getChain(networkKey)
  const nonce = randomNonce(32)

  // Fetch attestation
  const report = await fetchReport(model, nonce)
  if (report.error) throw new Error(`Attestation API error: ${JSON.stringify(report.error)}`)

  const attestation = selectAttestation(report)
  const quoteHex = `0x${attestation.intel_quote.replace(/^0x/, '')}` as Hex
  const quoteHash = keccak256(quoteHex)
  const signingAddr = attestation.signing_address as Address

  // Create wallet client
  const account = privateKeyToAccount(options.privateKey)
  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(network.rpc, { timeout: 180_000 }),
  })
  const publicClient = createPublicClient({
    chain,
    transport: http(network.rpc, { timeout: 180_000 }),
  })

  // Send transaction
  const txHash = await walletClient.writeContract({
    address: options.proofStore,
    abi: PROOF_STORE_ABI,
    functionName: 'verifyAndStore',
    args: [quoteHex, signingAddr],
  })

  // Wait for receipt
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 300_000 })

  return {
    txHash,
    quoteHash,
    isValid: receipt.status === 'success',
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed,
    explorer: `${network.explorer}/tx/${txHash}`,
  }
}

/**
 * Look up a previously stored proof by quote hash.
 */
export async function lookupProof(options: LookupProofOptions): Promise<ProofRecord | null> {
  const networkKey = options.network ?? 'automata-mainnet'
  const network = AUTOMATA_NETWORKS[networkKey]

  const client = createPublicClient({
    transport: http(network.rpc, { timeout: 30_000 }),
  })

  const proof = await client.readContract({
    address: options.proofStore,
    abi: PROOF_STORE_ABI,
    functionName: 'getProof',
    args: [options.quoteHash],
  })

  // viem returns struct as an object with named fields
  const p = proof as unknown as Record<string, unknown>
  const quoteHash = (p.quoteHash ?? p[0]) as Hex
  const signingAddress = (p.signingAddress ?? p[1]) as Address
  const isValid = (p.isValid ?? p[2]) as boolean
  const timestamp = (p.timestamp ?? p[3]) as bigint
  const blockNumber = (p.blockNumber ?? p[4]) as bigint
  const submitter = (p.submitter ?? p[5]) as Address

  if (quoteHash === '0x0000000000000000000000000000000000000000000000000000000000000000') {
    return null
  }

  return { quoteHash, signingAddress, isValid, timestamp, blockNumber, submitter }
}
