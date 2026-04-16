# RedPill Verifier

Cryptographic verification for RedPill Confidential AI. Prove that AI responses come from genuine TEE hardware — not trust, math.

Available as a **TypeScript/JavaScript npm package** (browser + Node.js) and **Python scripts**.

[![npm](https://img.shields.io/npm/v/@redpill-ai/verifier)](https://www.npmjs.com/package/@redpill-ai/verifier)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What it verifies

| Check | What it proves |
|---|---|
| **ECDSA Signature** | A specific Ethereum address signed the request+response hashes |
| **Intel TDX Quote** | The CPU enclave is genuine Intel TDX hardware |
| **Report Data Binding** | The signing key is generated inside the TEE and bound to hardware |
| **NVIDIA GPU Attestation** | The GPU is genuine H100/H200 in confidential computing mode |
| **Compose Manifest** | The exact code and model weights running match `mr_config` |
| **Sigstore Provenance** | Container images have verified build provenance |
| **On-Chain DCAP** | TDX quote verified trustlessly by an Ethereum smart contract |
| **On-Chain Proof Store** | Permanent, immutable, queryable record of verification |

## Quick Start (JavaScript / TypeScript)

```bash
cd js && npm install
```

### Verify your chat response

Use RedPill as an OpenAI drop-in, then verify the response came from a real TEE:

```typescript
import OpenAI from 'openai'
import { verifyResponse } from '@redpill-ai/verifier'

// Use RedPill as OpenAI alternative
const openai = new OpenAI({
  baseURL: 'https://api.redpill.ai/v1',
  apiKey: 'sk-your-key',
})

const response = await openai.chat.completions.create({
  model: 'phala/gpt-oss-120b',
  messages: [{ role: 'user', content: 'What is confidential computing?' }],
})

// Verify: signature is valid + signing key is inside a real TEE
const proof = await verifyResponse({
  chatId: response.id,
  model: 'phala/gpt-oss-120b',
  apiKey: 'sk-your-key',
})

console.log(proof.signatureValid)              // true
console.log(proof.attestation?.tdx.verified)   // true
console.log(proof.attestation?.gpu?.verdict)    // "true"
console.log(proof.attestation?.onchain?.verified) // true
```

### Verify attestation (no API key needed)

```typescript
import { verifyAttestation } from '@redpill-ai/verifier'

const result = await verifyAttestation({ model: 'phala/gpt-oss-120b' })
// result.tdx.verified === true
// result.reportData.bindsAddress === true
// result.gpu.verdict === "true"
// result.onchain.verified === true
```

### Verify on-chain only (works in browser)

```typescript
import { verifyOnchainFull } from '@redpill-ai/verifier'

// This is the only check that works directly in browsers (no CORS issues)
const onchain = await verifyOnchainFull({
  model: 'phala/gpt-oss-120b',
  network: 'automata-mainnet',
})
console.log(onchain.verified) // true — verified by smart contract, not an API
```

### Store proof permanently on-chain

```typescript
import { storeProof, lookupProof } from '@redpill-ai/verifier'

// Store (requires wallet + gas)
const tx = await storeProof({
  model: 'phala/gpt-oss-120b',
  network: 'sepolia',
  proofStore: '0x83541AD3f380De2b28E0108d4Da934236342B02b',
  privateKey: '0x...',
})
console.log(tx.txHash, tx.isValid) // permanent on-chain record

// Look up later (free)
const record = await lookupProof({
  quoteHash: tx.quoteHash,
  proofStore: '0x83541AD3f380De2b28E0108d4Da934236342B02b',
  network: 'sepolia',
})
```

### CLI

```bash
# Attestation (no API key)
npx redpill-verifier attestation --model phala/gpt-oss-120b

# Verify existing chat response
npx redpill-verifier verify --chat-id chatcmpl-xxx --api-key sk-xxx --model phala/gpt-oss-120b

# On-chain DCAP verification
npx redpill-verifier onchain --model phala/gpt-oss-120b --network sepolia

# Store proof on-chain
npx redpill-verifier store --private-key 0x... --proof-store 0x... --network sepolia

# Look up stored proof
npx redpill-verifier lookup --quote-hash 0x... --proof-store 0x... --network sepolia
```

## Quick Start (Python)

```bash
pip install -r requirements.txt
```

```bash
# Attestation verification (no API key)
python3 attestation_verifier.py --model phala/gpt-oss-120b

# Signature verification (requires API key)
API_KEY=sk-xxx python3 signature_verifier.py --model phala/gpt-oss-120b

# On-chain DCAP verification
python3 onchain_proof.py --model phala/gpt-oss-120b

# Store proof on-chain
PRIVATE_KEY=0x... python3 onchain_proof.py --store --proof-store 0x... --network sepolia
```

## How the verification chain works

```
User Request
    |
    v
+-----------------------------------------------+
|  TEE Enclave (Intel TDX + NVIDIA H100 GPU)    |
|                                               |
|  1. Receives request                          |
|  2. Runs inference on model                   |
|  3. SHA256(request) : SHA256(response)        |
|  4. Signs with Ethereum private key           |
|     (key NEVER leaves the enclave)            |
+-----------------------------------------------+
    |
    v
User gets: response + chat_id
    |
    v
Verification (what this tool does):
  +-- ECDSA Signature --> ecrecover --> signing_address signed these hashes
  +-- TDX Quote ---------> Intel verification --> genuine TDX enclave
  +-- Report Data -------> signing_address + nonce bound to hardware
  +-- NVIDIA NRAS -------> genuine H100/H200 GPU in confidential mode
  +-- Compose Manifest --> mr_config match --> exact code + model verified
  +-- Sigstore ----------> container build provenance verified
  +-- On-Chain DCAP -----> Automata smart contract --> trustless verification
  +-- Proof Store -------> permanent on-chain record anyone can query
```

## Two-layer TEE architecture

**Layer 1: TEE Gateway** (Intel TDX) — all 250+ models
- Request/response processing inside TDX enclave
- ECDSA signing key generated and bound to hardware
- Verified via `gateway_attestation`

**Layer 2: TEE Inference** (Intel TDX + NVIDIA H100/H200) — Phala models
- Model weights loaded in GPU confidential computing
- Inference runs in GPU secure enclaves
- Verified via `model_attestations` + NVIDIA NRAS

Both layers are independently attestable and verifiable.

## Deployed contracts

| Network | RedpillProofStore | Automata DCAP Verifier |
|---|---|---|
| Sepolia | [`0x83541AD3...`](https://sepolia.etherscan.io/address/0x83541AD3f380De2b28E0108d4Da934236342B02b) | [`0x76A3657F...`](https://sepolia.etherscan.io/address/0x76A3657F2d6c5C66733e9b69ACaDadCd0B68788b) |
| Automata Mainnet | - | [`0xE26E11B2...`](https://explorer.ata.network/address/0xE26E11B257856B0bEBc4C759aaBDdea72B64351F) |
| Automata Testnet | - | `0xefE368b1...` |
| Holesky | - | `0x13330365...` |

## Browser vs backend

| Check | Browser | Backend (Node.js) |
|---|---|---|
| On-chain DCAP (viem RPC) | Yes | Yes |
| ECDSA recovery (viem) | Yes | Yes |
| Signature fetch (api.redpill.ai) | CORS blocked | Yes |
| TDX quote (cloud-api.phala.network) | CORS blocked | Yes |
| GPU (nras.attestation.nvidia.com) | CORS blocked | Yes |

**For browser apps**: verify on your backend, pass the result to the frontend. Or use `verifyOnchainFull()` directly in the browser for trustless client-side proof via Automata's smart contract.

## Trust model

**You trust**: Intel (TDX), NVIDIA (H100/H200 TEE), Phala Network (deployment), open source code

**You do NOT trust**: RedPill operators, cloud providers, system administrators, other users on the same hardware

## API reference

### JavaScript exports (25 functions)

```typescript
// High-level orchestrators
verifyResponse(opts)      // Verify an existing chat response by chatId
verifySignature(opts)     // Demo: make chat call + verify (for testing)
verifyAttestation(opts)   // Full attestation pipeline
verifyOnchainFull(opts)   // Fetch attestation + verify on-chain

// Individual checks (composable)
fetchReport(model, nonce)
checkTdxQuote(attestation)
checkReportData(attestation, nonce, reportDataHex)
checkGpu(attestation, nonce)
checkCompose(attestation, mrConfig)
checkSigstore(attestation)
verifyOnchain(attestation, network)

// Signature
chat(model, message, apiKey)
fetchSignature(chatId, model, apiKey)
recoverSigner(text, signature)

// On-chain proof storage
storeProof(opts)
lookupProof(opts)

// Utilities
sha256(text)
randomNonce(bytes?)
decodeJwtPayload(jwt)
selectAttestation(report, signingAddress?)

// Constants
API_BASE, AUTOMATA_NETWORKS, DCAP_VERIFY_ABI, PROOF_STORE_ABI, DEFAULT_MODEL
```

## Smart contract

[`contracts/RedpillProofStore.sol`](contracts/RedpillProofStore.sol) — wraps Automata's `verifyAndAttestOnChain()` and stores results permanently:

```solidity
function verifyAndStore(bytes calldata quote, address signingAddress) external returns (bool)
function getProof(bytes32 quoteHash) external view returns (Proof memory)
function proofCount() external view returns (uint256)

event ProofStored(bytes32 indexed quoteHash, address indexed signingAddress, bool isValid, ...)
```

## Links

- **Website**: https://redpill.ai
- **Docs**: https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature
- **Gateway**: https://github.com/redpill-ai/redpill-gateway
- **Quote Explorer**: https://github.com/Phala-Network/ra-quote-explorer

## License

MIT
