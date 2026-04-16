---
name: verify-tee
description: Verify TEE attestation and signatures for Redpill Confidential AI models. Runs the full trust chain — chat completion, ECDSA signature verification, Intel TDX + NVIDIA GPU attestation, and on-chain DCAP verification via Automata smart contracts. Use when the user wants to verify a model's TEE, check attestation, test signatures, or store on-chain proofs.
allowed-tools: Bash(python3 *), Bash(pip3 install *), Bash(cd /tmp/redpill-verifier *)
---

# Verify TEE from Redpill

Verify the full Confidential AI trust chain for any Redpill TEE-protected model.

## Setup

The verifier tools live in a separate repo. Clone if not already present:

```bash
test -d /tmp/redpill-verifier || gh repo clone redpill-ai/redpill-verifier /tmp/redpill-verifier
cd /tmp/redpill-verifier && pip3 install -r requirements.txt
```

## Available Verification Modes

### 1. Attestation Verification (No API key needed)

Verifies TDX quote, GPU attestation, report data binding, compose manifest, Sigstore provenance, and on-chain DCAP.

```bash
cd /tmp/redpill-verifier && python3 attestation_verifier.py --model <MODEL>
```

Options:
- `--model MODEL` — Model to verify (default: `phala/gpt-oss-120b`)
- `--network NETWORK` — Automata network for on-chain verification: `automata-mainnet`, `automata-testnet`, `sepolia`, `holesky` (default: `automata-mainnet`)
- `--skip-onchain` — Skip on-chain DCAP verification

### 2. Signature Verification (Requires API_KEY)

Sends a chat completion, fetches the ECDSA signature, verifies it, then runs full attestation.

```bash
cd /tmp/redpill-verifier && API_KEY=<key> python3 signature_verifier.py --model <MODEL>
```

### 3. On-Chain Proof — Verify Only (No API key, no wallet)

Verifies a TDX quote trustlessly on-chain via Automata's DCAP smart contract.

```bash
cd /tmp/redpill-verifier && python3 onchain_proof.py --model <MODEL> --network <NETWORK>
```

### 4. On-Chain Proof — Store (Requires PRIVATE_KEY + gas)

Verifies the TDX quote on-chain AND permanently stores the result in the RedpillProofStore contract.

```bash
cd /tmp/redpill-verifier && PRIVATE_KEY=<key> python3 onchain_proof.py --store \
  --proof-store <PROOF_STORE_ADDRESS> --network <NETWORK> --model <MODEL>
```

### 5. On-Chain Proof — Lookup

Query a previously stored proof by its quote hash.

```bash
cd /tmp/redpill-verifier && python3 onchain_proof.py --lookup <QUOTE_HASH> \
  --proof-store <PROOF_STORE_ADDRESS> --network <NETWORK>
```

## Available Phala Confidential Models

To list currently available models:

```bash
curl -s https://api.redpill.ai/v1/models | python3 -c "import sys,json; [print(m['id']) for m in json.load(sys.stdin)['data'] if 'phala' in m['id'].lower()]"
```

## Deployed Contracts

| Network | RedpillProofStore | Automata DCAP Verifier |
|---|---|---|
| Sepolia | `0x83541AD3f380De2b28E0108d4Da934236342B02b` | `0x76A3657F2d6c5C66733e9b69ACaDadCd0B68788b` |
| Automata Mainnet | — (not yet deployed) | `0xE26E11B257856B0bEBc4C759aaBDdea72B64351F` |

## What Gets Verified

| Check | What it proves |
|---|---|
| **ECDSA Signature** | A specific Ethereum address signed the request+response hashes |
| **Intel TDX Quote** | The CPU enclave is genuine Intel TDX |
| **Report Data Binding** | The signing key + nonce are embedded in the TDX quote |
| **NVIDIA GPU Attestation** | The GPU is genuine NVIDIA H100/H200 in confidential mode |
| **Compose Manifest** | The exact code and model running matches `mr_config` |
| **Sigstore Provenance** | Container images have verified build provenance |
| **On-Chain DCAP** | TDX quote verified trustlessly by a smart contract (no oracles) |
| **On-Chain Proof Store** | Permanent, immutable, queryable record of verification |

## Interaction Guidelines

1. **Ask which mode** the user wants if not clear (attestation-only, signature, on-chain verify, on-chain store)
2. **Ask for the model** if not specified — suggest `phala/gpt-oss-120b` as default
3. **Ask for API_KEY** if running signature verification and it's not set
4. **Ask for PRIVATE_KEY** if running on-chain store and it's not set
5. **Show the full output** — the verification results are the whole point
6. **Explain failures** — if a check fails, explain what it means and potential causes
