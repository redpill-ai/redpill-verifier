#!/usr/bin/env python3
"""
Store RedPill TEE attestation proofs on-chain.

Verifies a TDX quote via Automata's on-chain DCAP verifier and permanently stores
the result in the RedpillProofStore contract. Anyone can later query the proof by
its quote hash to confirm the attestation was verified valid.

Two modes:
  --verify-only   Just call verifyAndAttestOnChain() (free, no wallet needed)
  --store         Call verifyAndStore() on the proof store contract (requires wallet + gas)

Usage:
  # Verify only (no wallet needed)
  python3 onchain_proof.py --model phala/gpt-oss-120b

  # Store proof on-chain (requires PRIVATE_KEY env var)
  PRIVATE_KEY=0x... python3 onchain_proof.py --model phala/gpt-oss-120b --store

  # Query an existing proof
  python3 onchain_proof.py --lookup 0xabcdef...

  # Deploy the RedpillProofStore contract (one-time setup)
  PRIVATE_KEY=0x... python3 onchain_proof.py --deploy
"""

import argparse
import json
import os
import secrets
import sys

import requests
from web3 import Web3

from attestation_verifier import (
    AUTOMATA_NETWORKS,
    DCAP_VERIFY_ABI,
    fetch_report,
    select_attestation,
)

# ---------------------------------------------------------------------------
# RedpillProofStore ABI (compiled from contracts/RedpillProofStore.sol)
# Only includes the functions we call — deploy with full bytecode separately.
# ---------------------------------------------------------------------------

PROOF_STORE_ABI = [
    {
        "inputs": [{"name": "_dcapVerifier", "type": "address"}],
        "stateMutability": "nonpayable",
        "type": "constructor",
    },
    {
        "inputs": [
            {"name": "quote", "type": "bytes"},
            {"name": "signingAddress", "type": "address"},
        ],
        "name": "verifyAndStore",
        "outputs": [{"name": "isValid", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "quoteHash", "type": "bytes32"}],
        "name": "getProof",
        "outputs": [
            {
                "components": [
                    {"name": "quoteHash", "type": "bytes32"},
                    {"name": "signingAddress", "type": "address"},
                    {"name": "isValid", "type": "bool"},
                    {"name": "timestamp", "type": "uint256"},
                    {"name": "blockNumber", "type": "uint256"},
                    {"name": "submitter", "type": "address"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "proofCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "quoteHash", "type": "bytes32"},
            {"indexed": True, "name": "signingAddress", "type": "address"},
            {"indexed": False, "name": "isValid", "type": "bool"},
            {"indexed": False, "name": "timestamp", "type": "uint256"},
            {"indexed": False, "name": "submitter", "type": "address"},
        ],
        "name": "ProofStored",
        "type": "event",
    },
]


def connect(network_key):
    """Connect to the RPC and return (web3, network_config)."""
    network = AUTOMATA_NETWORKS[network_key]
    w3 = Web3(Web3.HTTPProvider(network["rpc"], request_kwargs={"timeout": 180}))
    if not w3.is_connected():
        print(f"Error: Cannot connect to {network['name']} RPC at {network['rpc']}")
        sys.exit(1)
    print(f"Connected to {network['name']} (chain {network['chain_id']})")
    return w3, network


def get_account(w3):
    """Load account from PRIVATE_KEY env var."""
    pk = os.environ.get("PRIVATE_KEY", "")
    if not pk:
        print("Error: PRIVATE_KEY environment variable is required for on-chain transactions")
        print("Set it with: export PRIVATE_KEY=0x...")
        sys.exit(1)
    account = w3.eth.account.from_key(pk)
    print(f"Wallet: {account.address}")
    balance = w3.eth.get_balance(account.address)
    print(f"Balance: {w3.from_wei(balance, 'ether')} ETH")
    return account


def fetch_attestation(model):
    """Fetch attestation and return (attestation, nonce)."""
    nonce = secrets.token_hex(32)
    print(f"Fetching attestation for {model}...")
    report = fetch_report(model, nonce)

    if "error" in report:
        print(f"Error: {report['error']}")
        sys.exit(1)

    attestation = select_attestation(report)
    if "signing_address" not in attestation:
        print(f"Error: No signing_address in attestation. Keys: {sorted(report.keys())}")
        sys.exit(1)

    print(f"Signing address: {attestation['signing_address']}")
    return attestation, nonce


# ---------------------------------------------------------------------------
# Mode: verify-only (free, no wallet)
# ---------------------------------------------------------------------------

def cmd_verify(args):
    """Verify a TDX quote on-chain (view call, no gas)."""
    w3, network = connect(args.network)
    attestation, nonce = fetch_attestation(args.model)

    quote_bytes = bytes.fromhex(attestation["intel_quote"].removeprefix("0x"))
    print(f"TDX quote: {len(quote_bytes)} bytes")
    quote_hash = Web3.keccak(quote_bytes).hex()
    print(f"Quote hash: {quote_hash}")

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(network["contract"]),
        abi=DCAP_VERIFY_ABI,
    )

    print(f"\nCalling verifyAndAttestOnChain() on {network['contract']}...")
    print("(This may take 10-60 seconds)")
    is_valid, raw_data = contract.functions.verifyAndAttestOnChain(quote_bytes).call()

    print(f"\nResult: {'VALID' if is_valid else 'INVALID'}")
    print(f"Quote hash: {quote_hash}")
    print(f"Signing address: {attestation['signing_address']}")
    print(f"Explorer: {network['explorer']}/address/{network['contract']}")
    return is_valid


# ---------------------------------------------------------------------------
# Mode: store (requires wallet + gas)
# ---------------------------------------------------------------------------

def cmd_store(args):
    """Verify and store a TDX quote proof on-chain (requires wallet)."""
    if not args.proof_store:
        print("Error: --proof-store CONTRACT_ADDRESS is required")
        print("Deploy first with: python3 onchain_proof.py --deploy")
        sys.exit(1)

    w3, network = connect(args.network)
    account = get_account(w3)
    attestation, nonce = fetch_attestation(args.model)

    quote_bytes = bytes.fromhex(attestation["intel_quote"].removeprefix("0x"))
    signing_address = attestation["signing_address"]
    quote_hash = Web3.keccak(quote_bytes).hex()
    print(f"TDX quote: {len(quote_bytes)} bytes")
    print(f"Quote hash: {quote_hash}")

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(args.proof_store),
        abi=PROOF_STORE_ABI,
    )

    # Build and send the transaction
    print(f"\nCalling verifyAndStore() on {args.proof_store}...")
    print("(This submits a transaction — gas will be consumed)")

    signing_addr_checksum = Web3.to_checksum_address(signing_address)
    tx = contract.functions.verifyAndStore(quote_bytes, signing_addr_checksum).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 50_000_000,  # DCAP verification is compute-heavy
        "maxFeePerGas": w3.eth.gas_price * 2,
        "maxPriorityFeePerGas": w3.eth.gas_price,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, account.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Transaction sent: {tx_hash.hex()}")
    print("Waiting for confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    print(f"Status: {'SUCCESS' if receipt['status'] == 1 else 'REVERTED'}")
    print(f"Block: {receipt['blockNumber']}")
    print(f"Gas used: {receipt['gasUsed']}")
    print(f"Tx: {network['explorer']}/tx/{tx_hash.hex()}")

    # Parse the ProofStored event
    events = contract.events.ProofStored().process_receipt(receipt)
    if events:
        e = events[0]["args"]
        print(f"\nProof stored on-chain:")
        print(f"  Quote hash:       {e['quoteHash'].hex()}")
        print(f"  Signing address:  {e['signingAddress']}")
        print(f"  Valid:            {e['isValid']}")
        print(f"  Timestamp:        {e['timestamp']}")

    return receipt["status"] == 1


# ---------------------------------------------------------------------------
# Mode: lookup an existing proof
# ---------------------------------------------------------------------------

def cmd_lookup(args):
    """Look up a previously stored proof by quote hash."""
    if not args.proof_store:
        print("Error: --proof-store CONTRACT_ADDRESS is required")
        sys.exit(1)

    w3, network = connect(args.network)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(args.proof_store),
        abi=PROOF_STORE_ABI,
    )

    quote_hash = bytes.fromhex(args.lookup.removeprefix("0x"))
    proof = contract.functions.getProof(quote_hash).call()

    # proof is a tuple: (quoteHash, signingAddress, isValid, timestamp, blockNumber, submitter)
    if proof[0] == b"\x00" * 32:
        print(f"No proof found for quote hash {args.lookup}")
        return

    print(f"Proof found:")
    print(f"  Quote hash:       0x{proof[0].hex()}")
    print(f"  Signing address:  {proof[1]}")
    print(f"  Valid:            {proof[2]}")
    print(f"  Timestamp:        {proof[3]}")
    print(f"  Block number:     {proof[4]}")
    print(f"  Submitter:        {proof[5]}")

    count = contract.functions.proofCount().call()
    print(f"\nTotal proofs stored: {count}")


# ---------------------------------------------------------------------------
# Mode: deploy the RedpillProofStore contract
# ---------------------------------------------------------------------------

def cmd_deploy(args):
    """Deploy the RedpillProofStore contract."""
    w3, network = connect(args.network)
    account = get_account(w3)

    dcap_address = Web3.to_checksum_address(network["contract"])
    print(f"Deploying RedpillProofStore with DCAP verifier: {dcap_address}")
    print()
    print("NOTE: You need the compiled contract bytecode to deploy.")
    print("Compile contracts/RedpillProofStore.sol with solc or Remix, then set:")
    print("  export PROOF_STORE_BYTECODE=0x...")
    print()

    bytecode = os.environ.get("PROOF_STORE_BYTECODE", "")
    if not bytecode:
        print("Error: PROOF_STORE_BYTECODE environment variable is required")
        print("Compile the contract first:")
        print("  solc --bin --abi contracts/RedpillProofStore.sol -o contracts/build/")
        print("  export PROOF_STORE_BYTECODE=$(cat contracts/build/RedpillProofStore.bin)")
        sys.exit(1)

    contract = w3.eth.contract(abi=PROOF_STORE_ABI, bytecode=bytecode)
    tx = contract.constructor(dcap_address).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 2_000_000,
        "maxFeePerGas": w3.eth.gas_price * 2,
        "maxPriorityFeePerGas": w3.eth.gas_price,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, account.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Deploy tx sent: {tx_hash.hex()}")
    print("Waiting for confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    if receipt["status"] == 1:
        print(f"RedpillProofStore deployed at: {receipt['contractAddress']}")
        print(f"Explorer: {network['explorer']}/address/{receipt['contractAddress']}")
        print(f"\nUse this address with --proof-store {receipt['contractAddress']}")
    else:
        print("Deploy transaction reverted")

    return receipt.get("contractAddress")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Store RedPill TEE attestation proofs on-chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Verify only (free, no wallet needed)
  python3 onchain_proof.py --model phala/gpt-oss-120b

  # Store proof (requires wallet + gas)
  PRIVATE_KEY=0x... python3 onchain_proof.py --store --proof-store 0x... --model phala/gpt-oss-120b

  # Look up a stored proof
  python3 onchain_proof.py --lookup 0xabcdef... --proof-store 0x...

  # Deploy the proof store contract
  PROOF_STORE_BYTECODE=0x... PRIVATE_KEY=0x... python3 onchain_proof.py --deploy
""",
    )
    parser.add_argument("--model", default="phala/gpt-oss-120b", help="Model to verify")
    parser.add_argument(
        "--network",
        default="automata-mainnet",
        choices=list(AUTOMATA_NETWORKS.keys()),
        help="Automata network (default: automata-mainnet)",
    )
    parser.add_argument("--proof-store", help="RedpillProofStore contract address")
    parser.add_argument("--store", action="store_true", help="Store proof on-chain (requires PRIVATE_KEY)")
    parser.add_argument("--lookup", help="Look up a stored proof by quote hash (0x...)")
    parser.add_argument("--deploy", action="store_true", help="Deploy the RedpillProofStore contract")
    args = parser.parse_args()

    if args.deploy:
        cmd_deploy(args)
    elif args.lookup:
        cmd_lookup(args)
    elif args.store:
        cmd_store(args)
    else:
        cmd_verify(args)


if __name__ == "__main__":
    main()
