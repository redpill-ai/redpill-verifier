#!/usr/bin/env python3
"""Straightforward walkthrough for checking a RedPill attestation."""

import argparse
import base64
import json
import re
import secrets
from hashlib import sha256

import requests

try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

API_BASE = "https://api.redpill.ai"
GPU_VERIFIER_API = "https://nras.attestation.nvidia.com/v3/attest/gpu"
PHALA_TDX_VERIFIER_API = "https://cloud-api.phala.network/api/v1/attestations/verify"
SIGSTORE_SEARCH_BASE = "https://search.sigstore.dev/?hash="

# Automata on-chain DCAP verifier deployments
AUTOMATA_NETWORKS = {
    "automata-mainnet": {
        "name": "Automata Mainnet",
        "chain_id": 65536,
        "rpc": "https://rpc.ata.network",
        "contract": "0xE26E11B257856B0bEBc4C759aaBDdea72B64351F",
        "explorer": "https://explorer.ata.network",
    },
    "automata-testnet": {
        "name": "Automata Testnet",
        "chain_id": 1398243,
        "rpc": "https://1rpc.io/ata/testnet",
        "contract": "0xefE368b17D137E86298eec8EbC5502fb56d27832",
        "explorer": "https://explorer-testnet.ata.network",
    },
    "sepolia": {
        "name": "Sepolia",
        "chain_id": 11155111,
        "rpc": "https://rpc.sepolia.org",
        "contract": "0x76A3657F2d6c5C66733e9b69ACaDadCd0B68788b",
        "explorer": "https://sepolia.etherscan.io",
    },
    "holesky": {
        "name": "Holesky",
        "chain_id": 17000,
        "rpc": "https://ethereum-holesky.publicnode.com",
        "contract": "0x133303659F51d75ED216FD98a0B70CbCD75339b2",
        "explorer": "https://holesky.etherscan.io",
    },
}

DCAP_VERIFY_ABI = [
    {
        "inputs": [{"name": "data", "type": "bytes"}],
        "name": "verifyAndAttestOnChain",
        "outputs": [
            {"name": "", "type": "bool"},
            {"name": "", "type": "bytes"},
        ],
        "stateMutability": "view",
        "type": "function",
    }
]


def fetch_report(model, nonce):
    """Fetch attestation report from the API."""
    url = f"{API_BASE}/v1/attestation/report?model={model}&nonce={nonce}"
    return requests.get(url, timeout=30).json()


def select_attestation(report):
    """Normalize legacy and gateway-wrapped attestation responses."""
    for key in ("model_attestations", "all_attestations"):
        attestations = report.get(key)
        if isinstance(attestations, list):
            for attestation in attestations:
                if isinstance(attestation, dict) and "signing_address" in attestation:
                    return attestation

    container = report.get("gateway_attestation")
    if isinstance(container, dict):
        return container

    return report


def fetch_nvidia_verification(payload):
    """Submit GPU evidence to NVIDIA NRAS for verification."""
    return requests.post(GPU_VERIFIER_API, json=payload, timeout=30).json()


def base64url_decode_jwt_payload(jwt_token):
    """Decode the payload section of a JWT token."""
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode()


def check_report_data(attestation, request_nonce, intel_result):
    """Verify that TDX report data binds the signing address and request nonce.

    Returns dict with verification results.
    """
    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = bytes.fromhex(report_data_hex.removeprefix("0x"))
    signing_address = attestation["signing_address"]
    signing_algo = attestation.get("signing_algo", "ecdsa").lower()

    # Parse signing address bytes based on algorithm
    if signing_algo == "ecdsa":
        addr_hex = signing_address.removeprefix("0x")
        signing_address_bytes = bytes.fromhex(addr_hex)
    else:
        signing_address_bytes = bytes.fromhex(signing_address)

    embedded_address = report_data[:32]
    embedded_nonce = report_data[32:]

    binds_address = embedded_address == signing_address_bytes.ljust(32, b"\x00")
    embeds_nonce = embedded_nonce.hex() == request_nonce

    print("Signing algorithm:", signing_algo)
    print("Report data binds signing address:", binds_address)
    print("Report data embeds request nonce:", embeds_nonce)

    return {
        "binds_address": binds_address,
        "embeds_nonce": embeds_nonce,
    }


def check_gpu(attestation, request_nonce):
    """Verify GPU attestation evidence via NVIDIA NRAS.

    Returns dict with verification results.
    """
    payload = json.loads(attestation["nvidia_payload"])

    # Verify GPU uses the same request_nonce
    nonce_matches = payload["nonce"].lower() == request_nonce.lower()
    print("GPU payload nonce matches request_nonce:", nonce_matches)

    body = fetch_nvidia_verification(payload)

    jwt_token = body[0][1]
    verdict = json.loads(base64url_decode_jwt_payload(jwt_token))["x-nvidia-overall-att-result"]
    print("NVIDIA attestation verdict:", verdict)

    return {
        "nonce_matches": nonce_matches,
        "verdict": verdict,
    }


def check_tdx_quote(attestation):
    """Verify Intel TDX quote via RedPill's verification service.

    Returns the full intel_result including decoded quote data.
    """
    intel_result = requests.post(PHALA_TDX_VERIFIER_API, json={"hex": attestation["intel_quote"]}, timeout=30).json()
    payload = intel_result.get("quote") or {}
    verified = payload.get("verified")
    print("Intel TDX quote verified:", verified)
    message = payload.get("message") or intel_result.get("message")
    if message:
        print("Intel TDX verifier message:", message)

    return intel_result


def extract_sigstore_links(compose):
    """Extract all @sha256:xxx image digests and return Sigstore search links."""
    if not compose:
        return []

    # Match @sha256:hexdigest pattern in Docker compose
    pattern = r'@sha256:([0-9a-f]{64})'
    digests = re.findall(pattern, compose)

    # Deduplicate digests while preserving order
    seen = set()
    unique_digests = []
    for digest in digests:
        if digest not in seen:
            seen.add(digest)
            unique_digests.append(digest)

    return [f"{SIGSTORE_SEARCH_BASE}sha256:{digest}" for digest in unique_digests]


def check_sigstore_links(links):
    """Check that Sigstore links are accessible (not 404)."""
    results = []
    for link in links:
        try:
            response = requests.head(link, timeout=10, allow_redirects=True)
            accessible = response.status_code < 400
            results.append((link, accessible, response.status_code))
        except requests.RequestException as e:
            results.append((link, False, str(e)))
    return results


def show_sigstore_provenance(attestation):
    """Extract and display Sigstore provenance links from attestation."""
    tcb_info = attestation.get("info", {}).get("tcb_info", {})
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
    compose = tcb_info.get("app_compose")
    if not compose:
        return

    sigstore_links = extract_sigstore_links(compose)
    if not sigstore_links:
        return

    print("\n🔐 Sigstore provenance")
    print("Checking Sigstore accessibility for container images...")
    link_results = check_sigstore_links(sigstore_links)

    for link, accessible, status in link_results:
        if accessible:
            print(f"  ✓ {link} (HTTP {status})")
        else:
            print(f"  ✗ {link} (HTTP {status})")


def check_onchain(attestation, network_key="automata-mainnet"):
    """Verify TDX quote on-chain via Automata's DCAP verifier contract.

    This is a view call (read-only, no gas, no wallet needed).
    Returns dict with verification results.
    """
    if not HAS_WEB3:
        print("web3 not installed, skipping on-chain verification")
        print("Install with: pip install web3")
        return {"verified": None, "error": "web3 not installed"}

    network = AUTOMATA_NETWORKS[network_key]
    print(f"Network: {network['name']} (chain {network['chain_id']})")

    w3 = Web3(Web3.HTTPProvider(network["rpc"], request_kwargs={"timeout": 120}))
    if not w3.is_connected():
        print(f"Cannot connect to {network['name']} RPC")
        return {"verified": None, "error": "RPC connection failed"}

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(network["contract"]),
        abi=DCAP_VERIFY_ABI,
    )

    quote_bytes = bytes.fromhex(attestation["intel_quote"].removeprefix("0x"))
    print(f"TDX quote size: {len(quote_bytes)} bytes")
    print(f"Calling verifyAndAttestOnChain() (may take 10-60s)...")

    try:
        is_valid, raw_data = contract.functions.verifyAndAttestOnChain(quote_bytes).call()
    except Exception as e:
        print(f"On-chain call failed: {e}")
        return {"verified": False, "error": str(e)}

    print(f"On-chain DCAP verified: {is_valid}")
    print(f"Contract: {network['contract']}")
    print(f"Explorer: {network['explorer']}/address/{network['contract']}")

    return {"verified": is_valid, "raw_data": raw_data.hex() if raw_data else ""}


def show_compose(attestation, intel_result):
    """Display the Docker compose manifest and verify against mr_config from verified quote."""
    tcb_info = attestation["info"]["tcb_info"]
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
    app_compose = tcb_info.get("app_compose")
    if not app_compose:
        return
    docker_compose = json.loads(app_compose)["docker_compose_file"]
        
    print("\nDocker compose manifest attested by the enclave:")
    print(docker_compose)

    compose_hash = sha256(app_compose.encode()).hexdigest()
    print("Compose sha256:", compose_hash)

    mr_config = intel_result["quote"]["body"]["mrconfig"]
    print("mr_config (from verified quote):", mr_config)
    expected_mr_config = "0x01" + compose_hash
    print("mr_config matches compose hash:", mr_config.lower().startswith(expected_mr_config.lower()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify RedPill TEE Attestation")
    parser.add_argument("--model", default="phala/gpt-oss-120b")
    parser.add_argument(
        "--network",
        default="automata-mainnet",
        choices=list(AUTOMATA_NETWORKS.keys()),
        help="Automata network for on-chain DCAP verification (default: automata-mainnet)",
    )
    parser.add_argument("--skip-onchain", action="store_true", help="Skip on-chain DCAP verification")
    args = parser.parse_args()

    request_nonce = secrets.token_hex(32)
    report = fetch_report(args.model, request_nonce)

    if "error" in report:
        raise RuntimeError(f"Attestation API error: {report['error']}")

    attestation = select_attestation(report)

    if "signing_address" not in attestation:
        raise KeyError(f"Missing signing_address in attestation payload. Top-level keys: {sorted(report.keys())}")

    print("\nSigning address:", attestation["signing_address"])
    print("Request nonce:", request_nonce)

    print("\n🔐 Intel TDX quote")
    intel_result = check_tdx_quote(attestation)

    print("\n🔐 TDX report data")
    check_report_data(attestation, request_nonce, intel_result)

    print("\n🔐 GPU attestation")
    check_gpu(attestation, request_nonce)

    show_compose(attestation, intel_result)
    show_sigstore_provenance(attestation)

    if not args.skip_onchain:
        print("\n🔐 On-chain DCAP verification")
        check_onchain(attestation, args.network)


if __name__ == "__main__":
    main()
