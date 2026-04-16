#!/usr/bin/env python3
"""Minimal guide for checking signed chat responses."""

import argparse
import json
import os
import secrets
from hashlib import sha256

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_verifier import (
    check_report_data,
    check_gpu,
    check_tdx_quote,
    select_attestation,
    show_sigstore_provenance,
)

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = "https://api.redpill.ai"


def sha256_text(text):
    """Calculate SHA256 hash of text."""
    return sha256(text.encode()).hexdigest()


def fetch_signature(chat_id, model):
    """Fetch signature for a chat completion."""
    url = f"{BASE_URL}/v1/signature/{chat_id}?model={model}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get(url, headers=headers, timeout=30).json()


def recover_signer(text, signature):
    """Recover Ethereum address from ECDSA signature."""
    message = encode_defunct(text=text)
    return Account.recover_message(message, signature=signature)


def fetch_attestation_for(signing_address, model):
    """Fetch attestation for a specific signing address."""
    nonce = secrets.token_hex(32)
    url = f"{BASE_URL}/v1/attestation/report?model={model}&nonce={nonce}&signing_address={signing_address}"
    report = requests.get(url, timeout=30).json()

    if "error" in report:
        raise RuntimeError(f"Attestation API error: {report['error']}")

    # Normalize all response formats (gateway+model, all_attestations, flat)
    attestation = select_attestation(report)

    # If multiple attestations, prefer the one matching signing_address
    for key in ("model_attestations", "all_attestations"):
        items = report.get(key, [])
        for item in items:
            if isinstance(item, dict) and item.get("signing_address", "").lower() == signing_address.lower():
                attestation = item
                break

    return attestation, nonce


def check_attestation(signing_address, attestation, nonce):
    """Verify attestation for a signing address (calls check_report_data, check_gpu, check_tdx_quote)."""
    intel_result = check_tdx_quote(attestation)
    check_report_data(attestation, nonce, intel_result)
    check_gpu(attestation, nonce)
    show_sigstore_provenance(attestation)


def verify_chat(chat_id, request_body, response_text, label, model):
    """Verify a chat completion signature and attestation."""
    request_hash = sha256_text(request_body)
    response_hash = sha256_text(response_text)

    print(f"\n--- {label} ---")
    signature_payload = fetch_signature(chat_id, model)
    print(json.dumps(signature_payload, indent=2))

    if "error" in signature_payload:
        print(f"Signature error: {signature_payload['error']}")
        return

    hashed_text = signature_payload["text"]
    # Format may be "req_hash:resp_hash" or "model:req_hash:resp_hash"
    parts = hashed_text.split(":")
    if len(parts) == 3:
        request_hash_server, response_hash_server = parts[1], parts[2]
    elif len(parts) == 2:
        request_hash_server, response_hash_server = parts[0], parts[1]
    else:
        raise ValueError(f"Unexpected signature text format ({len(parts)} parts): {hashed_text[:60]}...")
    print("Request hash matches:", request_hash == request_hash_server)
    print("Response hash matches:", response_hash == response_hash_server)

    signature = signature_payload["signature"]
    signing_address = signature_payload["signing_address"]
    recovered = recover_signer(hashed_text, signature)
    print("Signature valid:", recovered.lower() == signing_address.lower())

    attestation, nonce = fetch_attestation_for(signing_address, model)
    print("\nAttestation signer:", attestation["signing_address"])
    print("Attestation nonce:", nonce)
    check_attestation(signing_address, attestation, nonce)


def streaming_example(model):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": True,
        "max_tokens": 1,
    }
    body_json = json.dumps(body)
    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        data=body_json,
        stream=True,
        timeout=30,
    )

    chat_id = None
    response_text = ""
    for chunk in response.iter_lines():
        line = chunk.decode()
        response_text += line + "\n"
        if chat_id is None and line.startswith("data:"):
            data_str = line[5:].strip()
            if data_str.startswith("{"):
                try:
                    chat_id = json.loads(data_str)["id"]
                except (json.JSONDecodeError, KeyError):
                    pass

    verify_chat(chat_id, body_json, response_text, "Streaming example", model)


def non_streaming_example(model):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": False,
        "max_tokens": 1,
    }
    body_json = json.dumps(body)
    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        data=body_json,
        timeout=30,
    )

    payload = response.json()
    chat_id = payload["id"]
    verify_chat(chat_id, body_json, response.text, "Non-streaming example", model)


def main():
    """Run example verification of streaming and non-streaming chat completions."""
    parser = argparse.ArgumentParser(description="Verify Signed Chat Responses")
    parser.add_argument("--model", default="phala/gpt-oss-120b")
    args = parser.parse_args()

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        print("Set it with: export API_KEY=your-api-key")
        return
    streaming_example(args.model)
    non_streaming_example(args.model)


if __name__ == "__main__":
    main()
