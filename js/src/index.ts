// Core verification functions
export {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  checkCompose,
  checkSigstore,
  verifyOnchain,
  verifyAttestation,
} from './attestation.js'

// Signature verification
export {
  chat,
  fetchSignature,
  recoverSigner,
  verifyResponse,
  verifySignature,
} from './signature.js'

// On-chain proof storage
export {
  verifyOnchainFull,
  storeProof,
  lookupProof,
} from './onchain.js'

// Utilities
export { sha256, randomNonce, decodeJwtPayload, selectAttestation } from './utils.js'

// Constants
export { API_BASE, AUTOMATA_NETWORKS, DCAP_VERIFY_ABI, PROOF_STORE_ABI, DEFAULT_MODEL } from './constants.js'

// Types
export type {
  AttestationReport,
  RawAttestation,
  TdxQuote,
  TdxQuoteBody,
  SignaturePayload,
  AttestationResult,
  SignatureResult,
  OnchainVerifyResult,
  ProofRecord,
  StoreProofResult,
  NetworkConfig,
  NetworkKey,
  VerifyAttestationOptions,
  VerifyResponseOptions,
  VerifySignatureOptions,
  VerifyOnchainOptions,
  StoreProofOptions,
  LookupProofOptions,
} from './types.js'
