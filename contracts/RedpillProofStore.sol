// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RedpillProofStore
/// @notice Verifies TDX quotes on-chain via Automata DCAP and stores the results permanently.
///         Anyone can later query a proof by its quote hash to confirm that a specific TEE
///         attestation was verified valid at a given block.

interface IAutomataDcapAttestation {
    function verifyAndAttestOnChain(bytes calldata data)
        external
        view
        returns (bool success, bytes memory output);
}

contract RedpillProofStore {
    struct Proof {
        bytes32 quoteHash;
        address signingAddress;
        bool isValid;
        uint256 timestamp;
        uint256 blockNumber;
        address submitter;
    }

    IAutomataDcapAttestation public immutable dcapVerifier;

    /// @notice quoteHash => Proof
    mapping(bytes32 => Proof) public proofs;

    /// @notice All stored quote hashes in insertion order
    bytes32[] public proofHashes;

    event ProofStored(
        bytes32 indexed quoteHash,
        address indexed signingAddress,
        bool isValid,
        uint256 timestamp,
        address submitter
    );

    constructor(address _dcapVerifier) {
        dcapVerifier = IAutomataDcapAttestation(_dcapVerifier);
    }

    /// @notice Verify a TDX quote on-chain and permanently store the result.
    /// @param quote     Raw TDX quote bytes
    /// @param signingAddress The TEE signing address associated with this quote
    /// @return isValid  Whether the DCAP verification passed
    function verifyAndStore(bytes calldata quote, address signingAddress)
        external
        returns (bool isValid)
    {
        (isValid, ) = dcapVerifier.verifyAndAttestOnChain(quote);

        bytes32 quoteHash = keccak256(quote);

        proofs[quoteHash] = Proof({
            quoteHash: quoteHash,
            signingAddress: signingAddress,
            isValid: isValid,
            timestamp: block.timestamp,
            blockNumber: block.number,
            submitter: msg.sender
        });

        proofHashes.push(quoteHash);

        emit ProofStored(quoteHash, signingAddress, isValid, block.timestamp, msg.sender);
    }

    /// @notice Look up a previously stored proof by quote hash.
    function getProof(bytes32 quoteHash) external view returns (Proof memory) {
        return proofs[quoteHash];
    }

    /// @notice Total number of stored proofs.
    function proofCount() external view returns (uint256) {
        return proofHashes.length;
    }
}
