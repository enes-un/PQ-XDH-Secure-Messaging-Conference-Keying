# PQ-XDH Secure Messaging Implementation

A Python-based implementation of a Post-Quantum Extended Triple Diffie-Hellman (PQXDH) messaging protocol. This project demonstrates secure end-to-end encryption (E2EE) by combining classical Elliptic Curve Cryptography (ECC) with CRYSTALS-Kyber post-quantum algorithms.

## 🔐 Key Security Features
- **Post-Quantum Security:** Integrated `Kyber1024` for key decapsulation (KEM) to protect against future quantum computing threats.
- **X3DH Hybrid Protocol:** Combines classical ECDH (using Ed25519) with Post-Quantum OTKs (One-Time Keys) for robust session key derivation.
- **Conference Key Establishment:** Implements a multi-party conference keying protocol based on partial key exchanges and verifiable signatures.
- **Digital Signatures:** Uses Edwards-curve Digital Signature Algorithm (EdDSA) for identity verification and registration.

## 🛠️ Technical Workflow
- **Key Generation & Registration:** Automated generation and server registration of Identity Keys (IK), Signed Pre-Keys (SPK), and both classical and PQ One-Time Keys (OTK).
- **Session Management:** Secure KDF (Key Derivation Function) chains using SHA3-256 for message-specific encryption keys.
- **Authenticated Encryption:** AES-CTR mode encryption combined with HMAC-SHA256 for message integrity and authenticity.
- **Server Interaction:** Full integration with a REST API for key bundle retrieval, message synchronization, and status tracking.

## 📦 Dependencies
- `ecpy` (Elliptic Curve operations)
- `pycryptodome` (AES, HMAC, SHA3)
- `kyber-py` (CRYSTALS-Kyber implementation)
- `requests` (API communication)
