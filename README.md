# veqtrx-crypto-reference

**Reference implementation of Veqtrx's client-side zero-knowledge encryption.**

This repository contains the actual cryptographic code that runs in every Veqtrx user's browser. It is published so that anyone — banks, security researchers, regulators, customers — can verify the zero-knowledge claim independently rather than taking our word for it.

> Veqtrx is a UK affordability/budget-assessment platform. When a customer creates a budget, their data is encrypted in their browser with a key the server never sees. This repo is the code that does that encryption.

## Status

| | |
|---|---|
| **Version** | 1.0.0 |
| **License** | [MIT](./LICENSE) |
| **External audit** | Planned Q2 2027 (SOC 2 Type I roadmap). See [whitepaper](#related-documents). |
| **Production usage** | This exact file ships verbatim to every visitor of veqtrx.co.uk |

## TL;DR — the three claims

1. **The server never sees plaintext customer data.** All encryption happens in the browser before any HTTP request leaves the user's machine. Verify: `test/zero-knowledge.test.ts → PROOF #1`.
2. **The server never sees a key capable of decrypting it.** The Key Encryption Key (KEK) is derived from the user's password in-browser via PBKDF2-SHA256 with 600,000 iterations. The KEK never crosses the network. Verify: `test/zero-knowledge.test.ts → PROOF #2`.
3. **The customer's password never leaves the browser.** It is only consumed by `deriveKEK()` which immediately imports it as a non-extractable `CryptoKey`. Anything outside that function path that references a password is a bug. Verify: `grep -n "password" src/zero-knowledge.ts`.

## Architecture in one diagram

```
                       ┌─────────────────────────────────────────────┐
                       │             BROWSER (trusted)               │
                       │                                             │
  password ─────►  PBKDF2(600k, SHA-256, salt)  ─────► KEK (256-bit) │
                                                          │          │
  budget data ───► AES-GCM (random nonce) ─┬────────────► ciphertext │
                       ▲                   │                         │
                       │                   ▼                         │
                       └────────────  DEK (256-bit)                  │
                                            │                        │
                       ┌────────────────────┼────────────────────┐   │
                       │ (wrapped 3 ways)   │                    │   │
                       ▼                    ▼                    ▼   │
              wrap with KEK      wrap with agent RSA      wrap with  │
              (customer)         public key (advisor)     share key  │
                       │                    │             (creditor) │
                       ▼                    ▼                    ▼   │
                  ┌────┴────────────────────┴────────────────────┴──┐│
                  │       Upload to server: only ciphertext         ││
                  │       + wrapped-DEK rows (no key material)      ││
                  └─────────────────────┬───────────────────────────┘│
                                        │                            │
                       ┌────────────────┼────────────────────────────┘
                       ▼                ▼
                  ┌────────────────────────────┐
                  │     SERVER (untrusted)     │
                  │  Stores ciphertext only.   │
                  │  Cannot decrypt — has no   │
                  │  key material.             │
                  └────────────────────────────┘
```

## What's in this repo

```
src/
  zero-knowledge.ts        # The crypto module — 360 LOC, single file.
test/
  zero-knowledge.test.ts   # Verification tests + the "proofs"
README.md                  # This file
LICENSE                    # MIT
package.json
tsconfig.json
```

## What's deliberately NOT in this repo

The following live in the private Veqtrx application repo:
- API endpoints (`back/routers/*`)
- Business logic (affordability engine, persona library)
- Database schema and migrations
- Customer-data handling code
- Plaid / partner integrations

The public surface is exactly the cryptographic primitives. Everything else is application-specific and not relevant to the zero-knowledge claim.

## Verify it yourself

```bash
git clone https://github.com/vaibhavkiyer24/veqtrx-crypto-reference.git
cd veqtrx-crypto-reference
npm install
npm test
```

All tests should pass on Node 20+ (uses the built-in `globalThis.crypto`). Each test demonstrates a specific property of the construction — read the test file, it's commented for readers, not for CI alone.

To confirm this is the exact code running in production:

1. Visit https://veqtrx.co.uk in a browser.
2. Open DevTools → Sources → look for the bundled chunk containing `deriveKEK`.
3. Diff against `src/zero-knowledge.ts` in this repo. Comments may differ (build minification); function bodies should be identical modulo minification.

## Cryptographic choices

| Primitive | Choice | Why |
|---|---|---|
| Password hashing for KEK | **PBKDF2-SHA256 @ 600,000 iter** | OWASP 2026 recommendation. Argon2 would be stronger but isn't in Web Crypto yet. |
| KEK / DEK / share-key | **AES-GCM 256-bit** | NIST-approved authenticated encryption. AEAD blocks ciphertext tampering. |
| Agent flow asymmetric | **RSA-OAEP 2048-bit + SHA-256** | Web Crypto's only widely-available asymmetric option. Curve25519 isn't in Web Crypto yet. |
| Salt | **32 random bytes from `crypto.getRandomValues`** | NIST SP 800-132 recommends ≥16; we use 32. |
| Share token | **32 random bytes, base64url-encoded** | 256 bits of entropy — no KDF needed on top. |

## Threat model

What this construction defends against:
- **Server compromise** — attacker who reads the database sees only ciphertext + wrapped DEKs. No plaintext, no decryptable keys.
- **TLS interception by a malicious proxy** — attacker sees ciphertext only.
- **Insider access at Veqtrx** — engineers / sysadmins / employees have no path to plaintext.
- **Government subpoena of server data** — we can produce ciphertext but cannot decrypt it.

What this construction does **not** defend against:
- **Client compromise** — malware on the user's device with access to the browser process can read decrypted data while the user views it. (Same as every other web application.)
- **Weak passwords** — a customer choosing `password123` makes PBKDF2 useless. We require minimum length and recommend strong passwords in the UI but cannot force it.
- **Phishing** — a customer typing their password into a fake site reveals it. Standard browser security model applies.
- **Web Crypto bugs** — we depend on the browser's `crypto.subtle` being implemented correctly. We have no way to verify it from JavaScript.

## Related documents

- **Security whitepaper** — full architecture + threat model + audit roadmap. https://veqtrx.co.uk/security-whitepaper.html
- **Security overview + FAQ** — what we can/cannot see, audit trail, compliance roadmap, top FAQ. https://veqtrx.co.uk/security
- **Privacy policy** — UK GDPR posture. https://veqtrx.co.uk/privacy

## Reporting issues

Found a vulnerability? Please email security disclosures to **hello.veqtrx@proton.me** (PGP key on request). We do not currently run a paid bug bounty but will publicly acknowledge confirmed reports.

For general questions about this code or the zero-knowledge architecture, open a GitHub Issue.

## License

MIT. See [LICENSE](./LICENSE).

## Contributing

We accept pull requests that:
- Tighten a cryptographic primitive (e.g. higher iteration count)
- Add tests that strengthen the proof
- Improve documentation clarity

We do **not** accept pull requests that:
- Add new dependencies (the audit surface stays minimal)
- Add new exported functions without a corresponding test
- Touch the constants block (`PBKDF2_ITERATIONS_DEFAULT`, etc.) without independent review

For any change to the cryptographic primitives, expect a slow review.
