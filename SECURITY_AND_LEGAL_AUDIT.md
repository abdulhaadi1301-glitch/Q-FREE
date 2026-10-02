# QFree Security, Legal & Architecture Audit Report

**Application:** QFree — Live Queue Tracking (India OPD/Clinic/Lab Healthcare Ecosystem)  
**Applicable Legal Framework:** Digital Personal Data Protection Act 2023 (DPDP Act, India) & CERT-In Guidelines  
**Current Audit Status:** **PHASE 1 & PHASE 2 COMPLETED & VERIFIED**  
**Architecture:** Zero-Trust Server-Authoritative (Express + TypeScript + Firestore / Persistent DB Adapter)

---

## 1. Executive Summary & Architecture Paradigm Shift

### Previous State (Phase 0 / Frontend-Only Prototype)
- Database instances and queue calculation engines (`qfreeDb`, `tokenEngine`) executed directly inside each user's browser runtime.
- State was desynchronised across different patient and doctor devices.
- Tamper risks existed through browser developer tools.

### Completed State (Phase 1 & Phase 2 Production Hardening)
- **Single Source of Truth:** The Express backend is now the **sole authoritative owner** of all queue state, token booking, status transitions, wait-time algorithms, and access permissions.
- **Repository / Adapter Pattern:** Database operations are decoupled behind `IQFreeRepository` (`server/db/repository.ts`), persisting to Firestore via Firebase Admin SDK with persistent disk backup and full compatibility for migration to PostgreSQL.
- **Zero-Trust Client Access:** The React frontend contains zero direct database or engine logic. All communication travels through `src/api/apiClient.ts` with strict `httpOnly` cookie session validation.
- **Real-Time Synchronisation:** Server-Sent Events (SSE) via `/api/realtime/stream` deliver instant updates to patient live queue tracking screens, provider dashboards, and admin monitoring views simultaneously without manual polling or refresh.
- **Atomic Concurrency Control:** Token creation is guarded by queue-level mutex locks (`bookTokenAtomic`), preventing token duplication and enforcing strict daily capacity limits under high concurrency.

---

## 2. Completed Phase 1 Milestones

- [x] **Verified Google Login Flow:** Server-side Google ID token verification via `google-auth-library`.
- [x] **Secure Session Architecture:** Sessions stored with cryptographic HMAC signatures in `httpOnly`, `SameSite=Lax`, `Secure` cookies (`qfree_session`), mitigating XSS token theft.
- [x] **Role-Based Access Control (RBAC):** Express middleware `requireRole(['PATIENT' | 'PROVIDER' | 'ADMIN'])` strictly enforced on all operational routes.
- [x] **Resource Ownership Verification:** Providers can only read, update, call, or pause queues belonging to their authenticated clinic ID. Patients can only query their own tokens and history.
- [x] **Strict PII Redaction & Minimisation:**
  - Patient phone numbers and emails are strictly stripped from all public and provider queue feeds.
  - Patient names are redacted to initials only for other waiting patients in the queue.
- [x] **Hardened HTTP Security Headers:** Helmet-configured Content-Security-Policy (CSP), `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and strict CORS whitelist.
- [x] **Rate Limiting:** Granular rate limits applied per IP and session for authentication, token generation, and administrative actions.
- [x] **Cryptographic Audit Trail:** High-integrity append-only audit logging recording security events, access denials, data exports, and token cancellations.

---

## 3. Completed Phase 2 Milestones (Moved from Pending to Completed)

- [x] **Persistent Database Layer (`server/db/repository.ts`):**
  - Concrete implementation of `IQFreeRepository` handling Users, Providers, Queues, Tokens, Provider Applications, Notifications, Audit Logs, and User Consents.
  - Dual persistent backend using Firebase Firestore (via `firebase-admin`) with fallback disk journaling (`.data/qfree-db.json`) ensuring 100% data durability across server restarts.
- [x] **Server-Authoritative Queue & Wait Estimation Engines (`server/engine/ServerQueueEngine.ts`):**
  - Extracted and ported domain logic from `QFreeDatabase.ts`, `TokenEngine.ts`, `QueueEngine.ts`, and `DynamicEstimatedWaitEngine.ts` to the backend.
  - Dynamic wait-time computation considering consultation duration, doctor delay offsets, tokens ahead, and operational pause states.
- [x] **Atomic Token Booking Transactions:**
  - Sequential, non-colliding token generation wrapped in serialized queue-level execution locks.
  - Strict daily limit enforcement (`dailyTokenLimit`). When limit is reached, incoming requests are rejected with `400 Bad Request: Queue capacity reached`.
- [x] **Client-Side Engine Decoupling:**
  - Removed all direct imports and instances of database and queue engines from `src/modules/`, `src/components/`, and `src/api/`.
  - Replaced with unified `apiClient.ts` communicating through REST endpoints and SSE streams.
- [x] **Real-Time Cross-Device Synchronization:**
  - Dedicated `/api/realtime/stream?queueId=...` endpoint powered by Node.js EventEmitter and SSE.
  - `useLiveQueueTracking.ts` seamlessly connects via EventSource with reconnection backoff and tab visibility management.
- [x] **Provider Approval & Provisioning Workflow:**
  - When an administrator reviews and approves a `ProviderApplicationRecord`, the server automatically:
    1. Instantiates a new `ProviderRecord`.
    2. Provisions today's operational `QueueRecord`.
    3. Promotes the applicant `User` to `PROVIDER` role and associates their `providerId`.
    4. Records an audit log event and emits real-time notifications to the applicant.
- [x] **Gated Demo Tools:**
  - The Live Engine Playground, Edge-Case Matrix, Architecture View, and Schema Explorer are strictly locked behind `DEMO_MODE=true` AND `ADMIN` role checks.
- [x] **Real Database Seeding:**
  - Production database initializes cleanly with real entities. In-memory demo seeds are only mounted when `DEMO_MODE=true`.

---

## 4. DPDP Act 2023 Compliance & Data Principal Rights

| Requirement | Implementation Details | Status |
| :--- | :--- | :--- |
| **Notice & Explicit Consent (§6)** | Mandatory consent recorded before token generation (`/api/me/consent`). Granular purposes stored with timestamp and IP. | **Compliant** |
| **Right to Access & Data Portability (§11)** | `/api/me/export` endpoint provides a machine-readable JSON archive of all personal data, bookings, and consent records. | **Compliant** |
| **Right to Erasure / "Right to be Forgotten" (§12)** | `DELETE /api/me` permanently purges the user profile, invalidates all sessions, and anonymises prior booking records. | **Compliant** |
| **Automated 90-Day PII Retention Scrub** | Scheduled background task runs daily, purging consultation notes and masking identifiers for completed tokens older than 90 days. | **Compliant** |
| **Purpose Limitation & Minimisation (§4)** | Only minimum requisite data (patient name, optional emergency phone) requested for queue operations. | **Compliant** |

---

## 5. Security Invariant Matrix

1. **Client Identity Invariance:** All user IDs, roles, and provider affiliations are derived exclusively from verified sessions. Client-supplied parameters in request bodies are ignored.
2. **Provider Isolation Invariance:** Any query or mutation on `/api/queues/:id/*` checks `queue.providerId === req.user.providerId`. Cross-tenant tampering yields `403 Forbidden`.
3. **Queue Limit Invariance:** Under high concurrency, total issued tokens for a queue cannot exceed `dailyTokenLimit`. Extra bookings are rejected before state alteration.
4. **Token Monotonicity:** Token numbers strictly increment from `1` to `N` for any given date and queue.

---

## 6. Phase 3 Roadmap (Future Considerations)

- **Dedicated SMS / WhatsApp OTP Providers:** Integration with TRAI DLT-registered SMS gateways (e.g., MSG91, Twilio India) once carrier templates are approved.
- **Hardware Display Integration:** Webhook endpoints for clinic waiting-room TV displays and digital token calling screens.
