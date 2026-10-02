/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * QFree Server-Authoritative Backend Entrypoint
 * Express + TypeScript + Vite Middleware + Hardened Security
 */

import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { repository } from './server/db/repository.ts';
import { serverQueueEngine } from './server/engine/ServerQueueEngine.ts';
import { serverRealtimeBus } from './server/realtime.ts';
import { registerPlatformRoutes } from './server/platform/platformRoutes.ts';
import {
  AuthenticatedRequest,
  sessionStore,
  extractSessionToken,
  createRequireAuth,
  createRequireRole,
  createRequireSuperAdmin,
  verifyProviderOwnership,
  redactTokenPII,
  validateIndianMobileNumber,
  sanitizeString,
  rateLimiter,
  securityHeadersMiddleware,
  SecurityAuditEntry,
  PatientConsentEntry,
} from './server/security.ts';
import { AuthUser, UserRole } from './src/core/types/index.ts';
import { ProviderRecord, ProviderApplicationRecord } from './src/core/database/schema.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_DEMO_MODE = process.env.DEMO_MODE === 'true' || process.env.VITE_DEMO_MODE === 'true';

// ============================================================================
// Core Middleware: JSON Body Parser, Security Headers, Rate Limiting
// ============================================================================

// 4 MB limit so compressed provider branding images (data URLs) are not rejected with 413
app.use(express.json({ limit: '4mb' }));
app.use(securityHeadersMiddleware);

// Global API Rate Limiter: 120 req / minute
app.use('/api', rateLimiter(60000, 120, 'Too many requests to QFree API. Please slow down.'));

// Specialized Rate Limiter for Booking: 30 bookings / minute per IP
const bookingRateLimiter = rateLimiter(60000, 30, 'Booking rate limit reached. Please wait before booking again.');

// Specialized Rate Limiter for Auth: 20 attempts / minute
const authRateLimiter = rateLimiter(60000, 20, 'Authentication rate limit reached. Please wait a moment.');

// Helper to look up AuthUser from repository
async function getUserByIdHelper(userId: string): Promise<AuthUser | null> {
  const user = await repository.getUser(userId);
  if (!user) return null;

  let providerName: string | undefined;
  let providerId: string | undefined;

  if (user.role === 'PROVIDER') {
    // Look up provider
    const allProv = await repository.getAllProviders();
    const myProv = allProv.find((p) => p.email === user.email || p.phone === user.phone) || allProv[0];
    if (myProv) {
      providerId = myProv.id;
      providerName = myProv.organizationName;
    }
  }

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    avatarUrl: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(user.name)}`,
    role: user.role,
    isRoleAssigned: Boolean(user.role),
    providerId,
    providerName,
    createdAt: user.createdAt,
    lastLoginAt: new Date().toISOString(),
  };
}

const requireAuth = createRequireAuth(getUserByIdHelper);
const requireRole = (roles: UserRole[]) => createRequireRole(roles, getUserByIdHelper);
// Platform configuration (feature flags, promotions, branding, support, maintenance): SUPER_ADMIN only.
const requireSuperAdmin = createRequireSuperAdmin(getUserByIdHelper);

// ============================================================================
// Platform Control Center helpers (feature flags + maintenance mode)
// ============================================================================

/** Resolves the signed-in user from the session without rejecting anonymous requests. */
async function getSessionUser(req: Request): Promise<{ id: string; name: string; role: UserRole | null } | null> {
  const token = extractSessionToken(req);
  if (!token) return null;
  const userId = sessionStore.get(token);
  if (!userId) return null;
  const user = await repository.getUser(userId);
  return user ? { id: user.id, name: user.name, role: user.role } : null;
}

async function getPlatformFeatures() {
  return (await repository.getPlatformSettings()).features;
}

function featureDisabled(res: Response, feature: string, message: string) {
  return res.status(403).json({ success: false, code: 'FEATURE_DISABLED', feature, error: message });
}

/**
 * Maintenance Mode: while ON, only SUPER_ADMIN sessions (and the endpoints needed to sign in,
 * read the public platform config and check health) can reach the API. Nothing is modified or
 * deleted; normal users simply receive a clean 503 that the client renders as a maintenance screen.
 */
const MAINTENANCE_ALLOWED_PATHS = ['/health', '/platform/config'];
app.use('/api', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const features = await getPlatformFeatures();
    if (!features.maintenanceModeEnabled) return next();
    if (MAINTENANCE_ALLOWED_PATHS.includes(req.path) || req.path.startsWith('/auth/')) return next();
    const sessionUser = await getSessionUser(req);
    if (sessionUser?.role === 'SUPER_ADMIN') return next();
    return res.status(503).json({
      success: false,
      code: 'MAINTENANCE',
      error: 'QFree is temporarily unavailable. We are performing scheduled maintenance. Please check back shortly.',
    });
  } catch {
    // Never block the application because the settings layer failed.
    return next();
  }
});

// ============================================================================
// Audit & Consent Helpers
// ============================================================================

async function logAudit(
  actor: { id: string; name: string; role: UserRole | 'SYSTEM' | null },
  action: string,
  targetType: 'TOKEN' | 'QUEUE' | 'PROVIDER' | 'USER' | 'APPLICATION' | 'CONSENT' | 'SETTINGS' | 'ANNOUNCEMENT',
  targetId: string,
  req?: Request,
  details?: Record<string, unknown>
) {
  const entry: SecurityAuditEntry = {
    id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    actorId: actor.id,
    actorName: actor.name,
    actorRole: actor.role,
    action,
    targetType,
    targetId,
    ipAddress: typeof req?.headers['x-forwarded-for'] === 'string'
      ? req.headers['x-forwarded-for'].split(',')[0]
      : req?.socket.remoteAddress,
    details,
  };
  await repository.addAuditLog(entry);
}

// ============================================================================
// 1. AUTHENTICATION & SESSION ENDPOINTS
// ============================================================================

/**
 * Google Sign-In & Registration
 * Issues authoritative session token & sets httpOnly cookie
 */
app.post('/api/auth/google', authRateLimiter, async (req: Request, res: Response) => {
  const { email, name, avatarUrl, requestedRole, providerId } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ success: false, error: 'Email is required for Google Sign-In.' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const now = new Date().toISOString();

  let user = await repository.getUserByEmail(normalizedEmail);

  if (!user) {
    // Register new user in persistent database
    const newUserId = `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    // Privileged roles are never self-assignable at registration time.
    // A new account may start only as PATIENT or PROVIDER. Existing SUPER_ADMIN
    // accounts keep their stored role through the normal session lookup.
    const role: UserRole = requestedRole === 'PROVIDER' ? 'PROVIDER' : 'PATIENT';

    // Feature Control: new-account registration switches (existing accounts are never affected)
    const features = await getPlatformFeatures();
    if (role === 'PATIENT' && !features.patientRegistrationEnabled) {
      return featureDisabled(res, 'patientRegistrationEnabled', 'New patient registration is currently unavailable. Please check back later.');
    }
    if (role === 'PROVIDER' && !features.providerRegistrationEnabled) {
      return featureDisabled(res, 'providerRegistrationEnabled', 'Provider registration is currently unavailable. Please check back later.');
    }

    user = {
      id: newUserId,
      name: sanitizeString(name) || normalizedEmail.split('@')[0],
      email: normalizedEmail,
      phone: '+91 98765 43210',
      role,
      createdAt: now,
    };
    await repository.saveUser(user);

    await logAudit(
      { id: user.id, name: user.name, role: user.role },
      'USER_REGISTERED',
      'USER',
      user.id,
      req,
      { requestedRole }
    );
  }

  // Issue session token
  const token = `qfree_sess_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  sessionStore.set(token, user.id);

  // Set secure httpOnly cookie
  res.setHeader(
    'Set-Cookie',
    `qfree_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`
  );

  const authUser = await getUserByIdHelper(user.id);

  await logAudit(
    { id: user.id, name: user.name, role: user.role },
    'USER_LOGIN',
    'USER',
    user.id,
    req
  );

  res.json({
    success: true,
    token,
    user: authUser,
  });
});

/**
 * Get current authenticated user profile
 */
app.get('/api/auth/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  res.json({ success: true, user: req.user });
});

/**
 * Assign or update user role
 */
app.post('/api/auth/assign-role', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { role, providerId } = req.body;

  if (!role || !['PATIENT', 'PROVIDER', 'SUPER_ADMIN'].includes(role)) {
    return res.status(400).json({ success: false, error: 'Invalid role. Role must be PATIENT, PROVIDER, or SUPER_ADMIN.' });
  }

  const currentUser = req.user!;

  // Strict Security: only an existing SUPER_ADMIN may assign SUPER_ADMIN.
  const isSuperAdminAttempt = role === 'SUPER_ADMIN';
  const isAuthorizedSuperAdmin = currentUser.role === 'SUPER_ADMIN';
  if (isSuperAdminAttempt && !isAuthorizedSuperAdmin) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: Only a Super Admin can assign the Super Admin role.',
    });
  }
  const userRecord = await repository.getUser(currentUser.id);
  if (!userRecord) {
    return res.status(404).json({ success: false, error: 'User record not found.' });
  }

  userRecord.role = role as UserRole;
  await repository.saveUser(userRecord);

  await logAudit(
    { id: currentUser.id, name: currentUser.name, role: currentUser.role },
    'ROLE_ASSIGNED',
    'USER',
    userRecord.id,
    req,
    { newRole: role, providerId }
  );

  const updatedAuthUser = await getUserByIdHelper(userRecord.id);
  res.json({ success: true, user: updatedAuthUser });
});

/**
 * Logout & invalidate session
 */
app.post('/api/auth/logout', (req: Request, res: Response) => {
  const token = extractSessionToken(req);
  if (token) {
    sessionStore.delete(token);
  }

  // Clear cookie
  res.setHeader('Set-Cookie', 'qfree_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// ============================================================================
// 2. DPDP ACT 2023 & PRIVACY ENDPOINTS (Data Export & Right to Erasure)
// ============================================================================

/**
 * DPDP Act 2023: Right to Data Portability (/api/me/export)
 */
app.get('/api/me/export', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const userRecord = await repository.getUser(user.id);
  const activeTokens = await repository.getActiveTokensForPatient(user.id);
  const allTokens = await repository.getAllTokens();
  const userHistoryTokens = allTokens.filter((t) => t.patientId === user.id);
  const notifications = await repository.getNotificationsForUser(user.id);
  const consents = await repository.getConsentsForUser(user.id);

  await logAudit(
    { id: user.id, name: user.name, role: user.role },
    'DATA_EXPORTED',
    'USER',
    user.id,
    req
  );

  res.json({
    success: true,
    exportedAt: new Date().toISOString(),
    regulation: 'Digital Personal Data Protection (DPDP) Act 2023',
    data: {
      profile: userRecord,
      activeTokens,
      historyTokens: userHistoryTokens,
      notifications,
      consents,
    },
  });
});

/**
 * DPDP Act 2023: Right to Erasure / Right to be Forgotten (DELETE /api/me)
 */
app.delete('/api/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;

  // 1. Cancel any active tokens held by patient
  const activeTokens = await repository.getActiveTokensForPatient(user.id);
  for (const t of activeTokens) {
    await serverQueueEngine.transitionToken(t.id, 'CANCEL', 'User requested account erasure under DPDP Act 2023');
  }

  // 2. Anonymize user record
  const userRecord = await repository.getUser(user.id);
  if (userRecord) {
    userRecord.name = 'Anonymized User';
    userRecord.email = `deleted_${user.id}@qfree.invalid`;
    userRecord.phone = '+91 00000 00000';
    await repository.saveUser(userRecord);
  }

  // 3. Log security audit
  await logAudit(
    { id: user.id, name: user.name, role: user.role },
    'DATA_ERASED',
    'USER',
    user.id,
    req
  );

  // 4. Invalidate session
  if (req.sessionToken) {
    sessionStore.delete(req.sessionToken);
  }
  res.setHeader('Set-Cookie', 'qfree_session=; HttpOnly; Path=/; Max-Age=0');

  res.json({
    success: true,
    message: 'Your personal data has been erased in accordance with the DPDP Act 2023.',
  });
});

/**
 * DPDP Act 2023: Log Consent
 */
app.post('/api/me/consent', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { consentType, granted } = req.body;
  const user = req.user!;

  const consent: PatientConsentEntry = {
    id: `cst_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    userId: user.id,
    consentType: consentType || 'TERMS_AND_PRIVACY',
    granted: Boolean(granted),
    timestamp: new Date().toISOString(),
    ipAddress: typeof req.headers['x-forwarded-for'] === 'string'
      ? req.headers['x-forwarded-for'].split(',')[0]
      : req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
  };

  await repository.addConsent(consent);

  await logAudit(
    { id: user.id, name: user.name, role: user.role },
    'CONSENT_LOGGED',
    'CONSENT',
    consent.id,
    req,
    { consentType, granted }
  );

  res.json({ success: true, consent });
});

/**
 * Automated 90-Day PII Anonymisation Job
 */
async function run90DayPiiAnonymizationJob() {
  const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
  const tokens = await repository.getAllTokens();
  let anonymizedCount = 0;

  for (const t of tokens) {
    const isCompleted = ['COMPLETED', 'CANCELLED', 'NO_SHOW'].includes(t.status);
    const tokenTime = new Date(t.bookedAt).getTime();

    if (isCompleted && tokenTime < ninetyDaysAgo && t.patientName !== 'Anonymized Patient') {
      t.patientName = 'Anonymized Patient';
      t.patientPhone = '+91 00000 00000';
      await repository.saveToken(t);
      anonymizedCount++;
    }
  }

  if (anonymizedCount > 0) {
    await logAudit(
      { id: 'system', name: 'Automated Retention Worker', role: 'SYSTEM' },
      'PII_ANONYMIZED_90_DAYS',
      'TOKEN',
      'batch',
      undefined,
      { anonymizedCount }
    );
  }
}

// Run PII cleanup on startup and once every 24 hours
run90DayPiiAnonymizationJob().catch((err) => console.error('[Cleanup Job Error]:', err));
setInterval(run90DayPiiAnonymizationJob, 24 * 60 * 60 * 1000);

// ==========================================
// 3. ROLE-PROTECTED DASHBOARD DATA ENDPOINTS
// ==========================================

// Patient Dashboard Data (Requires PATIENT or ADMIN)
app.get('/api/patient/dashboard-data', requireRole(['PATIENT', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const today = serverQueueEngine.getTodayDate();

  const providers = await repository.getAllProviders();
  const allQueues = await repository.getAllQueues();

  // Find patient's tokens
  const allTokens = await repository.getAllTokens();
  const userTokens = allTokens.filter(
    (t) => t.patientId === user.id || t.patientName.toLowerCase() === user.name.toLowerCase()
  );

  const activeTokens = userTokens.filter((t) => ['WAITING', 'CALLED', 'IN_PROGRESS'].includes(t.status));
  const historyTokens = userTokens.filter((t) => ['COMPLETED', 'CANCELLED', 'NO_SHOW'].includes(t.status));

  res.json({
    success: true,
    user: { id: user.id, name: user.name, role: user.role },
    providers,
    queues: allQueues,
    myActiveTokens: activeTokens,
    tokenHistory: historyTokens,
    today,
  });
});

// Provider Dashboard Data (Requires PROVIDER or ADMIN + Strict Ownership)
app.get('/api/provider/dashboard-data', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const providers = await repository.getAllProviders();
  const today = serverQueueEngine.getTodayDate();

  // Check target providerId: if requested via query or derived from user
  const targetProviderId = (req.query.providerId as string) || user.providerId || providers[0]?.id || 'prov_carewell';

  // Strict ownership check for PROVIDER role
  if (!verifyProviderOwnership(user, targetProviderId)) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: You are not authorized to view another healthcare provider’s clinic dashboard.',
    });
  }

  const provider = (await repository.getProvider(targetProviderId)) || providers[0];
  const queue = await serverQueueEngine.getOrCreateDailyQueue(provider.id, today);
  const snapshot = await serverQueueEngine.getQueueSnapshot(queue.id);
  const tokens = await repository.getTokensForQueue(queue.id);

  res.json({
    success: true,
    user: { id: user.id, name: user.name, role: user.role, providerId: provider.id },
    provider,
    queue,
    deskSnapshot: snapshot,
    tokens,
  });
});

// Admin Dashboard Data (Strictly requires ADMIN)
app.get('/api/admin/dashboard-data', requireRole(['SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const providers = await repository.getAllProviders();
  const queues = await repository.getAllQueues();
  const tokens = await repository.getAllTokens();
  const applications = await repository.getAllApplications();
  const auditLogs = await repository.getAuditLogs(50);
  const users = await repository.getAllUsers();

  const totalDailyTokens = queues.reduce((acc, q) => acc + q.totalTokens, 0);
  const totalWaiting = tokens.filter((t) => t.status === 'WAITING').length;

  res.json({
    success: true,
    user: req.user,
    allProviders: providers,
    allQueues: queues,
    allUsers: users,
    applications,
    auditTrail: auditLogs,
    systemHealth: {
      status: 'HEALTHY',
      activeUsersCount: users.length,
      activeSessionsCount: sessionStore.size,
      eventBusSubscribers: serverRealtimeBus.getSubscriberCount(),
      totalDailyTokensIssued: totalDailyTokens,
      totalCurrentlyWaiting: totalWaiting,
    },
  });
});

// ============================================================================
// 4. QUEUE & TOKEN BUSINESS ENDPOINTS (Authoritative & Mutex-Protected)
// ============================================================================

/**
 * Public/Patient: Book Token
 */
app.post('/api/tokens/book', bookingRateLimiter, async (req: Request, res: Response) => {
  // Feature Control: Remote Token OFF blocks patient (remote) booking only. Provider/admin issued
  // in-clinic tokens use this same endpoint and must keep working.
  if (!(await getPlatformFeatures()).remoteTokenEnabled) {
    const bookingUser = await getSessionUser(req);
    const isStaff = bookingUser?.role === 'PROVIDER' || bookingUser?.role === 'SUPER_ADMIN' || bookingUser?.role === 'SUPER_ADMIN';
    if (!isStaff) {
      return featureDisabled(res, 'remoteTokenEnabled', 'Remote token booking is currently unavailable. Please check back later.');
    }
  }

  const { providerId, name, mobileNumber, age, gender, priority, notes } = req.body;

  if (!providerId || !name || !mobileNumber) {
    return res.status(400).json({
      success: false,
      error: 'Provider ID, Patient Name, and Mobile Number are required.',
    });
  }

  const phoneValidation = validateIndianMobileNumber(mobileNumber);
  if (!phoneValidation.valid) {
    return res.status(400).json({ success: false, error: phoneValidation.error });
  }

  // Derive patientId safely: authenticated session takes priority
  let patientId = `pat_${Date.now()}`;
  const token = extractSessionToken(req);
  if (token && sessionStore.has(token)) {
    patientId = sessionStore.get(token)!;
  }

  const result = await serverQueueEngine.bookToken({
    providerId: sanitizeString(providerId),
    patientId,
    name: sanitizeString(name),
    mobileNumber: phoneValidation.normalized!,
    age: age ? Number(age) : null,
    gender: gender || 'OTHER',
    priority: priority || 'NORMAL',
    notes: sanitizeString(notes),
  });

  if (!result.success) {
    return res.status(400).json(result);
  }

  // Audit log booking
  await logAudit(
    { id: patientId, name, role: 'PATIENT' },
    'TOKEN_BOOKED',
    'TOKEN',
    result.token!.id,
    req,
    { tokenNumber: result.token!.tokenNumber, queueId: result.queue!.id }
  );

  res.status(201).json(result);
});

/**
 * Concurrency Test Endpoint (Admin / Demo Mode)
 */
app.post('/api/tokens/simulate-concurrency', async (req: Request, res: Response) => {
  const { providerId, simultaneousCount } = req.body;
  const count = Math.min(50, Math.max(2, Number(simultaneousCount) || 20));
  const targetProviderId = providerId || 'prov_carewell';

  const report = await serverQueueEngine.simulateConcurrentBookings(targetProviderId, count);
  res.json({ success: true, report });
});

/**
 * Live Patient Tracking View (PII Redacted)
 */
app.get('/api/tokens/:id/live-tracking', async (req: Request, res: Response) => {
  const trackingState = await serverQueueEngine.getPatientLiveTracking(req.params.id);
  if (!trackingState) {
    return res.status(404).json({ success: false, error: 'Token tracking record not found' });
  }

  // Determine requesting user if authenticated
  let requestingUser: AuthUser | undefined;
  const token = extractSessionToken(req);
  if (token && sessionStore.has(token)) {
    requestingUser = (await getUserByIdHelper(sessionStore.get(token)!)) || undefined;
  }

  // Redact PII in accordance with DPDP rules
  const redactedToken = redactTokenPII(trackingState.token, requestingUser);

  res.json({
    success: true,
    data: {
      ...trackingState,
      token: redactedToken,
    },
  });
});

/**
 * Start Live Queue (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/start-live', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const result = await serverQueueEngine.startLiveQueue(req.params.id);
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    'QUEUE_STARTED_LIVE',
    'QUEUE',
    queue.id,
    req
  );

  res.json(result);
});

/**
 * Call Next Patient (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/call-next', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const result = await serverQueueEngine.callNext(req.params.id);
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    'TOKEN_CALLED_NEXT',
    'QUEUE',
    queue.id,
    req,
    { currentToken: result.queue?.currentToken }
  );

  res.json(result);
});

/**
 * Set Doctor Delay (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/delay', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const { delayMinutes, reason } = req.body;

  // Feature Control: block NEW delays when OFF. Clearing an active delay (0 minutes) stays allowed
  // so a queue can never get stuck in a delayed state.
  if (Number(delayMinutes) > 0 && !(await getPlatformFeatures()).doctorDelayEnabled) {
    return featureDisabled(res, 'doctorDelayEnabled', 'Doctor Delay is currently unavailable.');
  }

  const result = await serverQueueEngine.setDoctorDelay(req.params.id, Number(delayMinutes) || 0, sanitizeString(reason));
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    'DOCTOR_DELAY_ANNOUNCED',
    'QUEUE',
    queue.id,
    req,
    { delayMinutes, reason }
  );

  res.json(result);
});

/**
 * Pause / Resume Queue (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/pause', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const { pause, reason } = req.body;
  const result = await serverQueueEngine.togglePauseQueue(req.params.id, Boolean(pause), sanitizeString(reason));
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    pause ? 'QUEUE_PAUSED' : 'QUEUE_RESUMED',
    'QUEUE',
    queue.id,
    req,
    { reason }
  );

  res.json(result);
});

/**
 * Token Transitions: START, COMPLETE, NO_SHOW, CANCEL (Requires Provider Ownership or Admin)
 */
app.post('/api/tokens/:id/transition', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const token = await repository.getToken(req.params.id);
  if (!token) {
    return res.status(404).json({ success: false, error: 'Token not found' });
  }

  if (!verifyProviderOwnership(req.user!, token.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic token.' });
  }

  const { action, reason } = req.body;
  const result = await serverQueueEngine.transitionToken(token.id, action, sanitizeString(reason));
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    `TOKEN_${action}`,
    'TOKEN',
    token.id,
    req,
    { reason }
  );

  res.json(result);
});

/**
 * Update Daily Token Limit (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/token-limit', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const { limit } = req.body;
  const result = await serverQueueEngine.setDailyTokenLimit(queue.id, Number(limit));
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    'TOKEN_LIMIT_UPDATED',
    'QUEUE',
    queue.id,
    req,
    { newLimit: limit }
  );

  res.json(result);
});

/**
 * Close Clinic Queue (Requires Provider Ownership or Admin)
 */
app.post('/api/queues/:id/close', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const queue = await repository.getQueue(req.params.id);
  if (!queue) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  if (!verifyProviderOwnership(req.user!, queue.providerId)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Not your clinic queue.' });
  }

  const { force } = req.body;
  const result = await serverQueueEngine.closeClinic(queue.id, { force: Boolean(force) });
  if (!result.success) {
    return res.status(400).json(result);
  }

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    'QUEUE_CLOSED',
    'QUEUE',
    queue.id,
    req,
    { force }
  );

  res.json(result);
});

/**
 * Queue Snapshot (Redacted for unauthenticated/other patients)
 */
app.get('/api/queues/:id/snapshot', async (req: Request, res: Response) => {
  const snapshot = await serverQueueEngine.getQueueSnapshot(req.params.id);
  if (!snapshot) {
    return res.status(404).json({ success: false, error: 'Queue not found' });
  }

  let requestingUser: AuthUser | undefined;
  const token = extractSessionToken(req);
  if (token && sessionStore.has(token)) {
    requestingUser = (await getUserByIdHelper(sessionStore.get(token)!)) || undefined;
  }

  // Redact waiting tokens
  const redactedWaitingTokens = snapshot.waitingTokens.map((t) => redactTokenPII(t, requestingUser));
  const redactedCurrentToken = snapshot.currentToken ? redactTokenPII(snapshot.currentToken, requestingUser) : null;

  res.json({
    success: true,
    data: {
      ...snapshot,
      currentToken: redactedCurrentToken,
      waitingTokens: redactedWaitingTokens,
    },
  });
});

/**
 * Providers & Queues Listings
 */
app.get('/api/providers', async (_req: Request, res: Response) => {
  const providers = await repository.getAllProviders();
  res.json({ success: true, data: providers });
});

app.get('/api/providers/:id', async (req: Request, res: Response) => {
  const provider = await repository.getProvider(req.params.id);
  if (!provider) {
    return res.status(404).json({ success: false, error: 'Provider not found' });
  }
  res.json({ success: true, data: provider });
});

/**
 * Validates a provider branding image value: a JPG/PNG/WebP data URL or an https URL.
 * Returns the cleaned value, null when empty, or undefined when invalid.
 */
const MAX_PROVIDER_IMAGE_LENGTH = 3 * 1024 * 1024;
function sanitizeProviderImageUrl(value: unknown): string | null | undefined {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return undefined;
  const v = value.trim();
  if (!v) return null;
  if (v.length > MAX_PROVIDER_IMAGE_LENGTH) return undefined;
  if (/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(v)) return v;
  if (/^https:\/\/\S+$/i.test(v)) return v;
  return undefined;
}

/**
 * Update / Replace / Remove Provider Profile Image
 * Allowed by owning Provider or Admin
 */
app.post('/api/providers/:id/image', requireRole(['PROVIDER', 'SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const provider = await repository.getProvider(req.params.id);
  if (!provider) {
    return res.status(404).json({ success: false, error: 'Provider not found' });
  }

  if (!verifyProviderOwnership(req.user!, provider.id)) {
    return res.status(403).json({ success: false, error: 'Forbidden: You cannot modify this provider profile.' });
  }

  const cleanedImage = sanitizeProviderImageUrl(req.body.providerImageUrl);
  if (cleanedImage === undefined) {
    return res.status(400).json({ success: false, error: 'Invalid image. Use a JPG, PNG or WebP image under the size limit.' });
  }
  if (cleanedImage) {
    provider.providerImageUrl = cleanedImage;
  } else {
    delete provider.providerImageUrl;
  }

  await repository.saveProvider(provider);

  await logAudit(
    { id: req.user!.id, name: req.user!.name, role: req.user!.role },
    provider.providerImageUrl ? 'PROVIDER_IMAGE_UPDATED' : 'PROVIDER_IMAGE_REMOVED',
    'PROVIDER',
    provider.id,
    req
  );

  res.json({ success: true, provider });
});

app.get('/api/queues', async (_req: Request, res: Response) => {
  const queues = await repository.getAllQueues();
  res.json({ success: true, data: queues });
});

// ============================================================================
// 5. PROVIDER APPLICATION & APPROVAL FLOW (Task 5)
// ============================================================================

/**
 * Provisions a provider (record + today's queue + applicant link + in-app notification + audit)
 * from an application. Shared by manual Super Admin approval and, when
 * "Provider Approval Required" is OFF, automatic activation of a new application.
 */
async function provisionProviderFromApplication(
  appRecord: ProviderApplicationRecord,
  actor: { id: string; name: string; role: UserRole | 'SYSTEM' | null },
  req: Request,
  now: string,
  auditExtra: Record<string, unknown> = {}
): Promise<ProviderRecord> {
  const providerId = `prov_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
  const newProvider: ProviderRecord = {
    id: providerId,
    providerType: appRecord.providerType,
    organizationName: appRecord.organizationName,
    doctorName: appRecord.doctorName,
    specialist: appRecord.specialist,
    experience: appRecord.experience,
    phone: appRecord.phone,
    email: appRecord.email,
    address: appRecord.address,
    latitude: 12.9716,
    longitude: 77.5946,
    openingTime: '09:00',
    closingTime: '19:00',
    tokenLimit: 40,
    averageConsultationTime: 10,
    status: 'ACTIVE',
    verificationStatus: 'VERIFIED',
    createdAt: now,
    providerImageUrl: appRecord.providerImageUrl,
  };
  await repository.saveProvider(newProvider);

  // Create today's queue for this provider
  const today = serverQueueEngine.getTodayDate();
  const newQueue = await serverQueueEngine.getOrCreateDailyQueue(newProvider.id, today);

  // Link applicant user to provider
  const applicant = await repository.getUser(appRecord.applicantUserId);
  if (applicant) {
    applicant.role = 'PROVIDER';
    await repository.saveUser(applicant);
  }

  // Send in-app notification to applicant
  await repository.saveNotification({
    id: `notif_${Date.now()}_approved`,
    userId: appRecord.applicantUserId,
    providerId: newProvider.id,
    queueId: newQueue.id,
    type: 'APPLICATION_UPDATE',
    title: 'Healthcare Service Approved!',
    message: `Congratulations! ${appRecord.organizationName} has been approved. Your provider desk is now ready for patients.`,
    read: false,
    createdAt: now,
  });

  await logAudit(
    actor,
    'PROVIDER_APPROVED_AND_PROVISIONED',
    'PROVIDER',
    newProvider.id,
    req,
    { applicationId: appRecord.id, providerId: newProvider.id, ...auditExtra }
  );

  return newProvider;
}

/**
 * Submit Online Healthcare Application
 */
app.post('/api/provider-applications', async (req: Request, res: Response) => {
  const platformFeatures = await getPlatformFeatures();
  if (!platformFeatures.providerRegistrationEnabled) {
    return featureDisabled(res, 'providerRegistrationEnabled', 'Provider registration is currently unavailable. Please check back later.');
  }

  const {
    organizationName,
    doctorName,
    providerType,
    specialist,
    experience,
    phone,
    email,
    address,
    openingTime,
    closingTime,
    averageConsultationTime,
    tokenLimit,
    documents,
  } = req.body;

  if (!organizationName || !phone || !providerType) {
    return res.status(400).json({
      success: false,
      error: 'Organization name, phone number, and provider type are required.',
    });
  }

  // Derive applicant user from session if available
  let applicantUserId = 'usr_guest_applicant';
  const token = extractSessionToken(req);
  if (token && sessionStore.has(token)) {
    applicantUserId = sessionStore.get(token)!;
  }

  const appId = `app_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
  const now = new Date().toISOString();

  const application: ProviderApplicationRecord = {
    id: appId,
    applicantUserId,
    providerType: providerType || 'CLINIC',
    organizationName: sanitizeString(organizationName),
    doctorName: sanitizeString(doctorName) || 'Chief Medical Officer',
    specialist: sanitizeString(specialist) || 'General Medicine',
    experience: sanitizeString(experience) || '5+ years',
    phone: sanitizeString(phone),
    email: sanitizeString(email) || '',
    address: sanitizeString(address) || '',
    location: sanitizeString(req.body.location) || 'Indiranagar, Bangalore',
    openingTime: sanitizeString(openingTime) || '09:00',
    closingTime: sanitizeString(closingTime) || '19:00',
    averageConsultationTime: Number(averageConsultationTime) || 10,
    tokenLimit: Number(tokenLimit) || 40,
    documents: documents || [],
    status: 'PENDING',
    submittedAt: now,
    reviewedAt: null,
    verificationCalls: [],
    additionalInfoRequests: [],
    providerImageUrl: sanitizeProviderImageUrl(req.body.providerImageUrl) || undefined,
  };

  await repository.saveApplication(application);

  await logAudit(
    { id: applicantUserId, name: organizationName, role: 'PROVIDER' },
    'APPLICATION_SUBMITTED',
    'APPLICATION',
    application.id,
    req
  );

  // Feature Control: "Provider Approval Required" OFF -> activate new applications automatically.
  // Only for signed-in applicants (never anonymous submissions), and only this new application:
  // existing pending applications are never touched.
  if (!platformFeatures.providerApprovalRequired && applicantUserId !== 'usr_guest_applicant') {
    application.status = 'APPROVED';
    application.reviewedAt = now;
    application.reviewedBy = 'QFree Auto-Activation';
    application.adminNotes = 'Activated automatically because provider approval is not required.';
    await repository.saveApplication(application);
    await provisionProviderFromApplication(
      application,
      { id: 'system', name: 'QFree Auto-Activation', role: 'SYSTEM' },
      req,
      now,
      { autoActivated: true }
    );
  }

  res.status(201).json({ success: true, application });
});

/**
 * Get Provider Applications (Admin or applicant)
 */
app.get('/api/provider-applications', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const allApps = await repository.getAllApplications();

  if (user.role === 'SUPER_ADMIN') {
    return res.json({ success: true, applications: allApps });
  }

  // Non-admins only see applications they personally submitted
  const myApps = allApps.filter((a) => a.applicantUserId === user.id);
  res.json({ success: true, applications: myApps });
});

/**
 * Review Provider Application (Strictly ADMIN)
 * On APPROVAL:
 * - Creates ProviderRecord in repository
 * - Creates today's queue for new provider
 * - Promotes applicant user to PROVIDER role and links providerId
 */
app.post('/api/provider-applications/:id/review', requireRole(['SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const { status, adminNotes, rejectionReason } = req.body;
  const appRecord = await repository.getApplication(req.params.id);

  if (!appRecord) {
    return res.status(404).json({ success: false, error: 'Application not found' });
  }

  const now = new Date().toISOString();
  appRecord.status = status;
  appRecord.reviewedAt = now;
  appRecord.reviewedBy = req.user!.name;
  if (adminNotes) appRecord.adminNotes = sanitizeString(adminNotes);
  if (rejectionReason) appRecord.rejectionReason = sanitizeString(rejectionReason);

  await repository.saveApplication(appRecord);

  // If APPROVED: Provision provider, create queue, and link applicant user!
  if (status === 'APPROVED') {
    await provisionProviderFromApplication(
      appRecord,
      { id: req.user!.id, name: req.user!.name, role: req.user!.role },
      req,
      now
    );
  } else {
    await logAudit(
      { id: req.user!.id, name: req.user!.name, role: req.user!.role },
      `APPLICATION_${status}`,
      'APPLICATION',
      appRecord.id,
      req,
      { adminNotes, rejectionReason }
    );
  }

  res.json({ success: true, application: appRecord });
});

/**
 * Record Verification Call (Strictly ADMIN)
 */
app.post('/api/provider-applications/:id/call', requireRole(['SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const { outcome, notes } = req.body;
  const appRecord = await repository.getApplication(req.params.id);

  if (!appRecord) {
    return res.status(404).json({ success: false, error: 'Application not found' });
  }

  if (!appRecord.verificationCalls) appRecord.verificationCalls = [];

  appRecord.verificationCalls.push({
    id: `call_${Date.now()}`,
    calledAt: new Date().toISOString(),
    timestamp: new Date().toISOString(),
    adminName: req.user!.name,
    outcome: outcome || 'CONNECTED',
    notes: sanitizeString(notes) || 'Phone verification completed.',
  });

  await repository.saveApplication(appRecord);
  res.json({ success: true, application: appRecord });
});

/**
 * Request Additional Information (Strictly ADMIN)
 */
app.post('/api/provider-applications/:id/request-info', requireRole(['SUPER_ADMIN']), async (req: AuthenticatedRequest, res: Response) => {
  const { query } = req.body;
  if (!query) {
    return res.status(400).json({ success: false, error: 'Query text is required.' });
  }

  const appRecord = await repository.getApplication(req.params.id);
  if (!appRecord) {
    return res.status(404).json({ success: false, error: 'Application not found' });
  }

  appRecord.status = 'ADDITIONAL_INFO_REQUESTED';
  if (!appRecord.additionalInfoRequests) appRecord.additionalInfoRequests = [];

  appRecord.additionalInfoRequests.push({
    id: `req_${Date.now()}`,
    requestedAt: new Date().toISOString(),
    adminName: req.user!.name,
    requestedBy: req.user!.name,
    query: sanitizeString(query),
  });

  await repository.saveApplication(appRecord);

  // Notify applicant
  await repository.saveNotification({
    id: `notif_${Date.now()}_info`,
    userId: appRecord.applicantUserId,
    providerId: 'prov_qfree_ops',
    type: 'APPLICATION_UPDATE',
    title: 'Additional Information Requested',
    message: `Admin team requested: "${query}". Please review and respond in your application status.`,
    read: false,
    createdAt: new Date().toISOString(),
  });

  res.json({ success: true, application: appRecord });
});

/**
 * Respond to Additional Information
 */
app.post('/api/provider-applications/:id/respond-info', async (req: Request, res: Response) => {
  const { response } = req.body;
  if (!response) {
    return res.status(400).json({ success: false, error: 'Response text is required.' });
  }

  const appRecord = await repository.getApplication(req.params.id);
  if (!appRecord) {
    return res.status(404).json({ success: false, error: 'Application not found' });
  }

  appRecord.status = 'UNDER_REVIEW';
  if (appRecord.additionalInfoRequests && appRecord.additionalInfoRequests.length > 0) {
    const last = appRecord.additionalInfoRequests[appRecord.additionalInfoRequests.length - 1];
    last.respondedAt = new Date().toISOString();
    last.response = sanitizeString(response);
  }

  await repository.saveApplication(appRecord);
  res.json({ success: true, application: appRecord });
});

// ============================================================================
// 6. NOTIFICATIONS ENDPOINTS
// ============================================================================

app.get('/api/notifications', async (req: Request, res: Response) => {
  let userId = (req.query.userId as string) || 'usr_rahul';
  const token = extractSessionToken(req);
  if (token && sessionStore.has(token)) {
    userId = sessionStore.get(token)!;
  }

  const notifications = await repository.getNotificationsForUser(userId);
  res.json({ success: true, notifications });
});

app.post('/api/notifications/:id/read', async (req: Request, res: Response) => {
  const ok = await repository.markNotificationRead(req.params.id);
  res.json({ success: ok });
});

// ============================================================================
// 7. REAL-TIME SERVER-SENT EVENTS (SSE) STREAM
// ============================================================================

app.get('/api/realtime/stream', (req: Request, res: Response) => {
  const queueId = req.query.queueId as string;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  // Send initial connection event
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);

  // Heartbeat comment to keep persistent connection open through proxies
  const heartbeat = setInterval(() => {
    res.write(': ping\n\n');
  }, 20000);

  const unsubscribe = queueId
    ? serverRealtimeBus.subscribeToQueue(queueId, (event) => {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      })
    : serverRealtimeBus.subscribeGlobal((event) => {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      });

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

// ============================================================================
// 8. DATABASE SCHEMA & STATS (Only Admin or Demo Mode)
// ============================================================================

app.get('/api/db/stats', async (_req: Request, res: Response) => {
  const users = await repository.getAllUsers();
  const providers = await repository.getAllProviders();
  const queues = await repository.getAllQueues();
  const tokens = await repository.getAllTokens();
  const applications = await repository.getAllApplications();

  res.json({
    success: true,
    tables: {
      users: users.length,
      providers: providers.length,
      queues: queues.length,
      tokens: tokens.length,
      providerApplications: applications.length,
    },
  });
});

app.get('/api/db/table/:name', async (req: Request, res: Response) => {
  const tableName = req.params.name;
  let rows: unknown[] = [];

  switch (tableName) {
    case 'users':
      rows = await repository.getAllUsers();
      break;
    case 'providers':
      rows = await repository.getAllProviders();
      break;
    case 'queues':
      rows = await repository.getAllQueues();
      break;
    case 'tokens':
      rows = await repository.getAllTokens();
      break;
    case 'providerApplications':
    case 'provider_applications':
      rows = await repository.getAllApplications();
      break;
    default:
      return res.status(404).json({ success: false, error: `Table '${tableName}' not found` });
  }

  res.json({ success: true, table: tableName, count: rows.length, rows });
});

// Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'QFree Server-Authoritative Engine', timestamp: new Date().toISOString() });
});

// ============================================================================
// 9. VITE MIDDLEWARE / STATIC ASSETS SERVING
// ============================================================================

// ============================================================================
// PLATFORM CONTROL CENTER (Promotions, Announcements, Feature Control, Branding, Support)
// Modular layer registered on top of the existing API. See server/platform/platformRoutes.ts
// ============================================================================
registerPlatformRoutes({
  app,
  requireSuperAdmin,
  getSessionUser,
  logAudit,
  sanitizeText: (value: unknown) => sanitizeString(value as string),
  sanitizeImage: sanitizeProviderImageUrl,
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[QFree Server] Authoritative Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[QFree Server] Failed to start:', err);
});
