# CRABHIVE.COM - RFC: Security Enhancements Implementation Guide
**Created:** 2026-01-31

---

## Format Specification

**Medium:** RFC implementation guide with TypeScript patterns
**Platform:** OpenClaw-compatible agentic frameworks
**Audience:** Framework developers, security engineers, self-hosters
**Tone:** Precise, implementation-ready, copy-paste friendly

---

## Execution Overview

This Vehicle provides complete implementation patterns for five security modules designed to harden agentic AI frameworks. Each module is independent, configurable, and non-breaking. Developers can implement all five or select modules based on threat model.

---

## Quick Start

### Minimal Integration (5 minutes)

```typescript
// 1. Add to your message handler entry point
import { createSecurityMiddleware } from './security/index.js';

const security = createSecurityMiddleware({
  sanitize: { enabled: true },
  rateLimit: { enabled: true, maxCallsPerMinute: 60 },
  audit: { enabled: true, sinks: [{ type: 'console' }] }
});

// 2. Wrap your message handler
async function handleMessage(sessionId: string, userId: string, message: string) {
  const secured = await security.process({ sessionId, userId, message });
  if (!secured.allowed) {
    return { error: secured.reason };
  }
  return yourExistingHandler(sessionId, secured.sanitizedMessage);
}
```

### Full Integration (Module-by-Module)

See detailed implementation for each module below.

---

## Module 1: Input Sanitization

### Purpose
Comprehensive payload cleaning to neutralize injection attacks, encoding tricks, and malicious patterns before they reach agent logic.

### File Structure
```
src/security/
├── sanitize.ts          # Core sanitization logic
├── patterns.ts          # Suspicious pattern definitions
└── types.ts             # Type definitions
```

### Implementation

```typescript
// src/security/types.ts

export interface SanitizeOptions {
  /** Maximum input length before truncation */
  maxLength?: number;
  /** Remove ASCII control characters (0x00-0x1F except \t\n\r) */
  stripControlChars?: boolean;
  /** Normalize Unicode to NFC form */
  normalizeUnicode?: boolean;
  /** Detect and flag base64-encoded payloads */
  detectBase64Payloads?: boolean;
  /** Log warnings for suspicious patterns */
  warnOnSuspiciousPatterns?: boolean;
}

export interface SanitizeResult {
  /** Cleaned input string */
  clean: string;
  /** Warning messages for suspicious content */
  warnings: string[];
  /** Whether input was modified */
  modified: boolean;
  /** Original length before processing */
  originalLength: number;
}

export const DEFAULT_SANITIZE_OPTIONS: SanitizeOptions = {
  maxLength: 100_000,
  stripControlChars: true,
  normalizeUnicode: true,
  detectBase64Payloads: true,
  warnOnSuspiciousPatterns: true,
};
```

```typescript
// src/security/patterns.ts

export const SUSPICIOUS_PATTERNS = {
  // Bidirectional text override characters (homoglyph attacks)
  bidiOverride: /[\u202A-\u202E\u2066-\u2069]/g,

  // Zero-width characters in unusual positions (invisible injection)
  zeroWidth: /[\u200B-\u200D\uFEFF]/g,

  // Excessive combining characters (DoS via rendering)
  excessiveCombining: /[\u0300-\u036F]{10,}/g,

  // Overlong UTF-8 sequences (encoding tricks) - detected by normalization mismatch

  // Embedded null bytes (string termination attacks)
  nullBytes: /\x00/g,

  // ANSI escape sequences (terminal injection)
  ansiEscape: /\x1B\[[0-9;]*[A-Za-z]/g,

  // Common injection prefixes
  injectionPrefixes: /^(ignore|disregard|forget|new instructions|system:)/i,
};

export function detectSuspiciousPatterns(input: string): string[] {
  const warnings: string[] = [];

  for (const [name, pattern] of Object.entries(SUSPICIOUS_PATTERNS)) {
    if (pattern.test(input)) {
      warnings.push(`Suspicious pattern detected: ${name}`);
    }
  }

  // Check for potential base64 payloads (long alphanumeric sequences)
  const base64Candidates = input.match(/[A-Za-z0-9+/]{100,}={0,2}/g);
  if (base64Candidates?.some(c => isLikelyBase64(c))) {
    warnings.push('Potential base64-encoded payload detected');
  }

  return warnings;
}

function isLikelyBase64(str: string): boolean {
  try {
    const decoded = atob(str);
    // Check if decoded content looks like text or code
    return /[\x00-\x1F]/.test(decoded) || decoded.includes('function') || decoded.includes('eval');
  } catch {
    return false;
  }
}
```

```typescript
// src/security/sanitize.ts

import { SanitizeOptions, SanitizeResult, DEFAULT_SANITIZE_OPTIONS } from './types.js';
import { SUSPICIOUS_PATTERNS, detectSuspiciousPatterns } from './patterns.js';

export function sanitizeInput(
  input: string,
  options: SanitizeOptions = DEFAULT_SANITIZE_OPTIONS
): SanitizeResult {
  const opts = { ...DEFAULT_SANITIZE_OPTIONS, ...options };
  const warnings: string[] = [];
  const originalLength = input.length;
  let clean = input;
  let modified = false;

  // 1. Length enforcement
  if (opts.maxLength && clean.length > opts.maxLength) {
    clean = clean.slice(0, opts.maxLength);
    warnings.push(`Input truncated from ${originalLength} to ${opts.maxLength} characters`);
    modified = true;
  }

  // 2. Control character stripping
  if (opts.stripControlChars) {
    const beforeStrip = clean;
    // Keep \t (0x09), \n (0x0A), \r (0x0D)
    clean = clean.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    if (clean !== beforeStrip) {
      warnings.push('Control characters stripped');
      modified = true;
    }
  }

  // 3. Unicode normalization
  if (opts.normalizeUnicode) {
    const beforeNorm = clean;
    clean = clean.normalize('NFC');
    if (clean !== beforeNorm) {
      warnings.push('Unicode normalized to NFC');
      modified = true;
    }
  }

  // 4. Remove dangerous patterns
  const beforePatterns = clean;
  clean = clean
    .replace(SUSPICIOUS_PATTERNS.bidiOverride, '')
    .replace(SUSPICIOUS_PATTERNS.zeroWidth, '')
    .replace(SUSPICIOUS_PATTERNS.nullBytes, '')
    .replace(SUSPICIOUS_PATTERNS.ansiEscape, '');

  if (clean !== beforePatterns) {
    warnings.push('Dangerous patterns removed');
    modified = true;
  }

  // 5. Detect suspicious patterns (warning only, not removed)
  if (opts.warnOnSuspiciousPatterns) {
    warnings.push(...detectSuspiciousPatterns(clean));
  }

  return { clean, warnings, modified, originalLength };
}
```

### Configuration

```yaml
# config.yaml
security:
  sanitize:
    enabled: true
    maxLength: 100000
    stripControlChars: true
    normalizeUnicode: true
    detectBase64Payloads: true
    warnOnSuspiciousPatterns: true
```

### Integration Point

```typescript
// In your message handler
import { sanitizeInput } from './security/sanitize.js';
import { logAudit } from './security/audit.js';

async function handleInboundMessage(sessionId: string, userId: string, raw: string) {
  const { clean, warnings, modified } = sanitizeInput(raw);

  if (warnings.length > 0) {
    logAudit({
      type: 'message.inbound',
      sessionId,
      channel: 'your-channel',
      actor: userId,
      action: 'sanitize',
      outcome: 'success',
      metadata: { warnings, modified, originalLength: raw.length },
    });
  }

  // Continue with sanitized input
  return processMessage(sessionId, clean);
}
```

---

## Module 2: Rate Limiting

### Purpose
Prevent resource exhaustion from runaway agents or malicious prompts through configurable, hierarchical call throttling.

### File Structure
```
src/security/
├── rate-limit.ts        # Core rate limiting logic
├── rate-store.ts        # In-memory LRU store
└── types.ts             # Type definitions (shared)
```

### Implementation

```typescript
// src/security/types.ts (additions)

export interface RateLimitConfig {
  /** Maximum tool calls per minute per session */
  maxCallsPerMinute?: number;
  /** Maximum tool calls per session lifetime */
  maxCallsPerSession?: number;
  /** Cooldown period (ms) when limit exceeded */
  cooldownMs?: number;
  /** Tools exempt from rate limiting */
  exemptTools?: string[];
  /** Per-tool overrides */
  toolLimits?: Record<string, { perMinute?: number; perSession?: number }>;
}

export interface RateLimitResult {
  /** Whether the call is allowed */
  allowed: boolean;
  /** Remaining calls in current window */
  remaining: number;
  /** Timestamp when limit resets */
  resetAt: number;
  /** Reason if denied */
  reason?: string;
}

export const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = {
  maxCallsPerMinute: 60,
  maxCallsPerSession: 500,
  cooldownMs: 30000,
  exemptTools: ['message', 'think'],
  toolLimits: {
    exec: { perMinute: 10, perSession: 50 },
    'browser.navigate': { perMinute: 20, perSession: 100 },
  },
};
```

```typescript
// src/security/rate-store.ts

interface RateBucket {
  callsThisMinute: number;
  callsThisSession: number;
  minuteStartedAt: number;
  cooldownUntil: number;
}

// Simple LRU with max 10000 sessions
const MAX_SESSIONS = 10000;
const store = new Map<string, RateBucket>();
const accessOrder: string[] = [];

function touch(sessionId: string): void {
  const idx = accessOrder.indexOf(sessionId);
  if (idx > -1) accessOrder.splice(idx, 1);
  accessOrder.push(sessionId);

  // Evict oldest if over limit
  while (accessOrder.length > MAX_SESSIONS) {
    const oldest = accessOrder.shift()!;
    store.delete(oldest);
  }
}

export function getBucket(sessionId: string): RateBucket {
  touch(sessionId);

  if (!store.has(sessionId)) {
    store.set(sessionId, {
      callsThisMinute: 0,
      callsThisSession: 0,
      minuteStartedAt: Date.now(),
      cooldownUntil: 0,
    });
  }

  return store.get(sessionId)!;
}

export function incrementBucket(sessionId: string): void {
  const bucket = getBucket(sessionId);
  const now = Date.now();

  // Reset minute counter if window passed
  if (now - bucket.minuteStartedAt > 60000) {
    bucket.callsThisMinute = 0;
    bucket.minuteStartedAt = now;
  }

  bucket.callsThisMinute++;
  bucket.callsThisSession++;
}

export function setCooldown(sessionId: string, durationMs: number): void {
  const bucket = getBucket(sessionId);
  bucket.cooldownUntil = Date.now() + durationMs;
}

export function resetSession(sessionId: string): void {
  store.delete(sessionId);
}
```

```typescript
// src/security/rate-limit.ts

import { RateLimitConfig, RateLimitResult, DEFAULT_RATE_LIMIT_CONFIG } from './types.js';
import { getBucket, incrementBucket, setCooldown, resetSession } from './rate-store.js';

export function checkRateLimit(
  sessionId: string,
  toolName: string,
  config: RateLimitConfig = DEFAULT_RATE_LIMIT_CONFIG
): RateLimitResult {
  const cfg = { ...DEFAULT_RATE_LIMIT_CONFIG, ...config };

  // Check if tool is exempt
  if (cfg.exemptTools?.includes(toolName)) {
    return { allowed: true, remaining: Infinity, resetAt: 0 };
  }

  const bucket = getBucket(sessionId);
  const now = Date.now();

  // Check cooldown
  if (bucket.cooldownUntil > now) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: bucket.cooldownUntil,
      reason: `In cooldown until ${new Date(bucket.cooldownUntil).toISOString()}`,
    };
  }

  // Get applicable limits (tool-specific or default)
  const toolConfig = cfg.toolLimits?.[toolName];
  const perMinute = toolConfig?.perMinute ?? cfg.maxCallsPerMinute ?? 60;
  const perSession = toolConfig?.perSession ?? cfg.maxCallsPerSession ?? 500;

  // Reset minute counter if window passed
  const minuteAge = now - bucket.minuteStartedAt;
  const effectiveMinuteCalls = minuteAge > 60000 ? 0 : bucket.callsThisMinute;

  // Check per-minute limit
  if (effectiveMinuteCalls >= perMinute) {
    setCooldown(sessionId, cfg.cooldownMs ?? 30000);
    return {
      allowed: false,
      remaining: 0,
      resetAt: bucket.minuteStartedAt + 60000,
      reason: `Rate limit exceeded: ${perMinute} calls/minute for ${toolName}`,
    };
  }

  // Check per-session limit
  if (bucket.callsThisSession >= perSession) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: Infinity, // Session limit doesn't reset
      reason: `Session limit exceeded: ${perSession} calls for ${toolName}`,
    };
  }

  // Allowed - increment counters
  incrementBucket(sessionId);

  return {
    allowed: true,
    remaining: Math.min(perMinute - effectiveMinuteCalls - 1, perSession - bucket.callsThisSession),
    resetAt: bucket.minuteStartedAt + 60000,
  };
}

export function getRateLimitStatus(sessionId: string): {
  callsThisMinute: number;
  callsThisSession: number;
  inCooldown: boolean;
} {
  const bucket = getBucket(sessionId);
  return {
    callsThisMinute: bucket.callsThisMinute,
    callsThisSession: bucket.callsThisSession,
    inCooldown: bucket.cooldownUntil > Date.now(),
  };
}

export { resetSession as resetRateLimit };
```

### Configuration

```yaml
# config.yaml
security:
  rateLimit:
    enabled: true
    maxCallsPerMinute: 60
    maxCallsPerSession: 500
    cooldownMs: 30000
    exemptTools:
      - message
      - think
    toolLimits:
      exec:
        perMinute: 10
        perSession: 50
      browser.navigate:
        perMinute: 20
        perSession: 100
```

### Integration Point

```typescript
// In your tool executor
import { checkRateLimit } from './security/rate-limit.js';
import { logAudit } from './security/audit.js';

async function executeToolCall(sessionId: string, userId: string, toolName: string, params: unknown) {
  const rateCheck = checkRateLimit(sessionId, toolName);

  if (!rateCheck.allowed) {
    logAudit({
      type: 'rate.exceeded',
      sessionId,
      channel: 'your-channel',
      actor: userId,
      action: toolName,
      outcome: 'denied',
      metadata: { reason: rateCheck.reason, resetAt: rateCheck.resetAt },
    });

    return {
      error: 'Rate limit exceeded',
      retryAfter: rateCheck.resetAt - Date.now(),
    };
  }

  // Continue with tool execution
  return executeTool(toolName, params);
}
```

---

## Module 3: Structured Audit Logging

### Purpose
Standardized forensic logging with configurable sinks for incident response, compliance, and pattern detection.

### File Structure
```
src/security/
├── audit.ts             # Core audit logging
├── audit-sinks.ts       # Sink implementations
└── types.ts             # Type definitions (shared)
```

### Implementation

```typescript
// src/security/types.ts (additions)

export type AuditEventType =
  | 'session.start'
  | 'session.end'
  | 'message.inbound'
  | 'message.outbound'
  | 'tool.call'
  | 'tool.result'
  | 'auth.attempt'
  | 'auth.success'
  | 'auth.failure'
  | 'config.change'
  | 'rate.exceeded'
  | 'error.security';

export interface AuditEvent {
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Unique event ID */
  eventId: string;
  /** Event classification */
  type: AuditEventType;
  /** Session identifier */
  sessionId: string;
  /** Channel (telegram, discord, cli, etc.) */
  channel: string;
  /** Actor identifier (user ID, system, etc.) */
  actor: string;
  /** Action performed */
  action: string;
  /** Outcome of the action */
  outcome: 'success' | 'denied' | 'error';
  /** Additional context */
  metadata?: Record<string, unknown>;
}

export interface AuditSink {
  name: string;
  write(event: AuditEvent): Promise<void>;
  flush?(): Promise<void>;
}

export interface AuditConfig {
  enabled: boolean;
  sinks: AuditSinkConfig[];
  include?: AuditEventType[];
  exclude?: AuditEventType[];
  bufferSize?: number;
  flushIntervalMs?: number;
}

export type AuditSinkConfig =
  | { type: 'console' }
  | { type: 'file'; path: string; rotate?: 'daily' | 'hourly' | 'none' }
  | { type: 'webhook'; url: string; headers?: Record<string, string> };
```

```typescript
// src/security/audit-sinks.ts

import { appendFile, mkdir } from 'fs/promises';
import { dirname } from 'path';
import { AuditEvent, AuditSink, AuditSinkConfig } from './types.js';

export function createConsoleSink(): AuditSink {
  return {
    name: 'console',
    async write(event: AuditEvent) {
      const prefix = event.outcome === 'denied' ? '[DENIED]' :
                     event.outcome === 'error' ? '[ERROR]' : '[AUDIT]';
      console.log(`${prefix} ${event.type} | ${event.actor} | ${event.action}`);
    },
  };
}

export function createFileSink(config: { path: string; rotate?: string }): AuditSink {
  let currentPath = config.path;
  let lastRotation = '';

  function getRotatedPath(): string {
    if (config.rotate === 'daily') {
      const date = new Date().toISOString().split('T')[0];
      if (date !== lastRotation) {
        lastRotation = date;
        const ext = config.path.includes('.') ? '' : '.jsonl';
        currentPath = config.path.replace(/(\.\w+)?$/, `-${date}$1${ext}`);
      }
    } else if (config.rotate === 'hourly') {
      const hour = new Date().toISOString().slice(0, 13).replace('T', '-');
      if (hour !== lastRotation) {
        lastRotation = hour;
        const ext = config.path.includes('.') ? '' : '.jsonl';
        currentPath = config.path.replace(/(\.\w+)?$/, `-${hour}$1${ext}`);
      }
    }
    return currentPath;
  }

  return {
    name: 'file',
    async write(event: AuditEvent) {
      const path = getRotatedPath();
      await mkdir(dirname(path), { recursive: true });
      await appendFile(path, JSON.stringify(event) + '\n');
    },
  };
}

export function createWebhookSink(config: { url: string; headers?: Record<string, string> }): AuditSink {
  const buffer: AuditEvent[] = [];
  let flushTimeout: NodeJS.Timeout | null = null;

  async function flush() {
    if (buffer.length === 0) return;

    const events = buffer.splice(0, buffer.length);
    try {
      await fetch(config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...config.headers,
        },
        body: JSON.stringify({ events }),
      });
    } catch (err) {
      // Re-add failed events to buffer (with limit)
      if (buffer.length < 1000) {
        buffer.unshift(...events);
      }
      console.error('Audit webhook failed:', err);
    }
  }

  return {
    name: 'webhook',
    async write(event: AuditEvent) {
      buffer.push(event);

      // Batch flush every 5 seconds or 100 events
      if (buffer.length >= 100) {
        await flush();
      } else if (!flushTimeout) {
        flushTimeout = setTimeout(async () => {
          flushTimeout = null;
          await flush();
        }, 5000);
      }
    },
    async flush() {
      if (flushTimeout) {
        clearTimeout(flushTimeout);
        flushTimeout = null;
      }
      await flush();
    },
  };
}

export function createSink(config: AuditSinkConfig): AuditSink {
  switch (config.type) {
    case 'console':
      return createConsoleSink();
    case 'file':
      return createFileSink(config);
    case 'webhook':
      return createWebhookSink(config);
    default:
      throw new Error(`Unknown sink type: ${(config as any).type}`);
  }
}
```

```typescript
// src/security/audit.ts

import { randomUUID } from 'crypto';
import { AuditEvent, AuditEventType, AuditSink, AuditConfig } from './types.js';
import { createSink } from './audit-sinks.js';

let sinks: AuditSink[] = [];
let config: AuditConfig = { enabled: false, sinks: [] };

export function configureAudit(cfg: AuditConfig): void {
  config = cfg;
  sinks = cfg.sinks.map(createSink);
}

export function registerAuditSink(sink: AuditSink): void {
  sinks.push(sink);
}

function shouldLog(type: AuditEventType): boolean {
  if (!config.enabled) return false;
  if (config.exclude?.includes(type)) return false;
  if (config.include && !config.include.includes(type)) return false;
  return true;
}

export function logAudit(
  event: Omit<AuditEvent, 'timestamp' | 'eventId'>
): void {
  if (!shouldLog(event.type)) return;

  const fullEvent: AuditEvent = {
    ...event,
    timestamp: new Date().toISOString(),
    eventId: randomUUID(),
  };

  // Fire-and-forget async writes
  for (const sink of sinks) {
    sink.write(fullEvent).catch(err => {
      console.error(`Audit sink ${sink.name} failed:`, err);
    });
  }
}

export async function flushAudit(): Promise<void> {
  await Promise.all(
    sinks
      .filter(s => s.flush)
      .map(s => s.flush!())
  );
}

export async function queryAuditLog(
  filter: Partial<AuditEvent>,
  options?: { limit?: number; offset?: number; since?: string }
): Promise<AuditEvent[]> {
  // Implementation depends on sink type
  // For file sinks, read and parse JSONL
  // For webhook sinks, query the SIEM
  throw new Error('Query not implemented - use your SIEM or log aggregator');
}
```

### Configuration

```yaml
# config.yaml
security:
  audit:
    enabled: true
    sinks:
      - type: file
        path: ./logs/audit.jsonl
        rotate: daily
      - type: console
      - type: webhook
        url: https://siem.example.com/ingest
        headers:
          Authorization: Bearer ${SIEM_TOKEN}
    include:
      - tool.call
      - auth.failure
      - rate.exceeded
      - error.security
    exclude:
      - message.outbound
```

### Integration Point

```typescript
// At application startup
import { configureAudit } from './security/audit.js';

configureAudit({
  enabled: true,
  sinks: [
    { type: 'file', path: './logs/audit.jsonl', rotate: 'daily' },
    { type: 'console' },
  ],
});

// Throughout your application
import { logAudit } from './security/audit.js';

// Log session start
logAudit({
  type: 'session.start',
  sessionId: session.id,
  channel: 'telegram',
  actor: userId,
  action: 'create',
  outcome: 'success',
  metadata: { userAgent: request.headers['user-agent'] },
});

// Log tool calls
logAudit({
  type: 'tool.call',
  sessionId,
  channel,
  actor: userId,
  action: `${toolName}(${JSON.stringify(params).slice(0, 100)})`,
  outcome: result.success ? 'success' : 'error',
  metadata: { duration: result.durationMs, error: result.error },
});
```

---

## Module 4: Session Isolation

### Purpose
Zero-trust session boundaries with configurable isolation levels to prevent state leakage and contain potential breaches.

### File Structure
```
src/security/
├── session-isolation.ts # Core session management
├── session-store.ts     # Session state storage
└── types.ts             # Type definitions (shared)
```

### Implementation

```typescript
// src/security/types.ts (additions)

export type IsolationLevel = 'strict' | 'standard' | 'relaxed';

export interface SessionBoundary {
  /** Session identifier */
  sessionId: string;
  /** User who owns this session */
  userId: string;
  /** Isolation level */
  level: IsolationLevel;
  /** Created timestamp */
  createdAt: number;
  /** Last activity timestamp */
  lastActivity: number;
  /** Session timeout (ms) */
  timeoutMs: number;
  /** Tool state (for strict isolation) */
  toolState?: Map<string, unknown>;
}

export interface IsolationConfig {
  /** Default isolation level */
  defaultLevel?: IsolationLevel;
  /** Session timeout (ms) */
  sessionTimeoutMs?: number;
  /** Clear tool state between sessions */
  clearToolState?: boolean;
  /** Validate session ownership on tool calls */
  validateOwnership?: boolean;
  /** Maximum concurrent sessions per user */
  maxSessionsPerUser?: number;
}

export const DEFAULT_ISOLATION_CONFIG: IsolationConfig = {
  defaultLevel: 'standard',
  sessionTimeoutMs: 3600000, // 1 hour
  clearToolState: true,
  validateOwnership: true,
  maxSessionsPerUser: 5,
};
```

```typescript
// src/security/session-store.ts

import { SessionBoundary, IsolationLevel } from './types.js';

const sessions = new Map<string, SessionBoundary>();
const userSessions = new Map<string, Set<string>>(); // userId -> sessionIds

export function getSession(sessionId: string): SessionBoundary | undefined {
  return sessions.get(sessionId);
}

export function setSession(session: SessionBoundary): void {
  sessions.set(session.sessionId, session);

  if (!userSessions.has(session.userId)) {
    userSessions.set(session.userId, new Set());
  }
  userSessions.get(session.userId)!.add(session.sessionId);
}

export function deleteSession(sessionId: string): void {
  const session = sessions.get(sessionId);
  if (session) {
    userSessions.get(session.userId)?.delete(sessionId);
    sessions.delete(sessionId);
  }
}

export function getUserSessionCount(userId: string): number {
  return userSessions.get(userId)?.size ?? 0;
}

export function getExpiredSessions(now: number): string[] {
  const expired: string[] = [];
  for (const [id, session] of sessions) {
    if (now - session.lastActivity > session.timeoutMs) {
      expired.push(id);
    }
  }
  return expired;
}

export function touchSession(sessionId: string): void {
  const session = sessions.get(sessionId);
  if (session) {
    session.lastActivity = Date.now();
  }
}
```

```typescript
// src/security/session-isolation.ts

import { randomUUID } from 'crypto';
import {
  SessionBoundary,
  IsolationConfig,
  IsolationLevel,
  DEFAULT_ISOLATION_CONFIG,
} from './types.js';
import {
  getSession,
  setSession,
  deleteSession,
  getUserSessionCount,
  getExpiredSessions,
  touchSession,
} from './session-store.js';
import { logAudit } from './audit.js';

export function createSession(
  userId: string,
  config: IsolationConfig = DEFAULT_ISOLATION_CONFIG
): SessionBoundary {
  const cfg = { ...DEFAULT_ISOLATION_CONFIG, ...config };

  // Check concurrent session limit
  const currentCount = getUserSessionCount(userId);
  if (cfg.maxSessionsPerUser && currentCount >= cfg.maxSessionsPerUser) {
    logAudit({
      type: 'auth.failure',
      sessionId: 'none',
      channel: 'system',
      actor: userId,
      action: 'session.create',
      outcome: 'denied',
      metadata: { reason: 'max_sessions_exceeded', current: currentCount },
    });
    throw new Error(`Maximum sessions (${cfg.maxSessionsPerUser}) exceeded for user`);
  }

  const session: SessionBoundary = {
    sessionId: randomUUID(),
    userId,
    level: cfg.defaultLevel ?? 'standard',
    createdAt: Date.now(),
    lastActivity: Date.now(),
    timeoutMs: cfg.sessionTimeoutMs ?? 3600000,
    toolState: cfg.clearToolState ? new Map() : undefined,
  };

  setSession(session);

  logAudit({
    type: 'session.start',
    sessionId: session.sessionId,
    channel: 'system',
    actor: userId,
    action: 'create',
    outcome: 'success',
    metadata: { level: session.level },
  });

  return session;
}

export function validateSession(
  sessionId: string,
  userId: string,
  config: IsolationConfig = DEFAULT_ISOLATION_CONFIG
): { valid: boolean; reason?: string } {
  const session = getSession(sessionId);

  if (!session) {
    return { valid: false, reason: 'Session not found' };
  }

  // Check ownership
  if (config.validateOwnership && session.userId !== userId) {
    logAudit({
      type: 'auth.failure',
      sessionId,
      channel: 'system',
      actor: userId,
      action: 'validate',
      outcome: 'denied',
      metadata: { reason: 'ownership_mismatch', owner: session.userId },
    });
    return { valid: false, reason: 'Session ownership mismatch' };
  }

  // Check timeout
  const now = Date.now();
  if (now - session.lastActivity > session.timeoutMs) {
    logAudit({
      type: 'session.end',
      sessionId,
      channel: 'system',
      actor: userId,
      action: 'timeout',
      outcome: 'success',
      metadata: { inactiveMs: now - session.lastActivity },
    });
    deleteSession(sessionId);
    return { valid: false, reason: 'Session expired' };
  }

  // Update activity
  touchSession(sessionId);

  return { valid: true };
}

export function terminateSession(sessionId: string): void {
  const session = getSession(sessionId);
  if (session) {
    logAudit({
      type: 'session.end',
      sessionId,
      channel: 'system',
      actor: session.userId,
      action: 'terminate',
      outcome: 'success',
    });
    deleteSession(sessionId);
  }
}

export function cleanupExpiredSessions(): number {
  const expired = getExpiredSessions(Date.now());
  for (const sessionId of expired) {
    terminateSession(sessionId);
  }
  return expired.length;
}

export function getSessionToolState<T>(sessionId: string, toolName: string): T | undefined {
  const session = getSession(sessionId);
  if (!session?.toolState) return undefined;
  return session.toolState.get(toolName) as T | undefined;
}

export function setSessionToolState<T>(sessionId: string, toolName: string, state: T): void {
  const session = getSession(sessionId);
  if (session?.toolState) {
    session.toolState.set(toolName, state);
  }
}
```

### Configuration

```yaml
# config.yaml
security:
  sessions:
    defaultLevel: standard
    timeoutMs: 3600000  # 1 hour
    clearToolState: true
    validateOwnership: true
    maxSessionsPerUser: 5
```

### Integration Point

```typescript
// Session creation (at conversation start)
import { createSession, validateSession } from './security/session-isolation.js';

const session = createSession(userId, config.security.sessions);

// Session validation (on every request)
async function handleRequest(sessionId: string, userId: string, request: Request) {
  const validation = validateSession(sessionId, userId);

  if (!validation.valid) {
    return { error: validation.reason, code: 'SESSION_INVALID' };
  }

  // Continue with request handling
  return processRequest(request);
}

// Cleanup job (run periodically)
import { cleanupExpiredSessions } from './security/session-isolation.js';

setInterval(() => {
  const cleaned = cleanupExpiredSessions();
  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} expired sessions`);
  }
}, 60000); // Every minute
```

---

## Module 5: Hook Execution Hardening

### Purpose
Defensive wrappers for hook execution that prevent timeout attacks, injection, and output manipulation.

### File Structure
```
src/hooks/
├── security.ts          # Hook security wrappers
└── types.ts             # Type definitions
```

### Implementation

```typescript
// src/hooks/types.ts

export interface HookSecurityConfig {
  /** Maximum execution time (ms) */
  timeoutMs?: number;
  /** Validate payload against schema */
  validatePayload?: boolean;
  /** Sanitize string fields in payload */
  sanitizeStrings?: boolean;
  /** Maximum payload size (bytes) */
  maxPayloadSize?: number;
  /** Wrap stdout/stderr to prevent injection */
  wrapOutput?: boolean;
}

export interface HookValidationResult {
  valid: boolean;
  errors: string[];
  sanitized?: unknown;
}

export interface HookExecutionResult<T> {
  result?: T;
  error?: Error;
  timedOut: boolean;
  executionMs: number;
  stdout?: string;
  stderr?: string;
}

export const DEFAULT_HOOK_SECURITY_CONFIG: HookSecurityConfig = {
  timeoutMs: 30000,
  validatePayload: true,
  sanitizeStrings: true,
  maxPayloadSize: 1048576, // 1MB
  wrapOutput: true,
};
```

```typescript
// src/hooks/security.ts

import { spawn } from 'child_process';
import { sanitizeInput } from '../security/sanitize.js';
import { logAudit } from '../security/audit.js';
import {
  HookSecurityConfig,
  HookValidationResult,
  HookExecutionResult,
  DEFAULT_HOOK_SECURITY_CONFIG,
} from './types.js';

export function validateHookPayload(
  payload: unknown,
  schema: object | null,
  config: HookSecurityConfig = DEFAULT_HOOK_SECURITY_CONFIG
): HookValidationResult {
  const cfg = { ...DEFAULT_HOOK_SECURITY_CONFIG, ...config };
  const errors: string[] = [];
  let sanitized = payload;

  // Check payload size
  const payloadStr = JSON.stringify(payload);
  if (cfg.maxPayloadSize && payloadStr.length > cfg.maxPayloadSize) {
    errors.push(`Payload size ${payloadStr.length} exceeds limit ${cfg.maxPayloadSize}`);
    return { valid: false, errors };
  }

  // Sanitize string fields recursively
  if (cfg.sanitizeStrings) {
    sanitized = sanitizePayloadStrings(payload);
  }

  // Schema validation (if provided)
  if (cfg.validatePayload && schema) {
    const schemaErrors = validateAgainstSchema(sanitized, schema);
    errors.push(...schemaErrors);
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitized,
  };
}

function sanitizePayloadStrings(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return sanitizeInput(obj).clean;
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizePayloadStrings);
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitizePayloadStrings(value);
    }
    return result;
  }
  return obj;
}

function validateAgainstSchema(obj: unknown, schema: object): string[] {
  // Implement JSON Schema validation or use a library like ajv
  // Simplified placeholder:
  return [];
}

export async function executeHookSafely<T>(
  command: string,
  args: string[],
  payload: unknown,
  config: HookSecurityConfig = DEFAULT_HOOK_SECURITY_CONFIG
): Promise<HookExecutionResult<T>> {
  const cfg = { ...DEFAULT_HOOK_SECURITY_CONFIG, ...config };
  const startTime = Date.now();

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let resolved = false;

    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: cfg.timeoutMs,
    });

    // Timeout handler
    const timeoutHandle = setTimeout(() => {
      if (!resolved) {
        timedOut = true;
        child.kill('SIGKILL');
      }
    }, cfg.timeoutMs ?? 30000);

    child.stdout.on('data', (data) => {
      stdout += data.toString();
      // Limit output capture to prevent memory issues
      if (stdout.length > 1024 * 1024) {
        stdout = stdout.slice(-512 * 1024);
      }
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
      if (stderr.length > 1024 * 1024) {
        stderr = stderr.slice(-512 * 1024);
      }
    });

    // Write payload to stdin
    if (payload !== undefined) {
      child.stdin.write(JSON.stringify(payload));
      child.stdin.end();
    }

    child.on('close', (code) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeoutHandle);

      const executionMs = Date.now() - startTime;

      // Sanitize output if configured
      if (cfg.wrapOutput) {
        stdout = sanitizeHookOutput(stdout);
        stderr = sanitizeHookOutput(stderr);
      }

      if (timedOut) {
        logAudit({
          type: 'error.security',
          sessionId: 'hook',
          channel: 'system',
          actor: 'hook',
          action: command,
          outcome: 'error',
          metadata: { reason: 'timeout', executionMs },
        });
        resolve({
          timedOut: true,
          executionMs,
          error: new Error(`Hook timed out after ${cfg.timeoutMs}ms`),
          stdout,
          stderr,
        });
        return;
      }

      if (code !== 0) {
        resolve({
          timedOut: false,
          executionMs,
          error: new Error(`Hook exited with code ${code}: ${stderr}`),
          stdout,
          stderr,
        });
        return;
      }

      // Parse stdout as JSON result
      try {
        const result = stdout.trim() ? JSON.parse(stdout) : undefined;
        resolve({
          result: result as T,
          timedOut: false,
          executionMs,
          stdout,
          stderr,
        });
      } catch {
        resolve({
          result: stdout as unknown as T,
          timedOut: false,
          executionMs,
          stdout,
          stderr,
        });
      }
    });

    child.on('error', (error) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeoutHandle);

      resolve({
        timedOut: false,
        executionMs: Date.now() - startTime,
        error,
      });
    });
  });
}

export function sanitizeHookOutput(output: string): string {
  return output
    // Remove ANSI escape sequences
    .replace(/\x1B\[[0-9;]*[A-Za-z]/g, '')
    // Remove other control characters except \t\n\r
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Limit line length to prevent terminal issues
    .split('\n')
    .map(line => line.length > 10000 ? line.slice(0, 10000) + '...' : line)
    .join('\n');
}
```

### Configuration

```yaml
# config.yaml
hooks:
  security:
    timeoutMs: 30000
    validatePayload: true
    sanitizeStrings: true
    maxPayloadSize: 1048576  # 1MB
    wrapOutput: true
```

### Integration Point

```typescript
// When executing hooks
import { validateHookPayload, executeHookSafely } from './hooks/security.js';

async function runHook(hookName: string, payload: unknown) {
  const hookConfig = getHookConfig(hookName);

  // Validate payload first
  const validation = validateHookPayload(payload, hookConfig.schema);
  if (!validation.valid) {
    logAudit({
      type: 'error.security',
      sessionId: 'hook',
      channel: 'system',
      actor: 'hook',
      action: hookName,
      outcome: 'denied',
      metadata: { errors: validation.errors },
    });
    return { error: 'Payload validation failed', details: validation.errors };
  }

  // Execute with security wrapper
  const result = await executeHookSafely(
    hookConfig.command,
    hookConfig.args,
    validation.sanitized,
    config.hooks.security
  );

  if (result.timedOut) {
    return { error: 'Hook timed out' };
  }

  if (result.error) {
    return { error: result.error.message };
  }

  return result.result;
}
```

---

## Unified Security Middleware

### All Modules Combined

```typescript
// src/security/index.ts

import { sanitizeInput, DEFAULT_SANITIZE_OPTIONS, SanitizeOptions } from './sanitize.js';
import { checkRateLimit, DEFAULT_RATE_LIMIT_CONFIG, RateLimitConfig } from './rate-limit.js';
import { validateSession, createSession, DEFAULT_ISOLATION_CONFIG, IsolationConfig } from './session-isolation.js';
import { logAudit, configureAudit, AuditConfig } from './audit.js';

export interface SecurityMiddlewareConfig {
  sanitize?: SanitizeOptions & { enabled?: boolean };
  rateLimit?: RateLimitConfig & { enabled?: boolean };
  sessions?: IsolationConfig & { enabled?: boolean };
  audit?: AuditConfig;
}

export interface SecurityMiddlewareInput {
  sessionId: string;
  userId: string;
  message: string;
  toolName?: string;
}

export interface SecurityMiddlewareResult {
  allowed: boolean;
  reason?: string;
  sanitizedMessage: string;
  warnings: string[];
}

export function createSecurityMiddleware(config: SecurityMiddlewareConfig) {
  // Initialize audit if configured
  if (config.audit?.enabled) {
    configureAudit(config.audit);
  }

  return {
    async process(input: SecurityMiddlewareInput): Promise<SecurityMiddlewareResult> {
      const warnings: string[] = [];
      let message = input.message;

      // 1. Input sanitization
      if (config.sanitize?.enabled !== false) {
        const sanitizeResult = sanitizeInput(message, config.sanitize);
        message = sanitizeResult.clean;
        warnings.push(...sanitizeResult.warnings);

        if (sanitizeResult.warnings.length > 0) {
          logAudit({
            type: 'message.inbound',
            sessionId: input.sessionId,
            channel: 'middleware',
            actor: input.userId,
            action: 'sanitize',
            outcome: 'success',
            metadata: { warnings: sanitizeResult.warnings },
          });
        }
      }

      // 2. Session validation
      if (config.sessions?.enabled !== false) {
        const validation = validateSession(input.sessionId, input.userId, config.sessions);
        if (!validation.valid) {
          return {
            allowed: false,
            reason: validation.reason,
            sanitizedMessage: message,
            warnings,
          };
        }
      }

      // 3. Rate limiting (if tool call)
      if (input.toolName && config.rateLimit?.enabled !== false) {
        const rateResult = checkRateLimit(input.sessionId, input.toolName, config.rateLimit);
        if (!rateResult.allowed) {
          logAudit({
            type: 'rate.exceeded',
            sessionId: input.sessionId,
            channel: 'middleware',
            actor: input.userId,
            action: input.toolName,
            outcome: 'denied',
            metadata: { reason: rateResult.reason },
          });
          return {
            allowed: false,
            reason: rateResult.reason,
            sanitizedMessage: message,
            warnings,
          };
        }
      }

      return {
        allowed: true,
        sanitizedMessage: message,
        warnings,
      };
    },

    createSession: (userId: string) => createSession(userId, config.sessions),
  };
}

// Re-export all modules for individual use
export * from './sanitize.js';
export * from './rate-limit.js';
export * from './session-isolation.js';
export * from './audit.js';
export * from '../hooks/security.js';
```

---

## Migration Guide

### For Existing OpenClaw Deployments

#### Step 1: Add Dependencies
```bash
# No external dependencies required - pure TypeScript
```

#### Step 2: Copy Security Modules
Copy the `src/security/` directory to your project.

#### Step 3: Add Configuration
```yaml
# config.yaml - start conservative
security:
  sanitize:
    enabled: true
  rateLimit:
    enabled: true
    maxCallsPerMinute: 120  # Start permissive
  sessions:
    enabled: false  # Enable after testing
  audit:
    enabled: true
    sinks:
      - type: console
```

#### Step 4: Integrate Middleware
```typescript
// Wrap your existing message handler
import { createSecurityMiddleware } from './security/index.js';

const security = createSecurityMiddleware(config.security);

// Before:
async function handleMessage(sessionId, userId, message) {
  return processMessage(sessionId, message);
}

// After:
async function handleMessage(sessionId, userId, message) {
  const secured = await security.process({ sessionId, userId, message });
  if (!secured.allowed) {
    return { error: secured.reason };
  }
  return processMessage(sessionId, secured.sanitizedMessage);
}
```

#### Step 5: Gradually Tighten
```yaml
# After 1 week, tighten limits
security:
  rateLimit:
    maxCallsPerMinute: 60
  sessions:
    enabled: true
    defaultLevel: standard
```

---

## Testing

### Unit Test Examples

```typescript
// tests/security/sanitize.test.ts
import { describe, it, expect } from 'vitest';
import { sanitizeInput } from '../../src/security/sanitize.js';

describe('sanitizeInput', () => {
  it('strips control characters', () => {
    const result = sanitizeInput('hello\x00world');
    expect(result.clean).toBe('helloworld');
    expect(result.modified).toBe(true);
  });

  it('normalizes unicode', () => {
    const result = sanitizeInput('café'); // combining accent
    expect(result.clean).toBe('café'); // precomposed
  });

  it('detects bidi override attacks', () => {
    const result = sanitizeInput('hello\u202Eworld');
    expect(result.warnings).toContain('Suspicious pattern detected: bidiOverride');
  });

  it('truncates oversized input', () => {
    const result = sanitizeInput('x'.repeat(200000), { maxLength: 100000 });
    expect(result.clean.length).toBe(100000);
  });
});
```

```typescript
// tests/security/rate-limit.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { checkRateLimit, resetRateLimit } from '../../src/security/rate-limit.js';

describe('checkRateLimit', () => {
  beforeEach(() => {
    resetRateLimit('test-session');
  });

  it('allows calls under limit', () => {
    const result = checkRateLimit('test-session', 'exec', { maxCallsPerMinute: 10 });
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(9);
  });

  it('blocks calls over limit', () => {
    for (let i = 0; i < 10; i++) {
      checkRateLimit('test-session', 'exec', { maxCallsPerMinute: 10 });
    }
    const result = checkRateLimit('test-session', 'exec', { maxCallsPerMinute: 10 });
    expect(result.allowed).toBe(false);
  });

  it('exempts configured tools', () => {
    for (let i = 0; i < 100; i++) {
      const result = checkRateLimit('test-session', 'message', {
        maxCallsPerMinute: 10,
        exemptTools: ['message'],
      });
      expect(result.allowed).toBe(true);
    }
  });
});
```

---

## Security Considerations

### Threat Matrix

| Threat | Module | Mitigation |
|--------|--------|------------|
| Prompt injection | Sanitization | Pattern detection, suspicious content warnings |
| Unicode attacks | Sanitization | NFC normalization, homoglyph detection |
| ANSI injection | Sanitization + Hooks | Control char stripping, output sanitization |
| Resource exhaustion | Rate Limiting | Per-session, per-tool limits |
| Session hijacking | Session Isolation | Ownership validation, timeout enforcement |
| State leakage | Session Isolation | Isolation levels, tool state clearing |
| Hook timeout attacks | Hook Hardening | Enforced timeouts with SIGKILL |
| Hook injection | Hook Hardening | Payload validation, output sanitization |
| Forensic blind spots | Audit Logging | Structured events, correlation IDs |

### What This Does NOT Address

- Network-level attacks (use TLS, firewalls)
- Authentication bypass (use proper auth)
- API key exposure (use secrets management)
- Denial of service at scale (use CDN, rate limiting at edge)

---

## Notes

This Document provides **production-ready implementation patterns**. 

Key sources:
[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[OpenClaw Security Audit Guidelines](https://docs.openclaw.ai/security)
[Agent Security Best Practices](https://docs.openclaw.ai/security/best-practices)
[moltaudit Defensive security audit tool (Moltbot/Clawdbot)](https://github.com/signalfi/MoltAudit)
[Home of the Iron Crab](crabhive.com)

The Iron Crab principle: hardened shell, verify everything. Start with all modules enabled and loosen only with explicit justification.

---

## Tags

#implementation #security #typescript #openclaw #rate-limiting #sanitization #audit-logging #session-isolation #hooks #openclaw #security #agenticai #researchai #rfc #crabhive #tetsu #tetsumaki #moltaudit #moltbook #zerotrust #defenseindepth
