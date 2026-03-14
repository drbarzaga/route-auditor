import type { AuditRule, AuditContext, RouteFile, Vulnerability, Fix, Severity } from '../types'

const RATE_LIMIT_SIGNATURES = [
  'ratelimit',
  'rateLimiter',
  'rate_limit',
  'RateLimit',
  'Ratelimit',
  'upstash',
  '@upstash/ratelimit',
  'next-rate-limit',
  'express-rate-limit',
  'limiter',
  'slowDown',
]

const AUTH_PATH_SEGMENTS = [
  'auth',
  'login',
  'logout',
  'register',
  'signup',
  'password',
  'token',
  'otp',
  'verify',
]

const MUTATION_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']

const UPSTASH_FIX: Fix = {
  description: 'Use @upstash/ratelimit to add rate limiting to this route.',
  effort: 'low',
  codeExample: `import { Ratelimit } from '@upstash/ratelimit'\nimport { Redis } from '@upstash/redis'\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(10, '10 s'),\n})\n\nexport async function POST(req: Request) {\n  const ip = req.headers.get('x-forwarded-for') ?? 'anonymous'\n  const { success } = await ratelimit.limit(ip)\n  if (!success) return Response.json({ error: 'Too many requests' }, { status: 429 })\n  // your logic\n}`,
}

const GENERIC_FIX: Fix = {
  description:
    'Add rate limiting to prevent abuse. Consider @upstash/ratelimit for a simple, scalable solution.',
  effort: 'low',
}

const hasRateLimit = (rawContent: string): boolean =>
  RATE_LIMIT_SIGNATURES.some((innerSignature) =>
    rawContent.toLowerCase().includes(innerSignature.toLowerCase()),
  )

const isAuthRoute = (routePath: string): boolean =>
  AUTH_PATH_SEGMENTS.some((innerSegment) => routePath.toLowerCase().includes(innerSegment))

const hasMutationMethod = (methods: string[]): boolean =>
  methods.some((innerMethod) => MUTATION_METHODS.includes(innerMethod))

const deriveSeverity = (routePath: string, methods: string[]): Severity | null => {
  if (isAuthRoute(routePath)) return 'high'
  if (hasMutationMethod(methods)) return 'medium'
  return null
}

const buildFix = (hasUpstash: boolean): Fix => (hasUpstash ? UPSTASH_FIX : GENERIC_FIX)

export const missingRateLimit: AuditRule = {
  id: 'RW-RATE-001',
  name: 'Missing Rate Limiting',
  description: 'API route does not appear to have rate limiting.',
  severity: 'medium',
  category: 'rate-limiting',
  enabled: true,
  check(route: RouteFile, context: AuditContext): Vulnerability[] {
    if (!route.isApiRoute) return []
    if (hasRateLimit(route.rawContent)) return []

    const severity = deriveSeverity(route.routePath, route.methods)
    if (severity === null) return []

    const hasUpstash = context.detectedStack.rateLimit === 'upstash'

    return [
      {
        id: 'RW-RATE-001',
        title: 'Missing Rate Limiting',
        description: `The API route ${route.routePath} has no rate limiting. It can be abused by sending unlimited requests.`,
        severity,
        category: 'rate-limiting',
        owasp: 'A04:2021 – Insecure Design',
        filePath: route.filePath,
        routePath: route.routePath,
        fix: buildFix(hasUpstash),
      },
    ]
  },
}
