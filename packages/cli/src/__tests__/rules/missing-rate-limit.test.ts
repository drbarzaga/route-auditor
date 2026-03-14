import { describe, it, expect } from 'vitest'
import { missingRateLimit } from '../../rules/missing-rate-limit'
import type { RouteFile, AuditContext } from '../../types'

const buildRouteFile = (overrides: Partial<RouteFile> = {}): RouteFile => ({
  projectRoot: '/project',
  filePath: '/project/app/api/users/route.ts',
  routePath: '/api/users',
  routerType: 'app',
  isApiRoute: true,
  isDynamic: false,
  dynamicSegments: [],
  hasCatchAll: false,
  hasOptionalCatchAll: false,
  methods: ['POST'],
  exports: ['POST'],
  rawContent: 'export async function POST(req: Request) { return Response.json({}) }',
  ...overrides,
})

const buildContext = (overrides: Partial<AuditContext> = {}): AuditContext => ({
  projectRoot: '/project',
  routerType: 'app',
  detectedStack: {},
  config: {},
  allRoutes: [],
  ...overrides,
})

describe('missingRateLimit', () => {
  describe('when route is not an API route', () => {
    it('returns no vulnerabilities', () => {
      const route = buildRouteFile({ isApiRoute: false })
      const result = missingRateLimit.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('when route is a GET-only route', () => {
    it('returns no vulnerabilities for public read endpoints', () => {
      const route = buildRouteFile({ methods: ['GET'], routePath: '/api/products' })
      const result = missingRateLimit.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('when route has rate limiting', () => {
    it.each([
      ['@upstash/ratelimit import', "import { Ratelimit } from '@upstash/ratelimit'"],
      ['Ratelimit class', 'new Ratelimit({ redis, limiter })'],
      ['ratelimit variable', 'const ratelimit = new Ratelimit()'],
      ['rateLimiter variable', 'const rateLimiter = createLimiter()'],
      ['rate_limit function', 'await rate_limit(ip)'],
      ['upstash reference', 'upstash.limit(ip)'],
      ['next-rate-limit', "import rateLimit from 'next-rate-limit'"],
    ])('returns no vulnerabilities when route uses %s', (_, rawContent) => {
      const route = buildRouteFile({ rawContent })
      const result = missingRateLimit.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('severity based on route type', () => {
    it('returns high severity for auth routes', () => {
      const route = buildRouteFile({ routePath: '/api/auth/login', methods: ['POST'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result[0]?.severity).toBe('high')
    })

    it.each(['login', 'logout', 'register', 'signup', 'password', 'token', 'otp', 'verify'])(
      'returns high severity for routes containing %s',
      (segment) => {
        const route = buildRouteFile({ routePath: `/api/${segment}`, methods: ['POST'] })
        const result = missingRateLimit.check(route, buildContext())
        expect(result[0]?.severity).toBe('high')
      },
    )

    it('returns medium severity for POST routes', () => {
      const route = buildRouteFile({ routePath: '/api/orders', methods: ['POST'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result[0]?.severity).toBe('medium')
    })

    it('returns medium severity for PUT routes', () => {
      const route = buildRouteFile({ routePath: '/api/users/[id]', methods: ['PUT'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result[0]?.severity).toBe('medium')
    })

    it('returns medium severity for DELETE routes', () => {
      const route = buildRouteFile({ routePath: '/api/users/[id]', methods: ['DELETE'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result[0]?.severity).toBe('medium')
    })

    it('skips GET-only routes that are not auth-related', () => {
      const route = buildRouteFile({ routePath: '/api/posts', methods: ['GET'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result).toHaveLength(0)
    })

    it('flags auth GET routes as high (e.g. token verification)', () => {
      const route = buildRouteFile({ routePath: '/api/verify/email', methods: ['GET'] })
      const result = missingRateLimit.check(route, buildContext())
      expect(result[0]?.severity).toBe('high')
    })
  })

  describe('fix suggestion', () => {
    it('returns upstash-specific fix when upstash is in the stack', () => {
      const context = buildContext({ detectedStack: { rateLimit: 'upstash' } })
      const result = missingRateLimit.check(buildRouteFile(), context)
      expect(result[0]?.fix.description).toContain('@upstash/ratelimit')
      expect(result[0]?.fix.codeExample).toContain('Ratelimit')
    })

    it('returns generic fix when no rate limit stack is detected', () => {
      const result = missingRateLimit.check(buildRouteFile(), buildContext())
      expect(result[0]?.fix.codeExample).toBeUndefined()
    })

    it('always returns low effort', () => {
      const result = missingRateLimit.check(buildRouteFile(), buildContext())
      expect(result[0]?.fix.effort).toBe('low')
    })
  })
})
