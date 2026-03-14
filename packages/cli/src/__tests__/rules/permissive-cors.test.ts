import { describe, it, expect } from 'vitest'
import { permissiveCors } from '../../rules/permissive-cors'
import type { RouteFile, AuditContext } from '../../types'

const buildRouteFile = (overrides: Partial<RouteFile> = {}): RouteFile => ({
  projectRoot: '/project',
  filePath: '/project/app/api/data/route.ts',
  routePath: '/api/data',
  routerType: 'app',
  isApiRoute: true,
  isDynamic: false,
  dynamicSegments: [],
  hasCatchAll: false,
  hasOptionalCatchAll: false,
  methods: ['GET'],
  exports: ['GET'],
  rawContent: `export async function GET() {\n  return Response.json({}, { headers: { 'Access-Control-Allow-Origin': '*' } })\n}`,
  ...overrides,
})

const buildContext = (): AuditContext => ({
  projectRoot: '/project',
  routerType: 'app',
  detectedStack: {},
  config: {},
  allRoutes: [],
})

describe('permissiveCors', () => {
  describe('when route is not an API route', () => {
    it('returns no vulnerabilities', () => {
      const route = buildRouteFile({ isApiRoute: false })
      const result = permissiveCors.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('when route has no CORS headers', () => {
    it('returns no vulnerabilities', () => {
      const route = buildRouteFile({
        rawContent: 'export async function GET() { return Response.json({}) }',
      })
      const result = permissiveCors.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('when route has wildcard CORS', () => {
    it.each([
      ['single-quote header set', "headers.set('Access-Control-Allow-Origin', '*')"],
      ['double-quote header set', 'headers.set("Access-Control-Allow-Origin", "*")'],
      ['object single-quote', "{ 'Access-Control-Allow-Origin': '*' }"],
      ['object double-quote', '{ "Access-Control-Allow-Origin": "*" }'],
      ["cors origin: '*'", "cors({ origin: '*' })"],
      ['cors origin: true', 'cors({ origin: true })'],
    ])('returns a vulnerability for %s', (_, rawContent) => {
      const route = buildRouteFile({ rawContent })
      const result = permissiveCors.check(route, buildContext())
      expect(result).toHaveLength(1)
      expect(result[0]?.id).toBe('RW-CORS-001')
      expect(result[0]?.severity).toBe('medium')
      expect(result[0]?.category).toBe('cors')
    })
  })

  describe('when route has a safe CORS configuration', () => {
    it.each([
      [
        'CORS_ORIGIN env variable',
        "const origin = process.env.CORS_ORIGIN\nheaders.set('Access-Control-Allow-Origin', '*')",
      ],
      ['ALLOWED_ORIGINS list', "const ALLOWED_ORIGINS = ['https://example.com']\norigin: '*'"],
      ['allowedOrigins check', "const allowedOrigins = [...]\norigin: '*'"],
      ['allowOrigins config', "allowOrigins: ['https://example.com']\norigin: '*'"],
    ])('returns no vulnerabilities when route uses %s', (_, rawContent) => {
      const route = buildRouteFile({ rawContent })
      const result = permissiveCors.check(route, buildContext())
      expect(result).toHaveLength(0)
    })
  })

  describe('vulnerability details', () => {
    it('includes the route path in the description', () => {
      const route = buildRouteFile({ routePath: '/api/public/data' })
      const result = permissiveCors.check(route, buildContext())
      expect(result[0]?.description).toContain('/api/public/data')
    })

    it('references ALLOWED_ORIGINS in the fix', () => {
      const result = permissiveCors.check(buildRouteFile(), buildContext())
      expect(result[0]?.fix.description).toContain('trusted origins')
      expect(result[0]?.fix.codeExample).toContain('ALLOWED_ORIGINS')
    })

    it('sets effort to low', () => {
      const result = permissiveCors.check(buildRouteFile(), buildContext())
      expect(result[0]?.fix.effort).toBe('low')
    })

    it('references the correct OWASP category', () => {
      const result = permissiveCors.check(buildRouteFile(), buildContext())
      expect(result[0]?.owasp).toContain('A05:2021')
    })
  })
})
