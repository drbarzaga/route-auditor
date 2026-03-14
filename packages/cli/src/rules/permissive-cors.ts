import type { AuditRule, AuditContext, RouteFile, Vulnerability } from '../types'

const WILDCARD_CORS_SIGNATURES = [
  "Access-Control-Allow-Origin', '*'",
  "Access-Control-Allow-Origin\", '*'",
  'Access-Control-Allow-Origin\', "*"',
  'Access-Control-Allow-Origin", "*"',
  "'Access-Control-Allow-Origin': '*'",
  '"Access-Control-Allow-Origin": "*"',
  "origin: '*'",
  'origin: "*"',
  'origin: true',
]

const SAFE_CORS_SIGNATURES = ['CORS_ORIGIN', 'ALLOWED_ORIGINS', 'allowedOrigins', 'allowOrigins']

const hasWildcardCors = (rawContent: string): boolean =>
  WILDCARD_CORS_SIGNATURES.some((innerSignature) => rawContent.includes(innerSignature))

const hasSafeCors = (rawContent: string): boolean =>
  SAFE_CORS_SIGNATURES.some((innerSignature) => rawContent.includes(innerSignature))

export const permissiveCors: AuditRule = {
  id: 'RW-CORS-001',
  name: 'Permissive CORS Policy',
  description:
    'API route sets Access-Control-Allow-Origin to wildcard (*), allowing any origin to read the response.',
  severity: 'medium',
  category: 'cors',
  enabled: true,
  check(route: RouteFile, _context: AuditContext): Vulnerability[] {
    if (!route.isApiRoute) return []
    if (!hasWildcardCors(route.rawContent)) return []
    if (hasSafeCors(route.rawContent)) return []

    return [
      {
        id: 'RW-CORS-001',
        title: 'Permissive CORS Policy',
        description: `The API route ${route.routePath} sets Access-Control-Allow-Origin to * — any external site can read its responses.`,
        severity: 'medium',
        category: 'cors',
        owasp: 'A05:2021 – Security Misconfiguration',
        filePath: route.filePath,
        routePath: route.routePath,
        fix: {
          description:
            'Restrict Access-Control-Allow-Origin to a specific list of trusted origins instead of using a wildcard.',
          effort: 'low',
          codeExample: `const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') ?? []\n\nexport async function GET(req: Request) {\n  const origin = req.headers.get('origin') ?? ''\n  const isAllowed = ALLOWED_ORIGINS.includes(origin)\n\n  return Response.json({ data }, {\n    headers: {\n      'Access-Control-Allow-Origin': isAllowed ? origin : '',\n    },\n  })\n}`,
        },
      },
    ]
  },
}
