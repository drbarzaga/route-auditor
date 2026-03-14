import type { AuditRule } from '../types'
import { unprotectedApiRoute } from './unprotected-api-route'
import { missingCsrfProtection } from './missing-csrf-protection'
import { missingRateLimit } from './missing-rate-limit'
import { permissiveCors } from './permissive-cors'

export const ALL_RULES: AuditRule[] = [
  unprotectedApiRoute,
  missingCsrfProtection,
  missingRateLimit,
  permissiveCors,
]
