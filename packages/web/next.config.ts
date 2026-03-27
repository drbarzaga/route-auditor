import type { NextConfig } from 'next'
import { readFileSync } from 'fs'
import { join } from 'path'

const { version } = JSON.parse(readFileSync(join(__dirname, '../cli/package.json'), 'utf-8')) as {
  version: string
}

const nextConfig: NextConfig = {
  serverExternalPackages: ['@resvg/resvg-js'],
  env: {
    NEXT_PUBLIC_CLI_VERSION: version,
  },
}

export default nextConfig
