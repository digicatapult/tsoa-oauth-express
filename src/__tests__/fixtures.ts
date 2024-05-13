import type express from 'express'
import * as jwt from 'jsonwebtoken'
import { AuthOptions } from '../index.js'

export function withMockJwks() {
  let jwksMockImportP = import('mock-jwks')
  let jwksMock: ReturnType<Awaited<typeof jwksMockImportP>['default']>
  beforeEach(async function () {
    const createJWKSMock = (await jwksMockImportP).default
    jwksMock = createJWKSMock('https://keycloak.example.com')
    jwksMock.start()
  })

  afterEach(function () {
    jwksMock.stop()
  })

  return {
    getJwksMock() {
      return jwksMock
    },
  }
}

export const testOptions: AuthOptions = {
  verifyOptions: {},
  jwksUri: () => Promise.resolve('https://keycloak.example.com/.well-known/jwks.json'),
  getAccessToken: (req: express.Request) => Promise.resolve(req.headers['authorization']?.substring('bearer '.length)),
  getScopesFromToken: async (decoded: string | jwt.JwtPayload) => {
    const scopes = ((decoded as jwt.JwtPayload).scopes as string) || ''
    return scopes.split(' ')
  },
  tryRefreshTokens: (_req: express.Request) => Promise.resolve(true),
}
