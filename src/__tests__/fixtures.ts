import type express from 'express'
import * as jwt from 'jsonwebtoken'
import mockJwks, { type JWKSMock } from 'mock-jwks'
import { AuthOptions } from '../index.js'

export function withMockJwks() {
  let jwksMock: JWKSMock
  let stop: () => void

  beforeEach(async function () {
    jwksMock = mockJwks.createJWKSMock('https://keycloak.example.com')
    stop = jwksMock.start()
  })

  afterEach(function () {
    stop && stop()
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
  tryRefreshTokens: (_req: express.Request) => Promise.resolve(false),
}
