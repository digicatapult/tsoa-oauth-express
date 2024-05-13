import type express from 'express'
import type * as jwt from 'jsonwebtoken'

import mkExpressAuthentication, { AuthOptions } from '../src/index.js'

const exampleOptions: AuthOptions = {
  verifyOptions: {},
  jwksUri: () => Promise.resolve('http://localhost:3080/realms/example/protocol/openid-connect/certs'),
  getAccessToken: (req: express.Request) => Promise.resolve(req.headers['authorization']?.substring('bearer '.length)),
  getScopesFromToken: async (decoded: string | jwt.JwtPayload) => {
    const scopes = ((decoded as jwt.JwtPayload).scopes as string) || ''
    return scopes.split(' ')
  },
  tryRefreshTokens: (_req: express.Request) => Promise.resolve(false),
}

export const expressAuthentication = mkExpressAuthentication(exampleOptions)
