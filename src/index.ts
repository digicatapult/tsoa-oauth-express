import type express from 'express'

import jwt from 'jsonwebtoken'
import jwksClient, { type JwksClient } from 'jwks-rsa'

export type ErrorReason = 'INVALID_SECURITY_TYPE' | 'NO_TOKEN' | 'MISSING_SCOPES' | 'INVALID_TOKEN'
export class OauthError extends Error {
  constructor(public reason: ErrorReason) {
    super(`Auth failed for reason: ${reason}`)
  }
}

export interface AuthOptions {
  securityName?: string
  verifyOptions?: jwt.VerifyOptions & { complete?: false }
  jwksUri: () => Promise<string>
  getAccessToken: (req: express.Request) => Promise<string | undefined>
  getScopesFromToken: (decoded: string | jwt.JwtPayload) => Promise<string[]>
  tryRefreshTokens?: (req: express.Request) => Promise<boolean>
}

type verifyResolve = [jwt.VerifyErrors | null, string | jwt.JwtPayload | undefined]
export type TsoaExpressAuthenticator = (
  request: express.Request,
  securityName: string,
  scopes?: string[]
) => Promise<void>

async function handleError(err: unknown, request: express.Request, options: AuthOptions) {
  if (!err) {
    return
  }

  if (!(err instanceof jwt.TokenExpiredError)) {
    throw new OauthError('INVALID_TOKEN')
  }

  const refresh = options.tryRefreshTokens
  if (!refresh) {
    throw new OauthError('INVALID_TOKEN')
  }

  const refreshSucceeded = await refresh(request)

  if (!refreshSucceeded) {
    throw new OauthError('INVALID_TOKEN')
  }
}

async function checkScopes(
  token: string | jwt.JwtPayload | undefined,
  requiredScopes: string[] | undefined,
  options: AuthOptions
) {
  if (!requiredScopes || requiredScopes.length === 0) {
    return
  }

  if (!token) {
    throw new OauthError('MISSING_SCOPES')
  }

  const tokenScopes = new Set(await options.getScopesFromToken(token))

  for (const requiredScope of requiredScopes) {
    if (!tokenScopes.has(requiredScope)) {
      throw new OauthError('MISSING_SCOPES')
    }
  }
}

export default function mkExpressAuthentication(options: AuthOptions): TsoaExpressAuthenticator {
  let client: JwksClient
  let requiredSecurityName = options.securityName ?? 'oauth2'

  const assertClient = async (): Promise<JwksClient> => {
    if (!client) {
      client = jwksClient({
        jwksUri: await options.jwksUri(),
        requestHeaders: {}, // Optional
        timeout: 30000, // Defaults to 30s
      })
    }
    return client
  }

  const getKey: jwt.GetPublicKeyOrSecret = (header, callback) => {
    client.getSigningKey(header.kid, function (err, key) {
      if (err || !key) {
        callback(err || new Error('Error getting jwks key'))
        return
      }
      callback(null, key.getPublicKey())
    })
  }

  return async function expressAuthentication(
    request: express.Request,
    securityName: string,
    scopes?: string[]
  ): Promise<void> {
    await assertClient()

    if (securityName !== requiredSecurityName) {
      throw new OauthError('INVALID_SECURITY_TYPE')
    }

    const accessToken = await options.getAccessToken(request)

    if (!accessToken) {
      throw new OauthError('NO_TOKEN')
    }

    const [err, result] = await new Promise<verifyResolve>((resolve) => {
      jwt.verify(accessToken, getKey, options.verifyOptions, function (err, decoded) {
        resolve([err, decoded])
      })
    })

    await handleError(err, request, options)

    await checkScopes(result, scopes, options)
  }
}
