import type express from 'express'

import jwt from 'jsonwebtoken'
import jwksClient, { type JwksClient } from 'jwks-rsa'

export type ErrorReason = 'INVALID_SECURITY_TYPE' | 'NO_TOKEN' | 'MISSING_SCOPES' | 'INVALID_TOKEN' | 'INTERNAL_ERROR'

/**
 * Error which represents and authentication failure
 */
export class OauthError extends Error {
  constructor(public reason: ErrorReason) {
    super(`Auth failed for reason: ${reason}`)
  }
}

/**
 * Error which represents multiple authentication failures when using `mergeAcceptAny`
 */
export class AggregateOAuthError extends Error {
  constructor(public errors: OauthError[]) {
    super(`Auth failed with multiple errors: [${errors.map((e) => e.reason).join(', ')}]`)
  }
}

/**
 * Options to be used when creating an authenticator.
 */
export interface AuthOptions {
  securityName?: string
  verifyOptions?: jwt.VerifyOptions & { complete?: false }
  jwksUri: () => Promise<string>
  getAccessToken: (req: express.Request) => Promise<string | undefined>
  getScopesFromToken: (decoded: string | jwt.JwtPayload) => Promise<string[]>
  tryRefreshTokens?: (req: express.Request) => Promise<string | false>
}

type VerifyResolve = { type: 'error'; err: jwt.VerifyErrors } | { type: 'success'; result: jwt.JwtPayload | string }

/**
 * User type populated onto `express` when authentication is successful
 */
export type TsoaExpressUser = {
  securityName: string
  jwt: jwt.JwtPayload | string
}

/**
 * Tsoa authentication function
 */
export type TsoaExpressAuthenticator = (
  request: express.Request,
  securityName: string,
  scopes?: string[]
) => Promise<TsoaExpressUser>

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

/**
 * Builds an authenticator for using with `tsoa`
 * @param options
 * @returns
 */
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

  const verifyToken = async (accessToken: string): Promise<VerifyResolve> => {
    return new Promise<VerifyResolve>((resolve, reject) => {
      jwt.verify(accessToken, getKey, options.verifyOptions, function (err, decoded) {
        if (err) {
          resolve({
            type: 'error',
            err,
          })
          return
        }

        if (!decoded) {
          reject(new OauthError('INTERNAL_ERROR'))
          return
        }

        resolve({ type: 'success', result: decoded })
      })
    })
  }

  async function handleErrorAndRefresh(verifyResult: VerifyResolve, request: express.Request) {
    if (verifyResult.type === 'success') {
      return verifyResult.result
    }

    const err = verifyResult.err
    if (!(err instanceof jwt.TokenExpiredError)) {
      throw new OauthError('INVALID_TOKEN')
    }

    const refresh = options.tryRefreshTokens
    if (!refresh) {
      throw new OauthError('INVALID_TOKEN')
    }

    const accessToken = await refresh(request)

    if (!accessToken) {
      throw new OauthError('INVALID_TOKEN')
    }

    const refreshVerify = await verifyToken(accessToken)
    if (refreshVerify.type === 'error') {
      throw new OauthError('INVALID_TOKEN')
    }

    return refreshVerify.result
  }

  return async function expressAuthentication(request: express.Request, securityName: string, scopes?: string[]) {
    await assertClient()

    if (securityName !== requiredSecurityName) {
      throw new OauthError('INVALID_SECURITY_TYPE')
    }

    const accessToken = await options.getAccessToken(request)

    if (!accessToken) {
      throw new OauthError('NO_TOKEN')
    }

    const verifyResult = await verifyToken(accessToken)
    const jwt = await handleErrorAndRefresh(verifyResult, request)
    await checkScopes(jwt, scopes, options)

    if (!jwt) {
      throw new OauthError('INTERNAL_ERROR')
    }

    return {
      securityName,
      jwt,
    }
  }
}

/**
 * Takes an array of TsoaExpressAuthenticator's producing a new TsoaExpressAuthenticator that will try each authenticator in turn. If any authenticator
 * succeeds authentication will pass with the reuslt of that authenticator . If all fail the first failure reason is thrown. At least one TsoaExpressAuthenticator must be provided
 * @param authenticators The array of TsoaExpressAuthenticator to evaluate a request against
 * @returns A TsoaExpressAuthenticator which aggregates the provided authenticators
 */
export function mergeAcceptAny(
  authenticators: [TsoaExpressAuthenticator, ...TsoaExpressAuthenticator[]]
): TsoaExpressAuthenticator {
  return async function expressAuthenticationMerged(request: express.Request, securityName: string, scopes?: string[]) {
    let errors: OauthError[] = []
    for (const authenticator of authenticators) {
      try {
        const result = await authenticator(request, securityName, scopes)
        return result
      } catch (err) {
        if (err instanceof OauthError) {
          errors.push(err)
          continue
        }
        throw err
      }
    }
    throw new AggregateOAuthError(errors)
  }
}
