import type express from 'express'

import { expect } from 'chai'
import { describe, test } from 'mocha'

import mkExpressAuthentication, { AggregateOAuthError, mergeAcceptAny, OauthError, TsoaExpressUser } from '../index.js'
import { testOptions, withMockJwks } from './fixtures.js'

describe('expressAuthenticator', function () {
  const { getJwksMock } = withMockJwks()

  test('with security !== oauth2 should throw ForbiddenError ', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: unknown
    try {
      await expressAuthenticator({} as express.Request, 'reconfigured')
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('INVALID_SECURITY_TYPE')
  })

  test('with no token should error', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: unknown
    try {
      await expressAuthenticator({ headers: {} } as express.Request, 'oauth2')
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('NO_TOKEN')
  })

  test('with valid token should succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let result: TsoaExpressUser
    result = await expressAuthenticator(
      {
        headers: {
          authorization: `Bearer ${getJwksMock().token()}`,
        },
      } as express.Request,
      'oauth2'
    )

    expect(result.securityName).equal('oauth2')
    expect(result.jwt).to.have.property('iat')
  })

  test('with security === reconfigured should succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      securityName: 'reconfigured',
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token()}`,
          },
        } as express.Request,
        'reconfigured'
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with a matching preconfigured sub should not error', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      verifyOptions: {
        subject: 'testing',
      },
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ sub: 'testing' })}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with a non-matching preconfigured sub should error', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      verifyOptions: {
        subject: 'production',
      },
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ sub: 'testing' })}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('INVALID_TOKEN')
  })

  test('with expired token and no refresh method should error', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      tryRefreshTokens: undefined,
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ exp: 0 })}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('INVALID_TOKEN')
  })

  test('with expired token should refresh and then succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      tryRefreshTokens: () => Promise.resolve(getJwksMock().token()),
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ exp: 0 })}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with unsuccessful refresh should error', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      tryRefreshTokens: () => Promise.resolve(false as const),
    })

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ exp: 0 })}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('INVALID_TOKEN')
  })

  test('with all required scopes should succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ scopes: 'test1 test2' })}`,
          },
        } as express.Request,
        'oauth2',
        ['test1', 'test2']
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with excess scopes should succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ scopes: 'test1 test2' })}`,
          },
        } as express.Request,
        'oauth2',
        ['test1']
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with missing scope should error', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ scopes: 'test1' })}`,
          },
        } as express.Request,
        'oauth2',
        ['test1', 'test2']
      )
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(OauthError)
    expect((error as OauthError).reason).to.equal('MISSING_SCOPES')
  })
})

describe('mergeAcceptAny', function () {
  const { getJwksMock } = withMockJwks()

  test('succeeds with single securityType', async function () {
    const expressAuthenticator = mergeAcceptAny([mkExpressAuthentication(testOptions)])

    let result: TsoaExpressUser
    result = await expressAuthenticator(
      {
        headers: {
          authorization: `Bearer ${getJwksMock().token()}`,
        },
      } as express.Request,
      'oauth2'
    )

    expect(result.securityName).equal('oauth2')
    expect(result.jwt).to.have.property('iat')
  })

  test('succeeds with first securityType', async function () {
    const expressAuthenticator = mergeAcceptAny([
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'first' }, securityName: 'first' }),
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'second' }, securityName: 'second' }),
    ])

    let result: TsoaExpressUser
    result = await expressAuthenticator(
      {
        headers: {
          authorization: `Bearer ${getJwksMock().token({ sub: 'first' })}`,
        },
      } as express.Request,
      'first'
    )

    expect(result.securityName).equal('first')
    expect(result.jwt).to.have.property('iat')
  })

  test('succeeds with second securityType', async function () {
    const expressAuthenticator = mergeAcceptAny([
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'first' }, securityName: 'first' }),
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'second' }, securityName: 'second' }),
    ])

    let result: TsoaExpressUser
    result = await expressAuthenticator(
      {
        headers: {
          authorization: `Bearer ${getJwksMock().token({ sub: 'second' })}`,
        },
      } as express.Request,
      'second'
    )

    expect(result.securityName).equal('second')
    expect(result.jwt).to.have.property('iat')
  })

  test('fails with AggregateOAuthError is both fail', async function () {
    const expressAuthenticator = mergeAcceptAny([
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'first' }, securityName: 'first' }),
      mkExpressAuthentication({ ...testOptions, verifyOptions: { subject: 'second' }, securityName: 'second' }),
    ])

    let error: unknown
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token({ sub: 'third' })}`,
          },
        } as express.Request,
        'third'
      )
    } catch (err) {
      error = err
    }

    expect(error).instanceOf(AggregateOAuthError)
    if (!(error instanceof AggregateOAuthError)) {
      throw new Error('Should never happen')
    }
    expect(error.errors.length).equal(2)
    expect(error.errors[0]).instanceOf(OauthError)
    expect((error.errors[0] as OauthError).reason).equal('INVALID_SECURITY_TYPE')
    expect(error.errors[1]).instanceOf(OauthError)
    expect((error.errors[1] as OauthError).reason).equal('INVALID_SECURITY_TYPE')
  })
})
