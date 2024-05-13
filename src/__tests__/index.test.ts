import type express from 'express'

import { describe, test } from 'mocha'

import mkExpressAuthentication, { OauthError } from '../index.js'
import { testOptions, withMockJwks } from './fixtures.js'

describe('expressAuthenticator', function () {
  let expect: Chai.ExpectStatic
  before(async () => {
    expect = (await import('chai')).expect
  })

  const { getJwksMock } = withMockJwks()

  test('with security !== oauth2 should throw ForbiddenError ', async function () {
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: any
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

    let error: any
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

    let error: any
    try {
      await expressAuthenticator(
        {
          headers: {
            authorization: `Bearer ${getJwksMock().token()}`,
          },
        } as express.Request,
        'oauth2'
      )
    } catch (err) {
      error = err
    }

    expect(error).equal(undefined)
  })

  test('with security === reconfigured should succeed', async function () {
    const expressAuthenticator = mkExpressAuthentication({
      ...testOptions,
      securityName: 'reconfigured',
    })

    let error: any
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

    let error: any
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

    let error: any
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

    let error: any
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
    const expressAuthenticator = mkExpressAuthentication(testOptions)

    let error: any
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
      tryRefreshTokens: () => Promise.resolve(false),
    })

    let error: any
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

    let error: any
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

    let error: any
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

    let error: any
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
