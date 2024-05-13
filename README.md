# tsoa-oauth-express

This library enables easy implementation of OAuth2 authentication for [tsoa](https://tsoa-community.github.io/docs/) on [express](http://expressjs.com/). To use this library first add it as an `npm` dependency to your existing `tsoa` application.

```sh
npm i @digicatapult/tsoa-oauth-express
```

Your authentication file (see tsoa's documentation on authentication setup [here](https://tsoa-community.github.io/docs/authentication.html)) will then need to contain something like:

```ts
import type express from 'express'
import type * as jwt from 'jsonwebtoken'

import mkExpressAuthentication, { AuthOptions } from '@digicatapult/tsoa-oauth-express'

// module options
const options: AuthOptions = {
  ...
}

export const expressAuthentication = mkExpressAuthentication(options)
```

where the `options` value is an object with the following type and properties:

```ts
interface AuthOptions {
  securityName?: string
  verifyOptions?: jwt.VerifyOptions & { complete?: false }
  jwksUri: () => Promise<string>
  getAccessToken: (req: express.Request) => Promise<string | undefined>
  getScopesFromToken: (decoded: string | jwt.JwtPayload) => Promise<string[]>
  tryRefreshTokens: (req: express.Request) => Promise<boolean>
}
```

| property           | required | description                                                                                                                                                                         |
| ------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| jwksUri            | `true`   | Resolves to the `uri` for your identity providers `jwks` configuration                                                                                                              |
| getAccessToken     | `true`   | Resolves a JWT from the `Request`. For example this may come from an `authorization` header or a `cookie` based on requirements                                                     |
| getScopesFromToken | `true`   | Resolves to an array of OAuth scopes that the provided token supports                                                                                                               |
| securityName       | `false`  | `OpenAPI` Security scheme name to be secured                                                                                                                                        |
| verifyOptions      | `false`  | `jsonwebtoken` verification options. See the [jsonwebtoken documentation](https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) for details |
| tryRefreshTokens   | `false`  | Performs a token refresh. Resolves to `true` if the refressh succeeded otherwise `false`. By default this always resolves to `false`                                                |

## Example

An example implementation of using the OAuth client-credential flow to authenticate a machine-to-machine (m2m) API is included in the package repository. This consists of two parts, a pre-configured `Keycloak` instance which can be instantiated with `docker compose` to act as our identity provider and an example application under [./example](./example) which implements to `tsoa` server. For further information please see the [tsoa authentication documentation](https://tsoa-community.github.io/docs/authentication.html) and our authentication handler example at [./example/authentication.ts](./example/authentication.ts).

To get started first bring up the `Keycloak` instance by executing from the repository root:

```sh
docker compose up -d
```

This will automatically pre-configure a client called `example` with client secret `example`. We can then fetch a m2m token by executing:

```sh
curl --request POST \
  --url 'http://localhost:3080/realms/example/protocol/openid-connect/token' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=client_credentials \
  --data client_id=example \
  --data client_secret=example
```

This will return a JSON object with a JWT auth token in the `access_token` property that takes the form like `eyJhbGci...r8TIOfRQ`.

The example server can then be run with:

```sh
npm run example
```

This server listens on port 3000 and exposes two routes `/authenticated` and `/unauthenticated` where only the first route requires an auth token. So we can for example call

```sh
curl http://localhost:3000/unauthenticated
```

which should return something like

```json
{ "message": "This route is unauthenticated", "authenticated": false }
```

But calling the authenticated route (`curl http://localhost:3000/authenticated`) in the same was will return an error

```json
{ "message": "unauthenticated" }
```

Providing the JWT auth token as part of an authentication header:

```sh
curl http://localhost:3000/authenticated --header 'authorization: bearer eyJhbGci...r8TIOfRQ'
```

causes the call to succeed:

```json
{ "message": "This route is authenticated", "authenticated": true }
```
