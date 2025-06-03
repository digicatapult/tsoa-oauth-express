import fs from 'node:fs/promises'
import path, { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import express, { Express } from 'express'

import { OauthError } from '../src/index.js'
import { RegisterRoutes } from './routes.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

async function run(): Promise<void> {
  const swaggerBuffer = await fs.readFile(path.join(__dirname, './swagger.json'))
  const swaggerJson = JSON.parse(swaggerBuffer.toString('utf8'))

  const app: Express = express()
  app.get('/api-docs', (_req, res) => {
    res.json(swaggerJson)
  })

  RegisterRoutes(app)

  app.use(function errorHandler(
    err: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ): void {
    if (err instanceof OauthError) {
      res.status(401)
      res.send({
        message: 'unauthenticated',
      })
    }
  })

  app.listen(3000, () => {
    console.log('Server listening on port 3000')
  })
}
run()
