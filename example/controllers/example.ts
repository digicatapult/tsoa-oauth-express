import { Controller, Get, Route, Security, SuccessResponse } from 'tsoa'

@Security('oauth2')
@Route('/authenticated')
export class AuthenticatedController extends Controller {
  @SuccessResponse(200)
  @Get('/')
  public async get() {
    return {
      message: 'This route is authenticated',
      authenticated: true,
    }
  }
}

@Route('/unauthenticated')
export class UnauthenticatedController extends Controller {
  @SuccessResponse(200)
  @Get('/')
  public async get() {
    return {
      message: 'This route is unauthenticated',
      authenticated: false,
    }
  }
}
