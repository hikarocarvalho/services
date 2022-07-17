import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { auth } from 'express-oauth2-jwt-bearer';
import { promisify } from 'node:util';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  private AUTH0_AUDIENCE: string;
  private AUTH0_ISSUER: string;

  constructor(private configService: ConfigService) {
    this.AUTH0_AUDIENCE = this.configService.get('AUTH_AUDIENCE') ?? '';
    this.AUTH0_ISSUER = this.configService.get('AUTH0_ISSUER') ?? '';
  }

  async canActivate( context: ExecutionContext): Promise<boolean> {
    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest();
    const res = httpContext.getResponse();

    const checkJWT = promisify (
      auth({
        audience: this.AUTH0_AUDIENCE,
        issuerBaseURL: this.AUTH0_ISSUER,
      }),
    );

    try {
      await checkJWT(req,res);
      return true;
    }catch {
      throw new UnauthorizedException();
    }
  }
}


