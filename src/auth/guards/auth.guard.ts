import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/pwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor( 
    private jwtService: JwtService,
    private authService : AuthService,
  ) { }
  
  async canActivate( context: ExecutionContext ):  Promise<boolean> {
    //return true;
    const request = context.switchToHttp().getRequest();
    //console.log( { request } );
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException( 'There is no beaser token' );
    }
    //console.log( { token } );
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED, }
      );
      //console.log( { payload } );
      const user = await this.authService.findUserById( payload.id );
      if ( !user ) throw new UnauthorizedException( 'User does not exists' );
      // 💡 We're assigning the payload to the request object here
      // so that we can access it in our route handlers
      //request['user'] = payload;
      if ( !user.isActive ) throw new UnauthorizedException( 'User not active' );
      request['user'] = user;
    } catch ( error ){
      throw new UnauthorizedException();
    }
    //return Promise.resolve(true);
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers[ 'authorization' ]?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

}
