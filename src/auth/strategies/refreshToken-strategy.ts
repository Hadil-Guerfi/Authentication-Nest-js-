import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refresh'),
      ignoreExpiration: false,
      secretOrKey: `${process.env.SECRET_KEY}`,
    });
  }

  /*
  After the token is extracted, the passport-jwt strategy verifies its validity using the secret key (secretOrKey: process.env.SECRET_KEY).
  If the token is valid, the validate method is called with the decoded payload of the token.
*/

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
  /*The validate method processes the payload (e.g., extracting user information) and returns an object that will be attached to the req.user property */
}
