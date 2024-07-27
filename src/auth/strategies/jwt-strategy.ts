import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: `${process.env.SECRET_KEY}`,
    });
  }

  // Payload contains the decoded token information

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }

  /* The validate method processes the payload (e.g., extracting user information) 
     and returns an object that will be attached to the req.user property 
  */
}
