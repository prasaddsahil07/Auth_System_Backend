import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => {
          if (!req?.cookies?.access_token) {
            console.log('Access token missing');
            return null;
          }
          return req.cookies.access_token;
        },
      ]),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
    });
  }

  async validate(payload: any) {
    if (!payload?.sub || !payload?.sid) {
      throw new UnauthorizedException('Invalid access token');
    }

    // THIS is what becomes req.user
    return {
      userId: payload.sub,
      sessionId: payload.sid,
    };
  }
}