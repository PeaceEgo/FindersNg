import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (request) => request?.cookies?.['session-token'],
            ]),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET || (() => {
                throw new Error('JWT_SECRET is not defined in the environment variables');
            })(),
        });
    }

    async validate(payload: any) {
        return { userId: payload.userId, email: payload.email, phoneNumber: payload.phoneNumber, firstName: payload.firstName };
    }
}