import { Module } from '@nestjs/common';
import { UserController } from './auth.controller';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import { VerificationCode, VerificationCodeSchema } from './schemas/verification-code.schema';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { MailService } from './mail.service';

@Module({
    imports: [
        MongooseModule.forFeature([
            { name: User.name, schema: UserSchema },
            { name: VerificationCode.name, schema: VerificationCodeSchema },
        ]),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
            secret: process.env.JWT_SECRET,
            signOptions: { expiresIn: '1h' },
        }),
    ],
    controllers: [UserController],
    providers: [AuthService, JwtStrategy,MailService],
    exports: [JwtStrategy, PassportModule],

  
   
  
})
export class AuthModule { }