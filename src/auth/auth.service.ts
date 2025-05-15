import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { VerificationCode } from './schemas/verification-code.schema';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { MailService } from './mail.service';

@Injectable()
export class AuthService {
    private googleClient = new OAuth2Client({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
    });

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(VerificationCode.name) private codeModel: Model<VerificationCode>,
        private jwtService: JwtService,
        private mailService: MailService,
    ) { }

    async getGoogleAuthUrl(): Promise<string> {
        return this.googleClient.generateAuthUrl({
            scope: ['profile', 'email'],
            prompt: 'consent',
        });
    }

    async sendEmailCode(email: string) {
        if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
            throw new BadRequestException('Invalid email format');
        }
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        try {
            await this.codeModel.deleteMany({ identifier: email });
            await this.codeModel.create({ identifier: email, code });
            await this.mailService.sendVerificationCode(email, code);
            return { message: 'Verification code sent' };
        } catch (error) {
            console.error('Error in sendEmailCode:', error);
            throw new BadRequestException('Failed to send verification code, please try again');
        }
    }

    async verifyEmailCode(email: string, code: string, userName?: string) {
        const verification = await this.codeModel.findOne({ identifier: email, code });
        if (!verification) {
            throw new UnauthorizedException('Invalid verification code');
        }

        await this.codeModel.deleteOne({ _id: verification._id });

        let user = await this.userModel.findOne({ email });
        if (!user) {
            if (!userName) {
                throw new BadRequestException('Username required for new user');
            }
            user = await this.userModel.create({ email, userName });
        } else if (userName && user.userName !== userName) {
            throw new BadRequestException('Username does not match existing user');
        }

        const payload = { userId: user._id, email: user.email, userName: user.userName };
        const token = this.jwtService.sign(payload, { expiresIn: '7d' });

        return {
            message: 'Authentication successful',
            user: { email: user.email, userName: user.userName },
            token,
        };
    }

    async googleSignIn(code: string) {
        try {
            const { tokens } = await this.googleClient.getToken(code);
            const ticket = await this.googleClient.verifyIdToken({
                idToken: tokens.id_token!,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const payload = ticket.getPayload();
            if (!payload) {
                throw new UnauthorizedException('Invalid Google token');
            }

            const { sub: googleId, email, name } = payload;

            let user = await this.userModel.findOne({ googleId });
            if (!user) {
                user = await this.userModel.create({
                    googleId,
                    email,
                    userName: name?.split(' ')[0] || 'User',
                });
            }

            const jwtPayload = { userId: user._id, email: user.email, userName: user.userName };
            const jwtToken = this.jwtService.sign(jwtPayload, { expiresIn: '7d' });

            return {
                message: 'Google sign-in successful',
                user: { email: user.email, userName: user.userName },
                token: jwtToken,
            };
        } catch (error) {
            console.error('Error in googleSignIn:', error);
            throw new UnauthorizedException('Invalid Google authorization code');
        }
    }

    async loginWithEmail(email: string, userName: string, token?: string) {
        try {
            console.log('loginWithEmail called with:', { email, userName, token });
            const user = await this.userModel.findOne({ email });
            if (!user) {
                console.log('User not found for email:', email);
                throw new UnauthorizedException('User not found');
            }
            if (user.userName !== userName) {
                console.log('Invalid username for user:', { email, userName });
                throw new UnauthorizedException('Invalid username');
            }

            if (token) {
                try {
                    const payload = this.jwtService.verify(token);
                    console.log('Token payload:', payload);
                    if (
                        payload.userId === user._id.toString() &&
                        payload.email === user.email &&
                        payload.userName === user.userName
                    ) {
                        const newPayload = { userId: user._id, email: user.email, userName: user.userName };
                        const newToken = this.jwtService.sign(newPayload, { expiresIn: '7d' });
                        console.log('Login successful, new token generated');
                        return {
                            message: 'Login successful',
                            user: { email: user.email, userName: user.userName },
                            token: newToken,
                        };
                    }
                } catch (error) {
                    console.error('Token verification failed:', error.message);
                    // Proceed to send verification code
                }
            }

            console.log('No valid token, sending verification code');
            await this.sendEmailCode(email);
            return { message: 'Verification code sent, please verify to complete login' };
        } catch (error) {
            console.error('Error in loginWithEmail:', error);
            throw error; 
        }
    }
    async getUserFromToken(token: string) {
        const payload = this.jwtService.verify(token);
        const user = await this.userModel.findById(payload.userId);

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return {
            email: user.email,
            userName: user.userName,
        };
    }

    async verifyToken(token: string) {
        try {
            const payload = this.jwtService.verify(token);
            const user = await this.userModel.findById(payload.userId);
            if (!user) {
                throw new UnauthorizedException('User not found');
            }
            return { message: 'Token is valid' };
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
    }

    async logout() {
        return { message: 'Logged out successfully' };
    }
}