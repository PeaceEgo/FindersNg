import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../auth/schemas/user.schema';
import { VerificationCode } from '../auth/schemas/verification-code.schema';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { MailService } from '../auth/mail.service';
import { UserSchema } from 'src/auth/schemas/user.schema';

@Injectable()
export class AuthService {
    private googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(VerificationCode.name) private codeModel: Model<VerificationCode>,
        private jwtService: JwtService,
        private mailService: MailService
    ) { }

    async sendEmailCode(email: string) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        try {
            await this.codeModel.deleteMany({ identifier: email });
            await this.codeModel.create({ identifier: email, code });
            const result = await this.mailService.sendVerificationCode(email, code);
            console.log('sendEmailCode result:', result);
            return { message: "Verification code sent" };
        } catch (error) {
            console.error('Error in sendEmailCode:', error);
            throw new Error('Failed to send verification code');
        }
    }

    async verifyEmailCode(email: string, code: string) {
        const verification = await this.codeModel.findOne({ identifier: email, code });
        if (!verification) {
            throw new UnauthorizedException("Invalid verification code");
        }

        await this.codeModel.deleteOne({ _id: verification._id });

        let user = await this.userModel.findOne({ email });
        if (!user) {
            user = await this.userModel.create({ email, firstName: "User" });
        }

        const payload = { userId: user._id, email: user.email, firstName: user.firstName };
        const token = this.jwtService.sign(payload, { expiresIn: '7d' });

        return {
            message: "Email verification successful",
            user: { email: user.email, firstName: user.firstName },
            token,
        };
    }

    async googleSignIn(token: string) {
        const ticket = await this.googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        if (!payload) {
            throw new UnauthorizedException("Invalid Google token");
        }

        const { sub: googleId, email, name } = payload;

        let user = await this.userModel.findOne({ googleId });
        if (!user) {
            user = await this.userModel.create({
                googleId,
                email,
                firstName: name?.split(" ")[0] || "User",
            });
        }

        const jwtPayload = { userId: user._id, email: user.email, firstName: user.firstName };
        const jwtToken = this.jwtService.sign(jwtPayload, { expiresIn: '7d' });

        return {
            message: "Google sign-in successful",
            user: { email: user.email, firstName: user.firstName },
            token: jwtToken,
        };
    }

    async loginWithEmail(email: string, token?: string) {
        let user = await this.userModel.findOne({ email });
        if (!user) {
            throw new UnauthorizedException("User not found");
        }

        // Check if token is provided and valid
        if (token) {
            try {
                const payload = this.jwtService.verify(token);
                if (payload.userId === user._id && payload.email === user.email) {
                    // Token is valid, generate new token
                    const newPayload = { userId: user._id, email: user.email, firstName: user.firstName };
                    const newToken = this.jwtService.sign(newPayload, { expiresIn: '7d' });
                    return {
                        message: "Login successful",
                        user: { email: user.email, firstName: user.firstName },
                        token: newToken,
                    };
                }
            } catch (error) {
                // Token is invalid or expired, require verification code
            }
        }

        // No valid token, send verification code
        await this.sendEmailCode(email);
        return { message: "Verification code sent, please verify to complete login" };
    }

    async getUserFromToken(token: string) {
        const payload = this.jwtService.verify(token);
        const user = await this.userModel.findById(payload.userId);

        if (!user) {
            throw new UnauthorizedException("User not found");
        }

        return {
            email: user.email,
            firstName: user.firstName,
        };
    }

    async verifyToken(token: string) {
        try {
            const payload = this.jwtService.verify(token);
            const user = await this.userModel.findById(payload.userId);
            if (!user) {
                throw new UnauthorizedException("User not found");
            }
            return { message: "Token is valid" };
        } catch (error) {
            throw new UnauthorizedException("Invalid token");
        }
    }

    async logout() {
        return { message: "Logged out successfully" };
    }
}