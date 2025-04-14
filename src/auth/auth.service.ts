import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { VerificationCode } from './schemas/verification-code.schema';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { MailService } from './mail.service';

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

        
        await this.codeModel.deleteMany({ identifier: email });

        await this.codeModel.create({ identifier: email, code });
        await this.mailService.sendVerificationCode(email, code);

        return { message: "Verification code sent" };
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
            token
        };
    }

    async sendWhatsAppCode(phoneNumber: string) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        await this.codeModel.deleteMany({ identifier: phoneNumber });
        await this.codeModel.create({ identifier: phoneNumber, code });

        if (process.env.NODE_ENV !== 'production') {
            console.log(`Verification code for ${phoneNumber}: ${code}`);
        }

        // Replace this with WhatsApp API integration in production
        return { message: "Verification code sent" };
    }

    async verifyWhatsAppCode(phoneNumber: string, code: string, firstName: string) {
        const verification = await this.codeModel.findOne({ identifier: phoneNumber, code });
        if (!verification) {
            throw new UnauthorizedException("Invalid verification code");
        }

        await this.codeModel.deleteOne({ _id: verification._id });

        let user = await this.userModel.findOne({ phoneNumber });
        if (!user) {
            user = await this.userModel.create({
                phoneNumber,
                firstName: firstName || "User"
            });
        }

        const payload = { userId: user._id, phoneNumber: user.phoneNumber, firstName: user.firstName };
        const token = this.jwtService.sign(payload, { expiresIn: '7d' });

        return {
            message: "WhatsApp verification successful",
            user: { phoneNumber: user.phoneNumber, firstName: user.firstName },
            token
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
                firstName: name?.split(" ")[0] || "User"
            });
        }

        const jwtPayload = { userId: user._id, email: user.email, firstName: user.firstName };
        const jwtToken = this.jwtService.sign(jwtPayload, { expiresIn: '7d' });

        return {
            message: "Google sign-in successful",
            user: { email: user.email, firstName: user.firstName },
            token: jwtToken
        };
    }

    async getUserFromToken(token: string) {
        const payload = this.jwtService.verify(token);
        const user = await this.userModel.findById(payload.userId);

        if (!user) {
            throw new UnauthorizedException("User not found");
        }

        return {
            email: user.email,
            phoneNumber: user.phoneNumber,
            firstName: user.firstName
        };
    }
}
