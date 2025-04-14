import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
    private transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS,
        },
    });

    async sendVerificationCode(to: string, code: string) {
        const mailOptions = {
            from: `"Find My Device" <${process.env.GMAIL_USER}>`,
            to,
            subject: 'Email Verification Code',
            text: `Your verification code is: ${code}`,
            html: `<p>Your verification code is: <strong>${code}</strong></p>`,
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('Verification email sent:', info.response);
        } catch (error) {
            console.error('Error sending verification email:', error);
            throw error;
        }
    }
}
