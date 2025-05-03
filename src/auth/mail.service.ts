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

    constructor() {
        console.log('Gmail User:', process.env.GMAIL_USER);
        console.log('Gmail Pass:', process.env.GMAIL_PASS ? '[REDACTED]' : undefined);
        this.transporter.verify((error, success) => {
            if (error) {
                console.error('SMTP verification failed:', error);
            } else {
                console.log('SMTP transporter is ready');
            }
        });
    }

    async sendVerificationCode(to: string, code: string) {
        const mailOptions = {
            from: `"Find My Device" <${process.env.GMAIL_USER}>`,
            to,
            subject: 'Email Verification Code',
            text: `Your verification code is: ${code}`,
            html: `<p>Your verification code is: <strong>${code}</strong></p>`,
            replyTo: process.env.GMAIL_USER,
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('Verification email sent:', JSON.stringify(info, null, 2));
            return { message: 'Verification code sent', messageId: info.messageId };
        } catch (error) {
            console.error('Error sending verification email:', error);
            throw new Error(`Failed to send verification email: ${error.message}`);
        }
    }
}