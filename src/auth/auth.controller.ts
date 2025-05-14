import { Controller, Post, Body, Get, Req, Res, UnauthorizedException, BadRequestException, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { UserDto } from '../dtos/user.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('email/send-code')
    @ApiOperation({ summary: 'Send a verification code to an email address' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                email: { type: 'string', example: 'test@example.com' },
            },
            required: ['email'],
        },
    })
    @ApiResponse({ status: 200, description: 'Verification code sent' })
    @ApiResponse({ status: 400, description: 'Email is required' })
    async sendEmailCode(@Body('email') email: string) {
        if (!email) {
            throw new BadRequestException('Email is required');
        }
        return this.authService.sendEmailCode(email);
    }

    @Post('email/verify-code')
    @ApiOperation({ summary: 'Verify an email verification code' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                email: { type: 'string', example: 'test@example.com' },
                code: { type: 'string', example: '123456' },
                userName: { type: 'string', example: 'john_doe', nullable: true },
            },
            required: ['email', 'code'],
        },
    })
    @ApiResponse({ status: 200, description: 'Authentication successful', type: UserDto })
    @ApiResponse({ status: 400, description: 'Email and code are required' })
    @ApiResponse({ status: 401, description: 'Invalid verification code' })
    async verifyEmailCode(
        @Body('email') email: string,
        @Body('code') code: string,
        @Body('userName') userName: string,
        @Res({ passthrough: true }) res: Response,
    ) {
        if (!email || !code) {
            throw new BadRequestException('Email and code are required');
        }
        const result = await this.authService.verifyEmailCode(email, code, userName);
        res.cookie('session-token', result.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return { message: result.message, user: result.user };
    }

    @Post('email/login')
    @ApiOperation({ summary: 'Log in with email and username' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                email: { type: 'string', example: 'test@example.com' },
                userName: { type: 'string', example: 'john_doe' },
            },
            required: ['email', 'userName'],
        },
    })
    @ApiResponse({ status: 200, description: 'Login successful or verification code sent', type: UserDto })
    @ApiResponse({ status: 400, description: 'Email and userName are required' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    async loginWithEmail(
        @Body('email') email: string,
        @Body('userName') userName: string,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        if (!email || !userName) {
            throw new BadRequestException('Email and userName are required');
        }
        const token = req.cookies['session-token'];
        const result = await this.authService.loginWithEmail(email, userName, token);
        if (result.token) {
            res.cookie('session-token', result.token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });
        }
        return { message: result.message, user: result.user };
    }

    @Post('email/signup')
    @ApiOperation({ summary: 'Sign up with email and username' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                email: { type: 'string', example: 'test@example.com' },
                userName: { type: 'string', example: 'john_doe' },
            },
            required: ['email', 'userName'],
        },
    })
    @ApiResponse({ status: 200, description: 'Verification code sent' })
    @ApiResponse({ status: 400, description: 'Email and userName are required' })
    async signUpWithEmail(@Body('email') email: string, @Body('userName') userName: string) {
        if (!email || !userName) {
            throw new BadRequestException('Email and userName are required');
        }
        return this.authService.sendEmailCode(email);
    }

    @Get('google/login')
    @ApiOperation({ summary: 'Initiate Google OAuth login' })
    @ApiResponse({ status: 302, description: 'Redirects to Google OAuth page' })
    async googleLogin(@Res() res: Response) {
        const url = await this.authService.getGoogleAuthUrl();
        res.redirect(url);
    }

    @Get('google/callback')
    @ApiOperation({ summary: 'Handle Google OAuth callback' })
    @ApiResponse({ status: 302, description: 'Redirects to dashboard on success' })
    @ApiResponse({ status: 401, description: 'Invalid Google authorization code' })
    async googleCallback(@Query('code') code: string, @Res({ passthrough: true }) res: Response) {
        if (!code) {
            throw new BadRequestException('Authorization code is required');
        }
        const result = await this.authService.googleSignIn(code);
        res.cookie('session-token', result.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.redirect('/dashboard');
    }

    @Post('google')
    @ApiOperation({ summary: 'Sign in with Google OAuth (deprecated)' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                token: { type: 'string', example: 'google-id-token' },
            },
            required: ['token'],
        },
    })
    @ApiResponse({ status: 200, description: 'Google sign-in successful', type: UserDto })
    @ApiResponse({ status: 400, description: 'Token is required' })
    @ApiResponse({ status: 401, description: 'Invalid Google token' })
    async googleSignIn(@Body('token') token: string, @Res({ passthrough: true }) res: Response) {
        if (!token) {
            throw new BadRequestException('Token is required');
        }
        const result = await this.authService.googleSignIn(token);
        res.cookie('session-token', result.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return { message: result.message, user: result.user };
    }

    @Get('verify')
    @ApiOperation({ summary: 'Verify the session token' })
    @ApiResponse({ status: 200, description: 'Token is valid' })
    @ApiResponse({ status: 401, description: 'Invalid token or no token provided' })
    async verifyToken(@Req() req: Request) {
        const token = req.cookies['session-token'];
        if (!token) {
            throw new UnauthorizedException('No token provided');
        }
        return this.authService.verifyToken(token);
    }

    @Post('logout')
    @ApiOperation({ summary: 'Log out the current user' })
    @ApiResponse({ status: 200, description: 'Logged out successfully' })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async logout(@Res({ passthrough: true }) res: Response) {
        const result = await this.authService.logout();
        res.clearCookie('session-token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        return result;
    }
}