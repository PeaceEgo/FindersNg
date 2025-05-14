import { Controller, Get, Req, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UserDto } from '../dtos/user.dto';

@ApiTags('User')
@Controller('user')
export class UserController {
    constructor(private authService: AuthService) { }

    @Get('me')
    @ApiOperation({ summary: 'Get the current user information' })
    @ApiResponse({ status: 200, description: 'User information retrieved', type: UserDto })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async getUser(@Req() req: Request) {
        const token = req.cookies['session-token'];
        if (!token) throw new UnauthorizedException("No token provided");
        return this.authService.getUserFromToken(token);
    }
}