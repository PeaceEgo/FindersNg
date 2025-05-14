import { Controller, Get, Post, Body, Req, UnauthorizedException, BadRequestException, UseGuards } from '@nestjs/common';
import { TrackingService } from './tracking.service';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { LocationDto } from '../dtos/location.dto';

interface JwtPayload {
    userId: string;
    email: string;
    firstName: string;
}

@ApiTags('Tracking')
@Controller('tracking')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT')
export class TrackingController {
    constructor(private trackingService: TrackingService) { }

    @Get('status')
    @ApiOperation({ summary: 'Get the tracking status for the user' })
    @ApiResponse({
        status: 200,
        description: 'Tracking status retrieved successfully',
        schema: {
            type: 'object',
            properties: {
                trackingEnabled: { type: 'boolean', example: true },
                lastLocation: {
                    type: 'object',
                    properties: {
                        latitude: { type: 'number', example: 37.7749 },
                        longitude: { type: 'number', example: -122.4194 },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async getTrackingStatus(@Req() req: Request) {
        const user = req.user as JwtPayload;
        if (!user || !user.userId) {
            throw new UnauthorizedException('Not authenticated');
        }
        return this.trackingService.getTrackingStatus(user.userId);
    }

    @Post('toggle')
    @ApiOperation({ summary: 'Toggle tracking on or off for the user' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                trackingEnabled: { type: 'boolean', example: true },
            },
            required: ['trackingEnabled'],
        },
    })
    @ApiResponse({ status: 200, description: 'Tracking toggled' })
    @ApiResponse({ status: 400, description: 'Invalid trackingEnabled value' })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async toggleTracking(@Req() req: Request, @Body('trackingEnabled') trackingEnabled: boolean) {
        if (typeof trackingEnabled !== 'boolean') {
            throw new BadRequestException('trackingEnabled must be a boolean');
        }
        const user = req.user as JwtPayload;
        if (!user || !user.userId) {
            throw new UnauthorizedException('Not authenticated');
        }
        return this.trackingService.toggleTracking(user.userId, trackingEnabled);
    }
}