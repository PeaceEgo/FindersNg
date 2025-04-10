import { Controller, Get, Post, Body, Req, UnauthorizedException, BadRequestException, UseGuards } from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { NotificationDto } from '../dtos/notification.dto';

@ApiTags('Notifications')
@Controller('notifications')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT')
export class NotificationsController {
    constructor(private notificationsService: NotificationsService) { }

    @Get()
    @ApiOperation({ summary: 'Get all notifications for the user' })
    @ApiResponse({ status: 200, description: 'Notifications retrieved successfully', type: [NotificationDto] })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async getUserNotifications(@Req() req: Request) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        return this.notificationsService.getUserNotifications(user.userId);
    }

    @Post()
    @ApiOperation({ summary: 'Create a new notification for the user' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Device moved to a new location' },
            },
            required: ['message'],
        },
    })
    @ApiResponse({ status: 200, description: 'Notification created successfully', type: NotificationDto })
    @ApiResponse({ status: 400, description: 'Message is required' })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async createNotification(
        @Body('message') message: string,
        @Req() req: Request
    ) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        if (!message) {
            throw new BadRequestException("Message is required");
        }
        return this.notificationsService.createNotification(user.userId, message);
    }
}