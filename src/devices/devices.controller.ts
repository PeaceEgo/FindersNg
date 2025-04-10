import { Controller, Get, Post, Param, Body, Req, UnauthorizedException, BadRequestException, UseGuards } from '@nestjs/common';
import { DevicesService } from './devices.service';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import { DeviceDto } from '../dtos/device.dto';
import { LocationHistoryDto } from '../dtos/location-history.dto';

@ApiTags('Devices')
@Controller('devices')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT')
export class DevicesController {
    constructor(private devicesService: DevicesService) { }

    @Post('add')
    @ApiOperation({ summary: 'Add a new device for the user' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                name: { type: 'string', example: 'My Phone' },
            },
            required: ['name'],
        },
    })
    @ApiResponse({ status: 200, description: 'Device added successfully', type: DeviceDto })
    @ApiResponse({ status: 400, description: 'Device name is required' })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async addDevice(
        @Body('name') name: string,
        @Req() req: Request
    ) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        if (!name) {
            throw new BadRequestException("Device name is required");
        }
        return this.devicesService.addDevice(user.userId, name);
    }

    @Get()
    @ApiOperation({ summary: 'Get all devices for the user' })
    @ApiResponse({ status: 200, description: 'Devices retrieved successfully', type: [DeviceDto] })
    @ApiResponse({ status: 401, description: 'Not authenticated' })
    async getUserDevices(@Req() req: Request) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        return this.devicesService.getUserDevices(user.userId);
    }

    @Get(':deviceId/location-history')
    @ApiOperation({ summary: 'Get location history for a device' })
    @ApiParam({ name: 'deviceId', description: 'The ID of the device', example: '12345' })
    @ApiResponse({ status: 200, description: 'Location history retrieved successfully', type: [LocationHistoryDto] })
    @ApiResponse({ status: 401, description: 'Device not found or not authorized' })
    async getLocationHistory(@Param('deviceId') deviceId: string, @Req() req: Request) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        return this.devicesService.getLocationHistory(deviceId, user.userId);
    }

    @Post(':deviceId/update-location')
    @ApiOperation({ summary: 'Update the location of a device' })
    @ApiParam({ name: 'deviceId', description: 'The ID of the device', example: '12345' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                latitude: { type: 'number', example: 37.7749 },
                longitude: { type: 'number', example: -122.4194 },
            },
            required: ['latitude', 'longitude'],
        },
    })
    @ApiResponse({ status: 200, description: 'Location updated successfully' })
    @ApiResponse({ status: 400, description: 'Latitude and longitude must be numbers' })
    @ApiResponse({ status: 401, description: 'Device not found or not authorized' })
    async updateLocation(
        @Param('deviceId') deviceId: string,
        @Body('latitude') latitude: number,
        @Body('longitude') longitude: number,
        @Req() req: Request
    ) {
        const user = req.user as any;
        if (!user) {
            throw new UnauthorizedException("Not authenticated");
        }
        if (typeof latitude !== 'number' || typeof longitude !== 'number') {
            throw new BadRequestException("Latitude and longitude must be numbers");
        }
        return this.devicesService.updateLocation(deviceId, user.userId, latitude, longitude);
    }
}