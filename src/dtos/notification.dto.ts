import { ApiProperty } from '@nestjs/swagger';

export class NotificationDto {
    @ApiProperty({ description: 'The notification ID', example: '12345' })
    _id: string;

    @ApiProperty({ description: 'The user ID', example: '67890' })
    userId: string;

    @ApiProperty({ description: 'The notification message', example: 'Device moved to a new location' })
    message: string;

    @ApiProperty({ description: 'The timestamp of the notification', example: '2025-04-10T12:00:00Z' })
    createdAt: Date;
}