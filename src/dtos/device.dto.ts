import { ApiProperty } from '@nestjs/swagger';
import { LocationDto } from './location.dto';

export class DeviceDto {
    @ApiProperty({ description: 'The device ID', example: '12345' })
    _id: string;

    @ApiProperty({ description: 'The user ID', example: '67890' })
    userId: string;

    @ApiProperty({ description: 'The device name', example: 'My Phone' })
    name: string;

    @ApiProperty({ description: 'The last synced date', example: '2025-04-10T12:00:00Z' })
    lastSynced: Date;

    @ApiProperty({ description: 'The last known location of the device' })
    lastLocation?: LocationDto;
}