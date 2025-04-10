import { ApiProperty } from '@nestjs/swagger';
import { LocationDto } from './location.dto';

export class LocationHistoryDto {
    @ApiProperty({ description: 'The location history ID', example: '12345' })
    _id: string;

    @ApiProperty({ description: 'The device ID', example: '67890' })
    deviceId: string;

    @ApiProperty({ description: 'The location data' })
    location: LocationDto;

    @ApiProperty({ description: 'The address of the location', example: '123 Main St' })
    address: string;

    @ApiProperty({ description: 'The timestamp of the location update', example: '2025-04-10T12:00:00Z' })
    createdAt: Date;
}