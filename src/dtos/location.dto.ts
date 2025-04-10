import { ApiProperty } from '@nestjs/swagger';

export class LocationDto {
    @ApiProperty({ description: 'Latitude coordinate', example: 37.7749 })
    latitude: number;

    @ApiProperty({ description: 'Longitude coordinate', example: -122.4194 })
    longitude: number;
}