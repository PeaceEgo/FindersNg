import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
    @ApiProperty({ description: 'The user’s email address', example: 'test@example.com' })
    email?: string;

    @ApiProperty({ description: 'The user’s phone number', example: '+1234567890' })
    phoneNumber?: string;

    @ApiProperty({ description: 'The user’s first name', example: 'John' })
    firstName: string;
}