import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
    @ApiProperty({ description: 'The user’s email address', example: 'test@example.com' })
    email?: string;

    @ApiProperty({ description: 'The user’s userName', example: 'John' })
    userName: string;
}