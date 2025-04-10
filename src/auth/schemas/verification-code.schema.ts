import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class VerificationCode extends Document {
    @Prop({ required: true })
    identifier: string; // email or phoneNumber

    @Prop({ required: true })
    code: string;

    @Prop({ expires: 600 }) // Expire after 10 minutes
    createdAt: Date;
}

export const VerificationCodeSchema = SchemaFactory.createForClass(VerificationCode);