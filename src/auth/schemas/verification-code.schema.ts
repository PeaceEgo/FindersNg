import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class VerificationCode extends Document {
    @Prop({ required: true })
    identifier: string; 

    @Prop({ required: true })
    code: string;

    @Prop({ expires: 60 }) 
    createdAt: Date;
}

export const VerificationCodeSchema = SchemaFactory.createForClass(VerificationCode);