import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
    @Prop({ required: true })
    firstName: string;

    @Prop()
    email: string;

    @Prop()
    phoneNumber: string;

    @Prop()
    googleId: string;
}

export const UserSchema = SchemaFactory.createForClass(User);