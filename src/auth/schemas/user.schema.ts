import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export interface User extends Document {
    _id: string;
    userName: string;
    email?: string;
    googleId?: string;
}

@Schema({ timestamps: true })
export class User extends Document {
    declare _id: string;

    @Prop({ required: true })
    userName: string;

    @Prop({ unique: true, sparse: true })
    email?: string;

    @Prop({ unique: true, sparse: true })
    googleId?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);