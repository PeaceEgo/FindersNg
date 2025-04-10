import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { Location, LocationSchema } from './location.schema';

@Schema({ timestamps: true })
export class LocationHistory extends Document {
    @Prop({ required: true })
    deviceId: string;

    @Prop({ type: LocationSchema, required: true })
    location: Location;

    @Prop()
    address: string;
}

export const LocationHistorySchema = SchemaFactory.createForClass(LocationHistory);