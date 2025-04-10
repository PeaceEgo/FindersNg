import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { Location, LocationSchema } from '../../devices/schemas/location.schema';
@Schema({ timestamps: true })
export class Tracking extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop({ default: false })
    trackingEnabled: boolean;

    @Prop({type: LocationSchema })
    lastLocation: { latitude: number; longitude: number };
}

export const TrackingSchema = SchemaFactory.createForClass(Tracking);