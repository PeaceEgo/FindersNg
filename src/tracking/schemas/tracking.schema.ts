import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Tracking extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop({ default: false })
    trackingEnabled: boolean;

    @Prop({ type: { latitude: Number, longitude: Number }, default: null })
    lastLocation: { latitude: number; longitude: number } | null;
}

export const TrackingSchema = SchemaFactory.createForClass(Tracking);