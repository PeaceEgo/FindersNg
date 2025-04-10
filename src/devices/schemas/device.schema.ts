import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { Location, LocationSchema } from './location.schema';

@Schema()
export class Device extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop({ required: true })
    name: string;

    @Prop({ required: true })
    lastSynced: Date;

    @Prop({ type: LocationSchema })
    lastLocation: Location;
}

export const DeviceSchema = SchemaFactory.createForClass(Device);