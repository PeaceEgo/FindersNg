import { Module } from '@nestjs/common';
import { TrackingController } from './tracking.controller';
import { TrackingService } from './tracking.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Tracking, TrackingSchema } from './schemas/tracking.schema';

@Module({
    imports: [
        MongooseModule.forFeature([{ name: Tracking.name, schema: TrackingSchema }]),
    ],
    controllers: [TrackingController],
    providers: [TrackingService],
})
export class TrackingModule { }