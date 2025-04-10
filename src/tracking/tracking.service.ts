import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Tracking } from './schemas/tracking.schema';

@Injectable()
export class TrackingService {
    constructor(
        @InjectModel(Tracking.name) private trackingModel: Model<Tracking>
    ) { }

    async getTrackingStatus(userId: string) {
        let tracking = await this.trackingModel.findOne({ userId });
        if (!tracking) {
            tracking = await this.trackingModel.create({ userId, trackingEnabled: false });
        }
        return {
            trackingEnabled: tracking.trackingEnabled,
            lastLocation: tracking.lastLocation || null,
        };
    }

    async toggleTracking(userId: string, trackingEnabled: boolean) {
        let tracking = await this.trackingModel.findOne({ userId });
        if (!tracking) {
            tracking = await this.trackingModel.create({ userId, trackingEnabled });
        } else {
            tracking.trackingEnabled = trackingEnabled;
            await tracking.save();
        }
        return { message: "Tracking toggled" };
    }
}