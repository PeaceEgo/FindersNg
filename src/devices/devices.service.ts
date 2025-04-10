import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Device } from './schemas/device.schema';
import { Location } from './schemas/location.schema';
import { LocationHistory } from './schemas/location-history.schema';

@Injectable()
export class DevicesService {
    constructor(
        @InjectModel(Device.name) private deviceModel: Model<Device>,
        @InjectModel(LocationHistory.name) private locationHistoryModel: Model<LocationHistory>
    ) { }

    async addDevice(userId: string, name: string) {
        const device = await this.deviceModel.create({
            userId,
            name,
            lastSynced: new Date(),
        });
        return { device };
    }

    async getUserDevices(userId: string) {
        const devices = await this.deviceModel.find({ userId }).exec();
        return { devices };
    }

    async getLocationHistory(deviceId: string, userId: string) {
        const device = await this.deviceModel.findOne({ _id: deviceId, userId }).exec();
        if (!device) {
            throw new UnauthorizedException("Device not found or not authorized");
        }

        const locationHistory = await this.locationHistoryModel
            .find({ deviceId })
            .sort({ createdAt: -1 })
            .limit(10)
            .exec();

        return { locationHistory };
    }

    async updateLocation(deviceId: string, userId: string, latitude: number, longitude: number) {
        const device = await this.deviceModel.findOne({ _id: deviceId, userId }).exec();
        if (!device) {
            throw new UnauthorizedException("Device not found or not authorized");
        }

        // Update the device's last location
        device.lastLocation = { latitude, longitude } as Location;
        device.lastSynced = new Date();
        await device.save();

        // Add to location history
        await this.locationHistoryModel.create({
            deviceId,
            location: { latitude, longitude },
            address: "Unknown Address", // Replace with geocoding in production
        });

        return { message: "Location updated successfully" };
    }
}