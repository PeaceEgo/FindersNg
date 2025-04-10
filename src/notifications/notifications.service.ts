import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Notification } from './schemas/notification.schema';

@Injectable()
export class NotificationsService {
    constructor(
        @InjectModel(Notification.name) private notificationModel: Model<Notification>
    ) { }

    async getUserNotifications(userId: string) {
        const notifications = await this.notificationModel
            .find({ userId })
            .sort({ createdAt: -1 })
            .limit(10)
            .exec();
        return { notifications };
    }

    async createNotification(userId: string, message: string) {
        const notification = await this.notificationModel.create({ userId, message });
        return { notification };
    }
}