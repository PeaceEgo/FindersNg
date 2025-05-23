import { Module } from '@nestjs/common';
import { NotificationsController } from './notifications.controller';
import { NotificationsService } from './notifications.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Notification, NotificationSchema } from './schemas/notification.schema';

@Module({
    imports: [
        MongooseModule.forFeature([{ name: Notification.name, schema: NotificationSchema }]),
    ],
    controllers: [NotificationsController],
    providers: [NotificationsService],
})
export class NotificationsModule { }