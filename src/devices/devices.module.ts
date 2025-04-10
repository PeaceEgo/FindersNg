import { Module } from '@nestjs/common';
import { DevicesController } from './devices.controller';
import { DevicesService } from './devices.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Device, DeviceSchema } from './schemas/device.schema';
import { Location, LocationSchema } from './schemas/location.schema';
import { LocationHistory, LocationHistorySchema } from './schemas/location-history.schema';

@Module({
    imports: [
        MongooseModule.forFeature([
            { name: Device.name, schema: DeviceSchema },
            { name: Location.name, schema: LocationSchema },
            { name: LocationHistory.name, schema: LocationHistorySchema },
        ]),
    ],
    controllers: [DevicesController],
    providers: [DevicesService],
})
export class DevicesModule { }