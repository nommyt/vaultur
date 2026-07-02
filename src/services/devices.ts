import { and, eq } from 'drizzle-orm';
import { devices, nowDb, type Db, type Device } from '../db';
import { b64Encode, randomBytes } from '../util';

export function newRefreshToken(): string {
  // vaultwarden: crypto::encode_random_bytes::<64>(BASE64URL)
  return b64Encode(randomBytes(64)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface DeviceLoginData {
  deviceIdentifier: string;
  deviceName: string;
  deviceType: number;
}

export async function getOrCreateDevice(
  db: Db,
  data: DeviceLoginData,
  userUuid: string,
): Promise<{ device: Device; isNew: boolean }> {
  const existing = await db.query.devices.findFirst({
    where: and(eq(devices.uuid, data.deviceIdentifier), eq(devices.userUuid, userUuid)),
  });
  if (existing) return { device: existing, isNew: false };

  const now = nowDb();
  const device: Device = {
    uuid: data.deviceIdentifier,
    createdAt: now,
    updatedAt: now,
    userUuid,
    name: data.deviceName,
    atype: data.deviceType,
    pushUuid: crypto.randomUUID(),
    pushToken: null,
    refreshToken: newRefreshToken(),
    twofactorRemember: null,
  };
  await db.insert(devices).values(device);
  return { device, isNew: true };
}

export async function touchDevice(db: Db, device: Device): Promise<void> {
  await db
    .update(devices)
    .set({ updatedAt: nowDb() })
    .where(and(eq(devices.uuid, device.uuid), eq(devices.userUuid, device.userUuid)));
}

export async function findDeviceByRefreshToken(db: Db, token: string): Promise<Device | undefined> {
  return db.query.devices.findFirst({ where: eq(devices.refreshToken, token) });
}
