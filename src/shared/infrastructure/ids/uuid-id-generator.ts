import { Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { IdGenerator } from '../../domain/ids/id-generator.port';

/**
 * Default ID generator.
 *
 * Uses Node's built-in `crypto.randomUUID()` which produces RFC 4122 v4
 * UUIDs. These are the IDs every aggregate in the system uses (the
 * database `String @id @default(uuid())` columns match).
 *
 * Why UUIDs and not nanoid? Consistency with the DB schema. The
 * `EntityId.assertUuid` validator accepts only UUIDs, so any non-UUID
 * generator would fail validation downstream.
 */
@Injectable()
export class UuidIdGenerator implements IdGenerator {
  public generate(): string {
    return randomUUID();
  }
}
