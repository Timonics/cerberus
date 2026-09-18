import { Injectable } from '@nestjs/common';
import { Clock } from '../../domain/clock/clock.port';

/**
 * Default Clock adapter.
 *
 * Wraps `new Date()` so production code never imports `Date` directly.
 * Tests can replace this with a fake that returns fixed values.
 */
@Injectable()
export class SystemClock implements Clock {
  public now(): Date {
    return new Date();
  }
}
