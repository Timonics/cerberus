/**
 * EngagementAuditLogHandler — contract tests.
 *
 * Pins that the four engagement event types get recorded as audit
 * rows when their events fire. The handler is a cross-context
 * subscriber; we mock the EventBus and RecordAuditEventUseCase.
 */

import { EngagementAuditLogHandler } from './engagement-audit-log.handler';
import {
  EmailVerificationConsumed,
  EmailVerificationRequested,
  PasswordResetConsumed,
  PasswordResetRequested,
} from '../../domain/events/engagement.events';
import { RecordAuditEventUseCase } from '../use-cases/record-audit-event.use-case';
import { EventBus } from '../../../shared/domain';

class FakeBus {
  public readonly handlers: Map<string, Array<(e: unknown) => Promise<void>>> =
    new Map();

  public async publishAll(events: ReadonlyArray<unknown>): Promise<void> {
    for (const event of events) {
      const name = (event as { eventName: string }).eventName;
      const handlers = this.handlers.get(name) ?? [];
      for (const h of handlers) await h(event);
    }
  }

  public subscribe(name: string, handler: (e: unknown) => Promise<void>): void {
    const list = this.handlers.get(name) ?? [];
    list.push(handler);
    this.handlers.set(name, list);
  }
}

describe('EngagementAuditLogHandler', () => {
  let bus: FakeBus;
  let recordAudit: jest.Mock;
  let handler: EngagementAuditLogHandler;

  beforeEach(() => {
    bus = new FakeBus();
    recordAudit = jest.fn().mockResolvedValue(undefined);
    // The handler only calls recordAuditEventUc.execute(input). A
    // plain jest.fn cast to the same shape works because we never
    // call any other method on the use-case.
    handler = new EngagementAuditLogHandler(
      bus as unknown as EventBus,
      { execute: recordAudit } as unknown as RecordAuditEventUseCase,
    );
    handler.onModuleInit();
  });

  it('subscribes to all four engagement event types', () => {
    expect(bus.handlers.has('engagement.email_verification.requested')).toBe(
      true,
    );
    expect(bus.handlers.has('engagement.email_verification.completed')).toBe(
      true,
    );
    expect(bus.handlers.has('engagement.password_reset.requested')).toBe(true);
    expect(bus.handlers.has('engagement.password_reset.completed')).toBe(true);
  });

  it('writes engagement.email_verification.requested on publish', async () => {
    const ev = new EmailVerificationRequested(
      'ev-1',
      new Date(),
      'user-1',
      'verif-1',
      'plaintext-not-logged',
    );
    await bus.publishAll([ev]);
    expect(recordAudit).toHaveBeenCalledWith({
      userId: 'user-1',
      eventId: 'ev-1',
      eventType: 'engagement.email_verification.requested',
      payload: { verificationId: 'verif-1' },
    });
  });

  it('writes engagement.email_verification.completed on publish', async () => {
    const ev = new EmailVerificationConsumed(
      'ev-1',
      new Date(),
      'user-1',
      'verif-1',
    );
    await bus.publishAll([ev]);
    expect(recordAudit).toHaveBeenCalledWith({
      userId: 'user-1',
      eventId: 'ev-1',
      eventType: 'engagement.email_verification.completed',
      payload: { verificationId: 'verif-1' },
    });
  });

  it('writes engagement.password_reset.requested on publish', async () => {
    const ev = new PasswordResetRequested(
      'ev-1',
      new Date(),
      'user-1',
      'reset-1',
      'plaintext-not-logged',
    );
    await bus.publishAll([ev]);
    expect(recordAudit).toHaveBeenCalledWith({
      userId: 'user-1',
      eventId: 'ev-1',
      eventType: 'engagement.password_reset.requested',
      payload: { resetId: 'reset-1' },
    });
  });

  it('writes engagement.password_reset.completed on publish', async () => {
    const ev = new PasswordResetConsumed(
      'ev-1',
      new Date(),
      'user-1',
      'reset-1',
    );
    await bus.publishAll([ev]);
    expect(recordAudit).toHaveBeenCalledWith({
      userId: 'user-1',
      eventId: 'ev-1',
      eventType: 'engagement.password_reset.completed',
      payload: { resetId: 'reset-1' },
    });
  });

  it('audit failures are caught and logged, not thrown', async () => {
    recordAudit.mockRejectedValueOnce(new Error('boom'));
    const ev = new EmailVerificationRequested(
      'ev-1',
      new Date(),
      'user-1',
      'verif-1',
      'plaintext',
    );
    // The publish path must not reject even if the audit write fails.
    await expect(bus.publishAll([ev])).resolves.toBeUndefined();
  });
});
