import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule as PinoLoggerModule } from 'nestjs-pino';
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AppConfig } from '../../config/configuration';

/**
 * Application-wide structured logging.
 *
 * Uses `nestjs-pino` which wraps `pino-http`. Every HTTP request gets a
 * correlation ID (the inbound `X-Request-Id` header if present, otherwise a
 * fresh UUID v4). The ID is echoed back in the response and emitted on every
 * log line tied to the request — critical for tracing one user's journey
 * across the login → MFA → token issuance flow.
 *
 * Secrets are redacted from log output by path. The list below MUST be kept
 * in sync with any new headers / body fields that carry credentials.
 */
@Module({
  imports: [
    PinoLoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const nodeEnv = config.getOrThrow<AppConfig['nodeEnv']>('nodeEnv');
        const logLevel = config.getOrThrow<AppConfig['logLevel']>('logLevel');

        return {
          pinoHttp: {
            level: logLevel,

            // Correlation ID: honour an inbound X-Request-Id, otherwise mint one.
            // Echo it back so callers can correlate their logs with ours.
            genReqId: (req: IncomingMessage, res: ServerResponse) => {
              const raw = req.headers['x-request-id'];
              const id = (Array.isArray(raw) ? raw[0] : raw) ?? randomUUID();
              res.setHeader('x-request-id', id);
              return id;
            },

            // Don't spam logs with every health probe.
            autoLogging: {
              ignore: (req) => {
                const url = req.url ?? '';
                return url === '/health' || url === '/ready';
              },
            },

            // Never let secrets reach the log stream, in any environment.
            // Audit 2026-10-19 H-9: the DTOs send TOTP/recovery codes in
            // `code` / `mfaCode` / `mfa_code` and password changes in
            // `currentPassword` / `newPassword` — all redacted here.
            redact: {
              paths: [
                'req.headers.authorization',
                'req.headers.cookie',
                'req.headers["x-admin-api-key"]',
                'req.body.password',
                'req.body.currentPassword',
                'req.body.newPassword',
                'req.body.code',
                'req.body.mfaCode',
                'req.body.mfa_code',
                'req.body.client_secret',
                'req.body.refresh_token',
                'req.body.token',
                'res.headers["set-cookie"]',
              ],
              censor: '[REDACTED]',
            },

            // Pretty-print only in local development; raw JSON in production.
            transport:
              nodeEnv === 'production'
                ? undefined
                : {
                    target: 'pino-pretty',
                    options: {
                      singleLine: true,
                      colorize: true,
                      translateTime: 'SYS:standard',
                      ignore: 'pid,hostname',
                    },
                  },
          },
        };
      },
    }),
  ],
})
export class AppLoggerModule {}
