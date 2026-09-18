/**
 * DI token for the raw Redis client.
 *
 * The infrastructure layer constructs the ioredis client and binds it to
 * this token. Other code (services, repositories) should depend on
 * `RedisService` (which wraps the client with lifecycle handling) rather
 * than on this raw token.
 */
export const REDIS_CLIENT = Symbol('RedisClient');
