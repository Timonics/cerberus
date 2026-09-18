import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

/**
 * Prisma infrastructure module.
 *
 * Marked `@Global()` so every repository adapter can inject `PrismaService`
 * without each bounded context re-importing this module. This module owns
 * the single PrismaClient lifecycle.
 */
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
