import { Inject, Injectable } from '@nestjs/common';
import {
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Service } from '../../domain/aggregates/service';
import {
  SERVICE_REPOSITORY,
  ServiceRepository,
} from '../../domain/ports/service.repository.port';

/**
 * List the full service catalog (admin surface). No pagination in V1 —
 * a deployment's catalog is operator-sized, not user-sized.
 */
@Injectable()
export class ListServicesUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SERVICE_REPOSITORY)
    private readonly serviceRepo: ServiceRepository,
  ) {}

  public async execute(): Promise<{ services: ReadonlyArray<Service> }> {
    const services = await this.txRunner.run<ReadonlyArray<Service>>(
      async (tx: Tx) => this.serviceRepo.list(tx),
    );
    return { services };
  }
}
