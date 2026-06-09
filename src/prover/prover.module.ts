import { Module } from '@nestjs/common';
import { ProverController } from './prover.controller';
import { ProverService } from './prover.service';

@Module({
  controllers: [ProverController],
  providers: [ProverService],
})
export class ProverModule {}
