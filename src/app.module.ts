import { Module } from '@nestjs/common';
import { ProverModule } from './prover/prover.module';

@Module({
  imports: [ProverModule],
})
export class AppModule {}
