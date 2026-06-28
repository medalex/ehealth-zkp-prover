import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { ProverService } from './prover.service';
import { ProveRequestDto } from './dto/prove-request.dto';

@Controller()
export class ProverController {
  constructor(private readonly proverService: ProverService) {}

  @Get('health')
  health() {
    return { status: 'ok' };
  }

  // Proof generation only. Verification is performed on-chain by the Groth16 verifier
  // contract (ehealth-evm); the prover no longer exposes a /verify endpoint.
  @Post('prove')
  @HttpCode(200)
  prove(@Body() dto: ProveRequestDto) {
    return this.proverService.prove(dto);
  }
}
