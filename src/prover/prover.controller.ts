import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { ProverService } from './prover.service';
import { ProveRequestDto } from './dto/prove-request.dto';
import { VerifyRequestDto } from './dto/verify-request.dto';

@Controller()
export class ProverController {
  constructor(private readonly proverService: ProverService) {}

  @Get('health')
  health() {
    return { status: 'ok' };
  }

  @Post('prove')
  @HttpCode(200)
  prove(@Body() dto: ProveRequestDto) {
    return this.proverService.prove(dto);
  }

  @Post('verify')
  @HttpCode(200)
  verify(@Body() dto: VerifyRequestDto) {
    return this.proverService.verify(dto);
  }
}
