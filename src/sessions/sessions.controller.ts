import {
  Controller,
  Get,
  Delete,
  Param,
  UseGuards,
} from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { JwtAuthGuard } from '../common/guards/jwt.guard';
import { GetUser } from '../common/decorators/get-user.decorator';

@Controller('sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private sessions: SessionsService) {}

  @Get('history')
  getHistory(@GetUser('userId') userId: string) {
    return this.sessions.getHistory(userId);
  }

  @Get('active')
  getActive(@GetUser('userId') userId: string) {
    return this.sessions.getActiveSessions(userId);
  }

  @Get('current')
  getCurrent(@GetUser('userId') userId: string, @GetUser('sessionId') sessionId: string) {
    return { sessionId };
  }

  @Get()
  getAll(@GetUser('userId') userId: string) {
    return this.sessions.getActiveSessions(userId);
  }

  @Delete(':id')
  revokeSession(
    @GetUser('userId') userId: string,
    @Param('id') sessionId: string,
  ) {
    return this.sessions.revokeSession(userId, sessionId);
  }
}