import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SessionsService {
  constructor(private prisma: PrismaService) {}

  getHistory(userId: string) {
    return this.prisma.session.findMany({
      where: { userId },
      orderBy: { loginAt: 'desc' },
    });
  }

  getActiveSessions(userId: string) {
    return this.prisma.session.findMany({
      where: {
        userId,
        isRevoked: false,
        logoutAt: null,
      },
      orderBy: { loginAt: 'desc' },
    });
  }

  async revokeSession(userId: string, sessionId: string) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });

    if (!session || session.userId !== userId) {
      throw new ForbiddenException('Access denied');
    }

    return this.prisma.session.update({
      where: { id: sessionId },
      data: {
        isRevoked: true,
        logoutAt: new Date(),
      },
    });
  }

  async revokeAll(userId: string) {
    return this.prisma.session.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        logoutAt: new Date(),
      },
    });
  }
}