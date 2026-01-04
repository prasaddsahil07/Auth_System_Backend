import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
    ) { }

    async register(email: string, password: string) {
        const hash = await bcrypt.hash(password, 10);
        return this.prisma.user.create({
            data: { email, password: hash },
        });
    }

    async login(dto, req) {
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (!user || !(await bcrypt.compare(dto.password, user.password))) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const sessionId = randomUUID();

        const refreshToken = this.jwt.sign(
            { sub: user.id, sid: sessionId },
            { secret: process.env.JWT_REFRESH_SECRET, expiresIn: parseInt(process.env.REFRESH_TOKEN_EXPIRES || '86400') }
        );

        const refreshHash = await bcrypt.hash(refreshToken, 10);

        await this.prisma.session.create({
            data: {
                id: sessionId,
                userId: user.id,
                refreshTokenHash: refreshHash,
                deviceType: dto.deviceType,
                deviceName: req.headers['user-agent'],
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
            },
        });

        const accessToken = this.jwt.sign(
            { sub: user.id, sid: sessionId },
            { secret: process.env.JWT_ACCESS_SECRET, expiresIn: parseInt(process.env.ACCESS_TOKEN_EXPIRES || '3600') }
        );

        return { accessToken, refreshToken };
    }

    async logout(userId: string, sessionId: string) {
        await this.prisma.session.update({
            where: { id: sessionId },
            data: {
                isRevoked: true,
                logoutAt: new Date(),
            },
        });
    }

    async logoutAll(userId: string) {
        await this.prisma.session.updateMany({
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

    async refreshTokens(userId: string, sessionId: string, refreshToken: string) {
        const session = await this.prisma.session.findUnique({
            where: { id: sessionId },
        });

        if (!session || session.isRevoked || session.logoutAt) {
            throw new UnauthorizedException('Session expired or revoked');
        }

        const isValid = await bcrypt.compare(
            refreshToken,
            session.refreshTokenHash,
        );

        if (!isValid) {
            // Token reuse detected → revoke session
            await this.prisma.session.update({
                where: { id: sessionId },
                data: { isRevoked: true },
            });
            throw new UnauthorizedException('Invalid refresh token');
        }

        // ROTATE refresh token
        const newRefreshToken = this.jwt.sign(
            { sub: userId, sid: sessionId },
            {
                secret: process.env.JWT_REFRESH_SECRET, expiresIn: parseInt(process.env.REFRESH_TOKEN_EXPIRES || '86400')
            },
        );

        const newRefreshHash = await bcrypt.hash(newRefreshToken, 10);

        await this.prisma.session.update({
            where: { id: sessionId },
            data: { refreshTokenHash: newRefreshHash },
        });

        const newAccessToken = this.jwt.sign(
            { sub: userId, sid: sessionId },
            {
                secret: process.env.JWT_ACCESS_SECRET, expiresIn: parseInt(process.env.ACCESS_TOKEN_EXPIRES || '3600')
            },
        );

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }
}