import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response } from 'express';
import { UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtAuthGuard } from '../common/guards/jwt.guard';
import { GetUser } from '../common/decorators/get-user.decorator';

@Controller('auth')
export class AuthController {
    constructor(private auth: AuthService) { }

    @Post('register')
    register(@Body() dto: RegisterDto) {
        return this.auth.register(dto.email, dto.password);
    }

    @Post('login')
    async login(
        @Body() dto: LoginDto,
        @Req() req,
        @Res({ passthrough: true }) res: Response,
    ) {
        const { accessToken, refreshToken } = await this.auth.login(dto, req);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            sameSite: 'lax',
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            sameSite: 'lax',
        });

        return { success: true };
    }

    @Post('logout')
    @UseGuards(JwtAuthGuard)
    async logout(
        @GetUser('userId') userId: string,
        @GetUser('sessionId') sessionId: string,
        @Res({ passthrough: true }) res: Response,
    ) {
        await this.auth.logout(userId, sessionId);

        res.clearCookie('access_token');
        res.clearCookie('refresh_token');

        return { success: true };
    }

    @Post('logout-all')
    @UseGuards(JwtAuthGuard)
    async logoutAll(
        @GetUser('userId') userId: string,
        @Res({ passthrough: true }) res: Response,
    ) {
        await this.auth.logoutAll(userId);

        res.clearCookie('access_token');
        res.clearCookie('refresh_token');

        return { success: true };
    }

    @Post('refresh')
    @UseGuards(AuthGuard('jwt-refresh'))
    async refresh(@Req() req, @Res({ passthrough: true }) res: Response) {
        const { userId, sessionId, refreshToken } = req.user;

        const isProd = process.env.NODE_ENV === 'production';

        const tokens = await this.auth.refreshTokens(
            userId,
            sessionId,
            refreshToken,
        );

        // res.cookie('access_token', tokens.accessToken, {
        //     httpOnly: true,
        //     sameSite: 'lax',
        // });

        res.cookie('access_token', tokens.accessToken, {
            httpOnly: true,
            secure: isProd,          // 🔥 REQUIRED
            sameSite: isProd ? 'none' : 'lax', // 🔥 REQUIRED
            path: '/',
        });

        // res.cookie('refresh_token', tokens.refreshToken, {
        //     httpOnly: true,
        //     sameSite: 'lax',
        // });

        res.cookie('refresh_token', tokens.refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? 'none' : 'lax',
            path: '/',
        });

        return { success: true };
    }

}