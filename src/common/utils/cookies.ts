import { Response } from 'express';

export const setAuthCookies = (
  res: Response,
  accessToken: string,
  refreshToken: string,
) => {
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    sameSite: 'lax',
  });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    sameSite: 'lax',
  });
};