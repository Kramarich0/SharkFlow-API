import { Router } from 'express';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import {
  logLogout,
  logLogoutInvalidToken,
  logLogoutAttempt,
  logLogoutFailure,
} from '#utils/loggers/authLoggers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { REFRESH_COOKIE_NAME } from '#config/cookiesConfig.js';

const router = Router();

/**
 * POST route to terminate all active refresh token sessions and device sessions for the authenticated user.
 * 
 * @param {import('express').Request} req - The Express request object containing user authentication context and cookies.
 * @param {import('express').Response} res - The Express response object used to clear cookies and send the response.
 * @returns {Promise<void>} Resolves when the operation is complete or an error is handled.
 */
router.post('/auth/logout/all', authenticateMiddleware, async (req, res) => {
  const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
  const userUuid = req.userUuid;
  const { ipAddress } = getRequestInfo(req);

  logLogoutAttempt(userUuid, ipAddress, '', 'all');

  if (!refreshToken) {
    logLogoutFailure(userUuid, ipAddress, 'Refresh token отсутствует', '', 'all');
    return res.status(204).send();
  }

  try {
    const tokenRecord = await prisma.refreshToken.findFirst({
      where: {
        token: refreshToken,
        user: { uuid: userUuid },
        revoked: false,
      },
      select: {
        id: true,
        userId: true,
        user: {
          select: {
            login: true,
            email: true,
          },
        },
      },
    });

    if (tokenRecord) {
      await prisma.refreshToken.updateMany({
        where: {
          userId: tokenRecord.userId,
          revoked: false,
        },
        data: { revoked: true },
      });

      await prisma.userDeviceSession.updateMany({
        where: { userId: tokenRecord.userId, isActive: true },
        data: { isActive: false },
      });

      logLogout(
        tokenRecord.user.login,
        tokenRecord.user.email,
        userUuid,
        ipAddress,
      );
    } else {
      logLogoutInvalidToken(userUuid, ipAddress);
    }

    res.clearCookie(REFRESH_COOKIE_NAME, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    });

    return res
      .status(200)
      .json({ message: 'Вы успешно вышли со всех устройств' });
  } catch (error) {
    handleRouteError(res, error, {
      logPrefix: 'Ошибка при выходе из всех устройств',
      status: 500,
      message: 'Произошла ошибка при выходе из всех устройств',
    });
  }
});

export default {
  path: '/',
  router,
};
