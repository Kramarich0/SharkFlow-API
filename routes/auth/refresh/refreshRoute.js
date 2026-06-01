import { Router } from 'express';
import { createAccessToken } from '#utils/tokens/accessToken.js';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { issueRefreshToken } from '#utils/tokens/refreshToken.js';
import { getRefreshCookieOptions } from '#utils/cookie/refreshCookie.js';
import {
  validateRefreshToken,
  isTokenExpired,
  shouldRotateToken,
} from '#utils/validators/jwtValidators.js';
import {
  logTokenRefresh,
  logTokenRefreshFailure,
  logTokenRefreshAttempt,
} from '#utils/loggers/authLoggers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { createCsrfToken } from '#utils/tokens/csrfToken.js';
import axios from 'axios';
import { parseDeviceInfo } from '#utils/helpers/authHelpers.js';
import { logLocationError } from '#utils/loggers/systemLoggers.js';
import { REFRESH_COOKIE_NAME } from '#config/cookiesConfig.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';

const router = Router();

router.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
  const { ipAddress, userAgent } = getRequestInfo(req);

  const deviceId = req.headers['x-device-id'] || req.ip;

  let userUuidForLog = null;

  try {
    const tokenValidation = refreshToken
      ? validateRefreshToken(refreshToken)
      : null;

    userUuidForLog =
      tokenValidation &&
      tokenValidation.isValid &&
      tokenValidation.payload
        ? tokenValidation.payload.userUuid
        : null;
  } catch {
    // ignore
  }

  logTokenRefreshAttempt(
    userUuidForLog,
    ipAddress,
    userAgent,
    deviceId,
  );

  if (!deviceId) {
    return res.status(401).json({
      message: 'Устройство не найдено',
    });
  }

  if (!refreshToken) {
    return res.status(401).json({
      message: 'Refresh token отсутствует',
    });
  }

  let geoLocation = null;

  try {
    const { data } = await axios.get(`https://ipwho.is/${ipAddress}`, {
      timeout: 10000,
      headers: {
        'x-forwarded-for': ipAddress,
      },
    });

    geoLocation = data;
  } catch (error) {
    logLocationError(ipAddress, error);
  }

  const deviceinfo = parseDeviceInfo(userAgent);

  const tokenValidation = validateRefreshToken(refreshToken);

  if (!tokenValidation.isValid) {
    return res.status(401).json({
      message: tokenValidation.error,
    });
  }

  const { payload } = tokenValidation;
  const userUuid = payload.userUuid;

  try {
    const tokenRecord = await prisma.refreshToken.findFirst({
      where: {
        userId: payload.userUuid,
      },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        revoked: true,
        rememberMe: true,
        deviceSessionId: true,
      },
    });

    if (!tokenRecord || tokenRecord.revoked) {
      logTokenRefreshFailure(
        userUuid,
        ipAddress,
        'Token revoked or not found',
      );

      return res.status(401).json({
        message:
          'Ваша сессия была завершена. Пожалуйста, войдите в систему заново',
      });
    }

    const deviceSession = await prisma.userDeviceSession.findFirst({
      where: {
        userId: tokenRecord.userId,
        isActive: true,
      },
    });

    if (!deviceSession) {
      logTokenRefreshFailure(
        userUuid,
        ipAddress,
        'Device session not found or inactive',
      );

      return res.status(401).json({
        message: 'Сессия устройства неактивна, войдите заново',
      });
    }

    if (tokenRecord.deviceSessionId !== deviceSession.id) {
      logTokenRefreshFailure(
        userUuid,
        ipAddress,
        'Device session mismatch',
      );

      return res.status(401).json({
        message: 'Несоответствие устройства',
      });
    }

    if (isTokenExpired(tokenRecord.expiresAt)) {
      await prisma.refreshToken.update({
        where: {
          id: tokenRecord.id,
        },
        data: {
          revoked: true,
          lastUsedAt: new Date(),
        },
      });

      logTokenRefreshFailure(
        userUuid,
        ipAddress,
        'Token expired',
      );

      return res.status(401).json({
        message:
          'Ваша сессия истекла. Пожалуйста, войдите в систему заново',
      });
    }

    await prisma.userDeviceSession.update({
      where: {
        id: deviceSession.id,
      },
      data: {
        lastUsedAt: new Date(),
        deviceType: deviceinfo.deviceType,
        deviceBrand: deviceinfo.deviceBrand,
        deviceModel: deviceinfo.deviceModel,
        osName: deviceinfo.osName,
        osVersion: deviceinfo.osVersion,
        clientName: deviceinfo.clientName,
        clientVersion: deviceinfo.clientVersion,
        geoLocation: geoLocation,
        userAgent: userAgent,
      },
    });

    await prisma.refreshToken.update({
      where: {
        id: tokenRecord.id,
      },
      data: {
        lastUsedAt: new Date(),
      },
    });

    let rotated = false;
    let newRefreshToken = null;

    if (shouldRotateToken(tokenRecord.expiresAt)) {
      rotated = true;

      newRefreshToken = await issueRefreshToken({
        userUuid,
        rememberMe: tokenRecord.rememberMe,
        userId: tokenRecord.userId,
        deviceSessionId: deviceSession.id,
      });

      await prisma.refreshToken.create({
        data: {
          token: newRefreshToken,
          userId: tokenRecord.userId,
          expiresAt: new Date(
            Date.now() +
              (tokenRecord.rememberMe
                ? Number(process.env.SESSION_EXPIRES_REMEMBER_ME)
                : Number(process.env.SESSION_EXPIRES_DEFAULT)),
          ),
          rememberMe: tokenRecord.rememberMe,
          deviceSessionId: deviceSession.id,
        },
      });

      res.cookie(
        REFRESH_COOKIE_NAME,
        newRefreshToken,
        getRefreshCookieOptions(tokenRecord.rememberMe),
      );

      const activeTokens = await prisma.refreshToken.findMany({
        where: {
          userId: tokenRecord.userId,
        },
        orderBy: {
          createdAt: 'asc',
        },
      });

      const MAX_TOKENS = 10;

      if (activeTokens.length > MAX_TOKENS) {
        const toRevoke = activeTokens.slice(
          0,
          activeTokens.length - MAX_TOKENS,
        );

        const ids = toRevoke.map((t) => t.id);

        await prisma.refreshToken.updateMany({
          where: {
            id: {
              in: ids,
            },
          },
          data: {
            revoked: true,
          },
        });
      }
    }

    const user = await prisma.user.findFirst({
      where: {
        uuid: userUuid,
        isDeleted: false,
      },
      select: {
        role: true,
      },
    });

    if (!user) {
      return res.status(401).json({
        message: 'Пользователь не найден',
      });
    }

    const newAccessToken = createAccessToken(
      userUuid,
      user.role,
    );

    const newCsrfToken = createCsrfToken(
      userUuid,
      user.role,
    );

    logTokenRefresh(
      userUuid,
      ipAddress,
      rotated,
    );

    return res.status(200).json({
      accessToken: newAccessToken,
      csrfToken: newCsrfToken,
      role: user.role,
    });
  } catch (error) {
    logTokenRefreshFailure(
      userUuidForLog,
      ipAddress,
      'Server error',
    );

    if (!res.headersSent) {
      if (error.message === 'Пользователь не найден') {
        return res.status(401).json({
          message:
            'Пользователь не найден. Пожалуйста, войдите в систему заново',
        });
      }

      handleRouteError(res, error, {
        logPrefix: 'Ошибка при обновлении токена',
        status: 500,
        message: 'Произошла внутренняя ошибка сервера',
      });
    }
  }
});

export default {
  path: '/',
  router,
};
