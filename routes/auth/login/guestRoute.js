import { Router } from 'express';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { getGuestCookieOptions } from '#utils/cookie/guestCookie.js';
import { findUserByUuid } from '#utils/helpers/userHelpers.js';
import {
  createAuthTokens,
  setAuthCookies,
  getRequestInfo,
} from '#utils/helpers/authHelpers.js';
import { verifyTurnstileCaptcha } from '#utils/helpers/verifyTurnstileCaptchaHelper.js';
import { generateUUID } from '#utils/generators/generateUUID.js';
import { GUEST_COOKIE_NAME } from '#config/cookiesConfig.js';
import {
  logLoginSuccess,
  logLoginFailure,
  logRegistrationSuccess,
  logSuspiciousAuthActivity,
  logGuestLoginAttempt,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const guestLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 guest login requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Слишком много попыток гостевого входа. Попробуйте позже.',
  },
});

router.post('/auth/guest-login', guestLoginLimiter, async (req, res) => {
  const { ipAddress, userAgent } = getRequestInfo(req);

  // Логгируем попытку гостевого входа
  logGuestLoginAttempt(ipAddress, userAgent);

  if (process.env.NODE_ENV === 'production') {
    const { captchaToken } = req.body;

    if (!captchaToken) {
      return res
        .status(400)
        .json({ error: 'Пожалуйста, подтвердите, что вы не робот!' });
    }

    const turnstileUuid = generateUUID();

    try {
      const captchaSuccess = await verifyTurnstileCaptcha(
        captchaToken,
        ipAddress,
        turnstileUuid,
      );
      if (!captchaSuccess) {
        return res
          .status(400)
          .json({ error: 'Captcha не пройдена. Попробуйте еще раз' });
      }
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }

  try {
    const guestUuid = req.cookies[GUEST_COOKIE_NAME];

    if (guestUuid) {
      const existingGuest = await findUserByUuid(guestUuid);
      if (existingGuest && existingGuest.role === 'guest') {
        const deviceId = req.headers['x-device-id'];
        if (!deviceId) {
          logSuspiciousAuthActivity('guest_login_no_device', guestUuid, ipAddress, 'Нет deviceId');
          return res.status(401).json({ error: 'Устройство не найдено' });
        }
        let deviceSession = await prisma.userDeviceSession.findFirst({
          where: { userId: existingGuest.id, deviceId, isActive: true },
        });
        if (deviceSession) {
          deviceSession = await prisma.userDeviceSession.update({
            where: { id: deviceSession.id },
            data: {
              userAgent,
              ipAddress,
              lastLoginAt: new Date(),
              isActive: true,
            },
          });
        } else {
          deviceSession = await prisma.userDeviceSession.create({
            data: {
              userId: existingGuest.id,
              deviceId,
              userAgent,
              ipAddress,
              lastLoginAt: new Date(),
              isActive: true,
            },
          });
        }
        const tokens = await createAuthTokens(
          existingGuest,
          false,
          deviceSession.id,
        );
        setAuthCookies(res, tokens.refreshToken, false);
        res.cookie(
          GUEST_COOKIE_NAME,
          existingGuest.uuid,
          getGuestCookieOptions(),
        );
        logLoginSuccess('guest', existingGuest.uuid, ipAddress);
        return res.status(200).json({
          accessToken: tokens.accessToken,
          csrfToken: tokens.csrfToken,
          role: existingGuest.role,
        });
      } else if (existingGuest) {
        logSuspiciousAuthActivity('guest_login_not_guest_role', existingGuest.uuid, ipAddress, 'Попытка guest-login с не guest-ролью');
      } else {
        logSuspiciousAuthActivity('guest_login_uuid_not_found', guestUuid, ipAddress, 'guestUuid не найден');
      }
    }

    if (!guestUuid) {
      const { guest, deviceSession } = await prisma.$transaction(async (tx) => {
        const rawUuid = uuidv4();
        const fakeEmail = `guest-${rawUuid}@guest.local`;
        const fakeLogin = `guest-${rawUuid.slice(0, 8)}`;
        const hashedPassword = await bcrypt.hash(rawUuid, 10);
        const guest = await tx.user.create({
          data: {
            email: fakeEmail,
            login: fakeLogin,
            password: hashedPassword,
            role: 'guest',
          },
        });
        const deviceId = req.headers['x-device-id'];
        if (!deviceId) {
          throw new Error('NO_DEVICE');
        }
        let deviceSession = await tx.userDeviceSession.findFirst({
          where: { userId: guest.id, deviceId, isActive: true },
        });
        if (deviceSession) {
          deviceSession = await tx.userDeviceSession.update({
            where: { id: deviceSession.id },
            data: {
              userAgent,
              ipAddress,
              lastLoginAt: new Date(),
              isActive: true,
            },
          });
        } else {
          deviceSession = await tx.userDeviceSession.create({
            data: {
              userId: guest.id,
              deviceId,
              userAgent,
              ipAddress,
              lastLoginAt: new Date(),
              isActive: true,
            },
          });
        }
        logRegistrationSuccess('guest', guest.id, ipAddress);
        return { guest, deviceSession };
      });
      const tokens = await createAuthTokens(guest, false, deviceSession.id);
      setAuthCookies(res, tokens.refreshToken, false);
      res.cookie(GUEST_COOKIE_NAME, guest.uuid, getGuestCookieOptions());
      logLoginSuccess('guest', guest.uuid, ipAddress);
      return res.status(200).json({
        accessToken: tokens.accessToken,
        csrfToken: tokens.csrfToken,
        role: guest.role,
      });
    }
  } catch (error) {
    logLoginFailure('guest', ipAddress, error.message);
    handleRouteError(res, error, {
      logPrefix: 'Ошибка при гостевом входе',
      status: 500,
      message: 'Ошибка при гостевом входе. Попробуйте позже',
    });
  }
});

export default {
  path: '/',
  router,
};
