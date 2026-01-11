import { Router } from 'express';
import axios from 'axios';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import { normalizeEmail } from '#utils/validators/normalizeEmail.js';
import { sendUserConfirmationCode } from '#utils/helpers/sendUserConfirmationCode.js';
import { setUserTempData } from '#store/userTempData.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import {
  logYandexOAuthAttempt,
  logYandexOAuthSuccess,
  logYandexOAuthFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const yandexConnectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 Yandex connect requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/yandex/connect',
  authenticateMiddleware,
  yandexConnectLimiter,
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { code } = req.body;

    logYandexOAuthAttempt('connect', '', '', ipAddress, userAgent);

    if (!code || typeof code !== 'string') {
      logYandexOAuthFailure('connect', '', '', ipAddress, 'code missing', userAgent);
      return res.status(400).json({ error: 'Код обязателен' });
    }

    const redirectUri =
      process.env.NODE_ENV === 'production'
        ? 'https://sharkflow.onrender.com/oauth/yandex/callback'
        : 'http://localhost:5173/oauth/yandex/callback';

    try {
      const tokenRes = await axios.post(
        'https://oauth.yandex.ru/token',
        new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: process.env.CLIENT_YANDEX_ID,
          client_secret: process.env.CLIENT_YANDEX_SECRET,
          redirect_uri: redirectUri,
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000,
        },
      );

      const accessTokenYA = tokenRes.data.access_token;

      if (!accessTokenYA) {
        return res
          .status(400)
          .json({ error: 'Не удалось получить токен от Yandex' });
      }

      if (tokenRes.data.token_type !== 'bearer') {
        return res.status(400).json({ error: 'Некорректный тип токена' });
      }

      const userRes = await axios.get('https://login.yandex.ru/info', {
        headers: { Authorization: `OAuth ${accessTokenYA}` },
        timeout: 10000,
      });

      const yandexUser = userRes.data;
      const email = yandexUser.default_email;

      if (!email) {
        logYandexOAuthFailure('connect', yandexUser?.id || '', '', ipAddress, 'email missing', userAgent);
        return res.status(400).json({
          error: 'Не удалось получить email из Yandex',
        });
      }

      const user = await findUserByUuidOrThrow(userUuid);

      const existingUserWithYandexId = await prisma.user.findFirst({
        where: { yandexId: String(yandexUser.id) },
      });

      if (
        existingUserWithYandexId &&
        existingUserWithYandexId.uuid !== userUuid
      ) {
        return res.status(409).json({
          error: 'Этот Yandex аккаунт уже привязан к другому пользователю',
          details: {
            existingUserEmail: existingUserWithYandexId.email,
            yandexId: String(yandexUser.id)
          }
        });
      }

      const userYandexIdStr = user.yandexId ? user.yandexId.toString() : null;
      const yandexIdStr = yandexUser.id.toString();

      if (userYandexIdStr && userYandexIdStr !== yandexIdStr) {
        return res.status(409).json({
          error: 'К аккаунту уже привязан другой Yandex аккаунт',
        });
      }

      if (userYandexIdStr === yandexIdStr) {
        return res
          .status(200)
          .json({ message: 'Yandex уже привязан к аккаунту' });
      }

      const normalizedUserEmail = normalizeEmail(user.email);
      const normalizedYandexEmail = normalizeEmail(email);

      if (normalizedUserEmail !== normalizedYandexEmail) {
        await sendUserConfirmationCode({
          userUuid,
          type: 'connectYandex',
          email: normalizedYandexEmail,
          skipUserCheck: true,
          loggers: {
            success: () => {},
            failure: () => {},
          },
        });

        await setUserTempData('connectYandex', userUuid, {
          yandexId: String(yandexUser.id),
          normalizedYandexEmail,
        });

        return res.status(200).json({
          message:
            'Email Yandex не совпадает с email аккаунта. Требуется подтверждение.',
          requireEmailConfirmed: true,
        });
      }

      await prisma.userOAuth.upsert({
        where: { provider_providerId: { provider: 'yandex', providerId: String(yandexUser.id) } },
        update: { userId: user.id, email: email, enabled: true },
        create: { userId: user.id, provider: 'yandex', providerId: String(yandexUser.id), email: email, enabled: true },
      });

      logYandexOAuthSuccess('connect', yandexUser?.id || '', userUuid, email, ipAddress, userAgent);
      return res
        .status(200)
        .json({ message: 'Yandex-аккаунт успешно привязан' });
    } catch (error) {
      logYandexOAuthFailure('connect', '', '', ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при привязке Yandex',
        status: 500,
        message: 'Не удалось привязать Yandex. Попробуйте позже.',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
