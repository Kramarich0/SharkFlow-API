import { Router } from 'express';
import { emailConfirmValidate } from '#utils/validators/emailConfirmValidate.js';
import { validateMiddleware } from '#middlewares/http/validateMiddleware.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { getUserTempData } from '#store/userTempData.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { deleteUserTempData } from '#store/userTempData.js';
import { validateAndDeleteConfirmationCode } from '#utils/helpers/confirmationHelpers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import {
  logYandexOAuthConfirmAttempt,
  logYandexOAuthConfirmSuccess,
  logYandexOAuthConfirmFailure,
} from '#utils/loggers/authLoggers.js';

const rateLimit = require('express-rate-limit');

const router = Router();

const yandexConnectConfirmLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for this endpoint
});

router.post(
  '/auth/oauth/yandex/confirm-connect',
  yandexConnectConfirmLimiter,
  authenticateMiddleware,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { confirmationCode } = req.body;
    logYandexOAuthConfirmAttempt(userUuid, ipAddress, userAgent);
    try {
      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'connectYandex',
        confirmationCode,
      );
      if (!validation.isValid) {
        logYandexOAuthConfirmFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      const storedData = await getUserTempData('connectYandex', userUuid);
      if (!storedData) {
        return res.status(400).json({ error: 'Код истёк или не найден' });
      }

      await deleteUserTempData('connectYandex', userUuid);

      const { yandexId, normalizedYandexEmail } = storedData;

      const user = await findUserByUuidOrThrow(userUuid);

      await prisma.userOAuth.upsert({
        where: { provider_providerId: { provider: 'yandex', providerId: yandexId } },
        update: { userId: user.id, email: normalizedYandexEmail, enabled: true },
        create: { userId: user.id, provider: 'yandex', providerId: yandexId, email: normalizedYandexEmail, enabled: true },
      });

      logYandexOAuthConfirmSuccess(userUuid, ipAddress, userAgent);
      res.status(200).json({
        message: 'Код подтверждения верен, привязка Yandex успешна',
      });
    } catch (error) {
      logYandexOAuthConfirmFailure(userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при подтверждении Yandex OAuth',
        status: 500,
        message: 'Ошибка при проверке кода подтверждения',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
