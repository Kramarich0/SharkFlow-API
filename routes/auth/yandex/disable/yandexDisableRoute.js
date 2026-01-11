import { Router } from 'express';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import { validateAndDeleteConfirmationCode } from '#utils/helpers/confirmationHelpers.js';
import { emailConfirmValidate } from '#utils/validators/emailConfirmValidate.js';
import { validateMiddleware } from '#middlewares/http/validateMiddleware.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import {
  logYandexOAuthDisableAttempt,
  logYandexOAuthDisableSuccess,
  logYandexOAuthDisableFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const yandexDisableRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs for this route
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/yandex/disable',
  authenticateMiddleware,
  yandexDisableRateLimiter,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    try {
      const userUuid = req.userUuid;
      logYandexOAuthDisableAttempt(userUuid, ipAddress, userAgent);
      const { confirmationCode } = req.body;

      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'disableYandex',
        confirmationCode,
      );

      if (!validation.isValid) {
        logYandexOAuthDisableFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      await findUserByUuidOrThrow(userUuid, false, { uuid: true });

      const user = await prisma.user.findFirst({ where: { uuid: userUuid } });
      if (!user) {
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      await prisma.userOAuth.updateMany({
        where: { userId: user.id, provider: 'yandex' },
        data: { enabled: false },
      });
      logYandexOAuthDisableSuccess(userUuid, ipAddress, userAgent);
      return res.json({ message: 'Yandex успешно отвязан от вашего аккаунта' });
    } catch (error) {
      logYandexOAuthDisableFailure(req.userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при отвязке Yandex',
        status: 500,
        message: 'Произошла ошибка при отвязке Yandex. Попробуйте позже.',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
