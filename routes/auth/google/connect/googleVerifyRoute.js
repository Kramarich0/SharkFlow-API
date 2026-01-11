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
  logGoogleOAuthConfirmAttempt,
  logGoogleOAuthConfirmSuccess,
  logGoogleOAuthConfirmFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const googleConfirmConnectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 confirmation attempts per window
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/google/confirm-connect',
  googleConfirmConnectLimiter,
  authenticateMiddleware,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { confirmationCode } = req.body;
    logGoogleOAuthConfirmAttempt(userUuid, ipAddress, userAgent);
    try {
      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'connectGoogle',
        confirmationCode,
      );
      if (!validation.isValid) {
        logGoogleOAuthConfirmFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      const storedData = await getUserTempData('connectGoogle', userUuid);
      if (!storedData) {
        return res.status(400).json({ error: 'Код истёк или не найден' });
      }

      await deleteUserTempData('connectGoogle', userUuid);

      const { googleSub, normalizedGoogleEmail } = storedData;

      const user = await findUserByUuidOrThrow(userUuid);

      await prisma.userOAuth.upsert({
        where: { provider_providerId: { provider: 'google', providerId: googleSub } },
        update: { userId: user.id, email: normalizedGoogleEmail, enabled: true },
        create: { userId: user.id, provider: 'google', providerId: googleSub, email: normalizedGoogleEmail, enabled: true },
      });

      logGoogleOAuthConfirmSuccess(userUuid, ipAddress, userAgent);
      res.status(200).json({
        message: 'Код подтверждения верен, привязка Google успешна',
      });
    } catch (error) {
      logGoogleOAuthConfirmFailure(userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при подтверждении Google OAuth',
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
