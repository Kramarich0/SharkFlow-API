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
  logGoogleOAuthDisableAttempt,
  logGoogleOAuthDisableSuccess,
  logGoogleOAuthDisableFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const googleDisableRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 disable attempts per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error:
      'Слишком много попыток отвязки Google. Пожалуйста, попробуйте снова позже.',
  },
});

router.post(
  '/auth/oauth/google/disable',
  authenticateMiddleware,
  googleDisableRateLimiter,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    try {
      const userUuid = req.userUuid;
      logGoogleOAuthDisableAttempt(userUuid, ipAddress, userAgent);
      const { confirmationCode } = req.body;

      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'disableGoogle',
        confirmationCode,
      );

      if (!validation.isValid) {
        logGoogleOAuthDisableFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      await findUserByUuidOrThrow(userUuid, false, { uuid: true });

      const user = await findUserByUuidOrThrow(userUuid, false, { id: true });
      await prisma.userOAuth.updateMany({
        where: { userId: user.id, provider: 'google', enabled: true },
        data: { enabled: false },
      });

      logGoogleOAuthDisableSuccess(userUuid, ipAddress, userAgent);
      return res.json({ message: 'Google успешно отвязан от вашего аккаунта' });
    } catch (error) {
      logGoogleOAuthDisableFailure(req.userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при отвязке Google',
        status: 500,
        message: 'Произошла ошибка при отвязке Google. Попробуйте позже.',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
