import { Router } from 'express';
import rateLimit from 'express-rate-limit';
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
  logGithubOAuthConfirmAttempt,
  logGithubOAuthConfirmSuccess,
  logGithubOAuthConfirmFailure,
} from '#utils/loggers/authLoggers.js';

const router = Router();

const githubConfirmConnectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for this endpoint
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/github/confirm-connect',
  githubConfirmConnectLimiter,
  authenticateMiddleware,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { confirmationCode } = req.body;
    logGithubOAuthConfirmAttempt(userUuid, ipAddress, userAgent);
    try {
      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'connectGithub',
        confirmationCode,
      );
      if (!validation.isValid) {
        logGithubOAuthConfirmFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      const storedData = await getUserTempData('connectGithub', userUuid);
      if (!storedData) {
        return res.status(400).json({ error: 'Код истёк или не найден' });
      }

      await deleteUserTempData('connectGithub', userUuid);

      const { githubId, normalizedGithubEmail } = storedData;

      const user = await findUserByUuidOrThrow(userUuid);

      await prisma.userOAuth.upsert({
        where: { provider_providerId: { provider: 'github', providerId: githubId } },
        update: { userId: user.id, email: normalizedGithubEmail, enabled: true },
        create: { userId: user.id, provider: 'github', providerId: githubId, email: normalizedGithubEmail, enabled: true },
      });

      logGithubOAuthConfirmSuccess(userUuid, ipAddress, userAgent);
      res.status(200).json({
        message: 'Код подтверждения верен, привязка Github успешна',
      });
    } catch (error) {
      logGithubOAuthConfirmFailure(userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при подтверждении Github OAuth',
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
