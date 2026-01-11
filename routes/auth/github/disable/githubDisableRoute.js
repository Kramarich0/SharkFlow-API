import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import { validateAndDeleteConfirmationCode } from '#utils/helpers/confirmationHelpers.js';
import { emailConfirmValidate } from '#utils/validators/emailConfirmValidate.js';
import { validateMiddleware } from '#middlewares/http/validateMiddleware.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import {
  logGithubOAuthDisableAttempt,
  logGithubOAuthDisableSuccess,
  logGithubOAuthDisableFailure,
} from '#utils/loggers/authLoggers.js';
import { getUserOAuthEnabledByUserId } from '#utils/helpers/userHelpers.js';

const router = Router();

const githubDisableRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 disable requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/github/disable',
  githubDisableRateLimiter,
  authenticateMiddleware,
  validateMiddleware(emailConfirmValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    try {
      const userUuid = req.userUuid;
      logGithubOAuthDisableAttempt(userUuid, ipAddress, userAgent);
      const { confirmationCode } = req.body;

      const validation = await validateAndDeleteConfirmationCode(
        userUuid,
        'disableGithub',
        confirmationCode,
      );

      if (!validation.isValid) {
        logGithubOAuthDisableFailure(userUuid, ipAddress, validation.error, userAgent);
        return res.status(400).json({ error: validation.error });
      }

      await findUserByUuidOrThrow(userUuid, false, { uuid: true });

      await prisma.user.update({
        where: { uuid: userUuid },
        data: {
          githubId: null,
        },
      });

      const user = await findUserByUuidOrThrow(userUuid, false, { id: true, uuid: true });
      const githubOAuthEnabled = await getUserOAuthEnabledByUserId(user.id, 'github');

      logGithubOAuthDisableSuccess(userUuid, ipAddress, userAgent);
      return res.json({
        ...user,
        githubOAuthEnabled,
      });
    } catch (error) {
      logGithubOAuthDisableFailure(req.userUuid, ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при отвязке Github',
        status: 500,
        message: 'Произошла ошибка при отвязке Github. Попробуйте позже.',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
