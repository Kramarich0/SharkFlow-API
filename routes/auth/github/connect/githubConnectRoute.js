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
  logGithubOAuthAttempt,
  logGithubOAuthSuccess,
  logGithubOAuthFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const githubConnectRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 GitHub connect requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/oauth/github/connect',
  authenticateMiddleware,
  githubConnectRateLimiter,
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { code } = req.body;

    // Логгируем попытку привязки GitHub OAuth
    logGithubOAuthAttempt('connect', '', '', ipAddress, userAgent);

    if (!code || typeof code !== 'string') {
      logGithubOAuthFailure('connect', '', '', ipAddress, 'code missing', userAgent);
      return res.status(400).json({ error: 'Код обязателен' });
    }

    try {
      const tokenRes = await axios.post(
        'https://github.com/login/oauth/access_token',
        {
          client_id: process.env.CLIENT_GITHUB_ID,
          client_secret: process.env.CLIENT_GITHUB_SECRET,
          code,
        },
        { headers: { Accept: 'application/json' }, timeout: 10000 },
      );

      const accessTokenGH = tokenRes.data.access_token;

      if (!accessTokenGH) {
        return res
          .status(400)
          .json({ error: 'Не удалось получить токен от GitHub' });
      }

      if (tokenRes.data.token_type !== 'bearer') {
        return res.status(400).json({ error: 'Некорректный тип токена' });
      }

      const [userRes, emailsRes] = await Promise.all([
        axios.get('https://api.github.com/user', {
          headers: { Authorization: `Bearer ${accessTokenGH}` },
          timeout: 10000,
        }),
        axios.get('https://api.github.com/user/emails', {
          headers: { Authorization: `Bearer ${accessTokenGH}` },
          timeout: 10000,
        }),
      ]);

      const githubUser = userRes.data;
      const primary = Array.isArray(emailsRes.data)
        ? emailsRes.data.find((e) => e.primary && e.verified)
        : null;
      const email = primary?.email;
      const githubIdNumber = githubUser.id;

      if (!email) {
        logGithubOAuthFailure('connect', githubIdNumber || '', '', ipAddress, 'email missing', userAgent);
        return res.status(400).json({
          error: 'Не удалось получить подтверждённый email из GitHub',
        });
      }

      const user = await findUserByUuidOrThrow(userUuid);

      const existingUserWithGithubId = await prisma.user.findFirst({
        where: { githubId: githubIdNumber.toString() },
      });

      if (
        existingUserWithGithubId &&
        existingUserWithGithubId.uuid !== userUuid
      ) {
        return res.status(409).json({
          error: 'Этот GitHub аккаунт уже привязан к другому пользователю',
        });
      }

      const userGithubIdStr = user.githubId ? user.githubId.toString() : null;
      const githubIdStr = githubIdNumber.toString();

      if (userGithubIdStr && userGithubIdStr !== githubIdStr) {
        return res.status(409).json({
          error: 'К аккаунту уже привязан другой GitHub аккаунт',
        });
      }

      if (userGithubIdStr === githubIdStr) {
        return res
          .status(200)
          .json({ message: 'GitHub уже привязан к аккаунту' });
      }

      const normalizedUserEmail = normalizeEmail(user.email);
      const normalizedGithubEmail = normalizeEmail(email);

      if (normalizedUserEmail !== normalizedGithubEmail) {
        await sendUserConfirmationCode({
          userUuid,
          type: 'connectGithub',
          email: normalizedGithubEmail,
          skipUserCheck: true,
          loggers: {
            success: () => {},
            failure: () => {},
          },
        });

        await setUserTempData('connectGithub', userUuid, {
          githubId: githubIdNumber.toString(),
          normalizedGithubEmail,
        });

        return res.status(200).json({
          message:
            'Email GitHub не совпадает с email аккаунта. Требуется подтверждение.',
          requireEmailConfirmed: true,
        });
      }

      await prisma.userOAuth.upsert({
        where: { provider_providerId: { provider: 'github', providerId: githubIdNumber.toString() } },
        update: { userId: user.id, email: email, enabled: true },
        create: { userId: user.id, provider: 'github', providerId: githubIdNumber.toString(), email: email, enabled: true },
      });

      logGithubOAuthSuccess('connect', githubIdNumber || '', userUuid, email, ipAddress, userAgent);
      return res
        .status(200)
        .json({ message: 'Github-аккаунт успешно привязан' });
    } catch (error) {
      logGithubOAuthFailure('connect', '', '', ipAddress, error?.message || 'unknown error', userAgent);
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при логине через GitHub',
        status: 500,
        message: 'Не удалось войти через GitHub. Попробуйте позже.',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
