import { Router } from 'express';
import { authenticateMiddleware } from
'#middlewares/http/authenticateMiddleware.js';
import { logUserFetch } from
'#utils/loggers/authLoggers.js';
import { logUserFetchAttempt } from
'#utils/loggers/authLoggers.js';
import { logUserFetchFailure } from
'#utils/loggers/authLoggers.js';
import { getRequestInfo } from
'#utils/helpers/authHelpers.js';
import { handleRouteError } from
'#utils/handlers/handleRouteError.js';
import { findUserByUuidOrThrow } from
'#utils/helpers/userHelpers.js';
import { getUserOAuthByUserId } from
'#utils/helpers/userHelpers.js';
import { getUserOAuthEnabledByUserId } from
'#utils/helpers/userHelpers.js';

const router = Router();

router.get('/users', authenticateMiddleware, async (req, res) => {
  const userUuid = req.userUuid;
  const { ipAddress, userAgent } = getRequestInfo(req);

  logUserFetchAttempt(userUuid, ipAddress, userAgent);

  try {
    const includeSensitiveData = req.query.includeSensitive === 'true';

    const user = await findUserByUuidOrThrow(userUuid, false, {
      id: true,
      uuid: true,
      login: true,
      email: true,
      role: true,
      twoFactorEnabled: true,
      avatarUrl: true,
      password: includeSensitiveData, // debug for admin panel
    });

    logUserFetch(userUuid, ipAddress);

    const [googleOAuth, githubOAuth, yandexOAuth] = await Promise.all([
      getUserOAuthByUserId(user.id, 'google'),
      getUserOAuthByUserId(user.id, 'github'),
      getUserOAuthByUserId(user.id, 'yandex'),
    ]);

    // small optimization to avoid extra db request
    const githubOAuthEnabled = githubOAuth
      ? true
      : await getUserOAuthEnabledByUserId(user.id, 'github');

    res.setHeader(
      'Cache-Control',
      'public, max-age=300'
    );

    return res.json({
      uuid: user.uuid,
      login: user.login,
      email: user.email,
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled,
      avatarUrl: user.avatarUrl,
      googleOAuthEnabled: Boolean(googleOAuth),
      githubOAuthEnabled: Boolean(githubOAuthEnabled),
      yandexOAuthEnabled: Boolean(yandexOAuth),
      password: includeSensitiveData ? user.password : undefined,
    });

  } catch (error) {
    logUserFetchFailure(userUuid, ipAddress, error);

    handleRouteError(res, error, {
      logPrefix: 'Ошибка при получении пользователя',
      status: 500,
      message:
        process.env.NODE_ENV === 'development'
          ? error.message
          : 'Ошибка сервера',
    });
  }
});

export default {
  path: '/',
  router,
};
