import { Router } from 'express';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { uploadAvatarAndUpdateUser } from '#utils/helpers/uploadAvatarAndUpdateUser.js';
import { generateUUID } from '#utils/generators/generateUUID.js';
import { verifyTurnstileCaptcha } from '#utils/helpers/verifyTurnstileCaptchaHelper.js';
import {
  getGeoLocation,
  validateDeviceId,
} from '#utils/helpers/deviceSessionHelper.js';
import { GUEST_COOKIE_NAME } from '#config/cookiesConfig.js';
import { getGuestCookieOptions } from '#utils/cookie/guestCookie.js';
import { findUserOAuth, getUserOAuthEnabledByUserId } from '#utils/helpers/userHelpers.js';
import { findOrCreateUserWithOAuth } from '#utils/helpers/oauthHelpers.js';
import { createUserSessionAndTokens } from '#utils/helpers/authSessionHelpers.js';
import {
  logGithubOAuthAttempt,
  logGithubOAuthSuccess,
  logGithubOAuthFailure,
} from '#utils/loggers/authLoggers.js';

const router = Router();

const githubOAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 GitHub OAuth requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Слишком много попыток входа через GitHub. Попробуйте позже.',
  },
});

router.post('/auth/oauth/github', githubOAuthLimiter, async (req, res) => {
  const { ipAddress, userAgent } = getRequestInfo(req);
  const { code, state, captchaToken } = req.body;
  const guestUuid = req.cookies[GUEST_COOKIE_NAME];

  // Логгируем попытку входа через GitHub OAuth
  logGithubOAuthAttempt('login', '', '', ipAddress, userAgent);

  if (!code) {
    logGithubOAuthFailure('login', '', '', ipAddress, 'code missing', userAgent);
    return res.status(400).json({ error: 'Код авторизации обязателен' });
  }

  if (process.env.NODE_ENV === 'production') {
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

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Код обязателен' });
  }

  if (!state || typeof state !== 'string') {
    return res.status(400).json({ error: 'State обязателен' });
  }

  const [stateToken, nextPath = '/dashboard'] = state.split('|');

  if (
    !stateToken ||
    stateToken.length < 10 ||
    !/^[a-zA-Z0-9\-_]+$/.test(stateToken)
  ) {
    return res.status(400).json({ error: 'Некорректный state' });
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

    if (!email) {
      logGithubOAuthFailure('login', githubUser?.id || '', '', ipAddress, 'email missing', userAgent);
      return res
        .status(400)
        .json({ error: 'Не удалось получить подтверждённый email из GitHub' });
    }

    let user = null;
    const userOAuth = await findUserOAuth('github', String(githubUser.id));
    if (userOAuth) {
      user = userOAuth.user;
    } else {
      user = await findOrCreateUserWithOAuth({
        provider: 'github',
        providerId: String(githubUser.id),
        email,
        guestUuid,
        givenName: githubUser.login,
        req,
        res,
      });
      if (guestUuid) {
        res.clearCookie(GUEST_COOKIE_NAME, getGuestCookieOptions());
      }
    }

    if (githubUser.avatar_url) {
      const hasAvatar = Boolean(user.avatarUrl);
      const isCloudinary = user.avatarUrl?.includes('res.cloudinary.com');
      if (!hasAvatar || !isCloudinary) {
        await uploadAvatarAndUpdateUser(
          user.id,
          githubUser.avatar_url,
          `github_${githubUser.id}`,
        );
      }
    }

    if (user.role === 'guest' || !user.isActive) {
      logGithubOAuthFailure('login', githubUser?.id || '', email, ipAddress, 'guest or inactive', userAgent);
      return res
        .status(403)
        .json({ error: 'Этот аккаунт не может использовать OAuth' });
    }

    const deviceId = validateDeviceId(req, res);
    if (!deviceId) return;

    const geoLocation = await getGeoLocation(ipAddress);

    const { accessToken, csrfToken } = await createUserSessionAndTokens({
      user,
      deviceId,
      userAgent,
      ipAddress,
      req,
      res,
      rememberMe: true,
      referrer: req.get('Referer') || null,
      geoLocation,
    });

    const githubOAuthEnabled = await getUserOAuthEnabledByUserId(user.id, 'github');
    logGithubOAuthSuccess('login', githubUser?.id || '', user.uuid, email, ipAddress, userAgent);
    return res.status(200).json({
      accessToken,
      csrfToken,
      githubOAuthEnabled,
    });
  } catch (error) {
    logGithubOAuthFailure('login', '', '', ipAddress, error?.message || 'unknown error', userAgent);
    handleRouteError(res, error, {
      logPrefix: 'Ошибка при логине через GitHub',
      status: 500,
      message: 'Не удалось войти через GitHub. Попробуйте позже.',
    });
  }
});

export default {
  path: '/',
  router,
};
