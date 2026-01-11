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
import { findUserOAuth, getUserOAuthByUserId } from '#utils/helpers/userHelpers.js';
import { findOrCreateUserWithOAuth } from '#utils/helpers/oauthHelpers.js';
import { createUserSessionAndTokens } from '#utils/helpers/authSessionHelpers.js';
import {
  logYandexOAuthAttempt,
  logYandexOAuthSuccess,
  logYandexOAuthFailure,
} from '#utils/loggers/authLoggers.js';

function isCloudinaryUrl(avatarUrl) {
  if (!avatarUrl) return false;
  try {
    const parsed = new URL(avatarUrl);
    return parsed.hostname === 'res.cloudinary.com';
  } catch {
    return false;
  }
}

const router = Router();

const yandexOAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 Yandex OAuth requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/auth/oauth/yandex', yandexOAuthLimiter, async (req, res) => {
  const { ipAddress, userAgent } = getRequestInfo(req);
  const { code, state, captchaToken } = req.body;
  const guestUuid = req.cookies[GUEST_COOKIE_NAME];

  // Логгируем попытку входа через Yandex OAuth
  logYandexOAuthAttempt('login', '', '', ipAddress, userAgent);

  if (!code || typeof code !== 'string') {
    logYandexOAuthFailure('login', '', '', ipAddress, 'code missing', userAgent);
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
      logYandexOAuthFailure('login', yandexUser?.id || '', '', ipAddress, 'email missing', userAgent);
      return res
        .status(400)
        .json({ error: 'Не удалось получить email из Yandex' });
    }

    let user = null;
    const userOAuth = await findUserOAuth('yandex', String(yandexUser.id));
    if (userOAuth) {
      user = userOAuth.user;
    } else {
      user = await findOrCreateUserWithOAuth({
        provider: 'yandex',
        providerId: String(yandexUser.id),
        email,
        guestUuid,
        givenName: yandexUser.login,
        req,
        res,
      });
      if (guestUuid) {
        res.clearCookie(GUEST_COOKIE_NAME, getGuestCookieOptions());
      }
    }

    const avatarUrl = yandexUser.default_avatar_id
      ? `https://avatars.yandex.net/get-yapic/${yandexUser.default_avatar_id}/islands-200`
      : null;

    if (avatarUrl) {
      const hasAvatar = Boolean(user.avatarUrl);
      const isCloudinary = isCloudinaryUrl(user.avatarUrl);
      if (!hasAvatar || !isCloudinary) {
        await uploadAvatarAndUpdateUser(
          user.id,
          avatarUrl,
          `yandex_${yandexUser.id}`,
        );
      }
    }

    if (user.role === 'guest' || !user.isActive) {
      logYandexOAuthFailure('login', yandexUser?.id || '', email, ipAddress, 'guest or inactive', userAgent);
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

    const yandexOAuthEnabled = Boolean(await getUserOAuthByUserId(user.id, 'yandex'));
    logYandexOAuthSuccess('login', yandexUser?.id || '', user.uuid, email, ipAddress, userAgent);
    return res.status(200).json({
      accessToken,
      csrfToken,
      yandexOAuthEnabled,
    });
  } catch (error) {
    logYandexOAuthFailure('login', '', '', ipAddress, error?.message || 'unknown error', userAgent);
    handleRouteError(res, error, {
      logPrefix: 'Ошибка при логине через Yandex',
      status: 500,
      message: 'Не удалось войти через Yandex. Попробуйте позже.',
    });
  }
});

export default {
  path: '/',
  router,
};
