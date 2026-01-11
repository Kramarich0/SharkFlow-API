import { Router } from 'express';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { OAuth2Client } from 'google-auth-library';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { uploadAvatarAndUpdateUser } from '#utils/helpers/uploadAvatarAndUpdateUser.js';
import { generateUUID } from '#utils/generators/generateUUID.js';
import { verifyTurnstileCaptcha } from '#utils/helpers/verifyTurnstileCaptchaHelper.js';
import {
  getGeoLocation,
  validateDeviceId,
} from '#utils/helpers/deviceSessionHelper.js';
import { getGuestCookieOptions } from '#utils/cookie/guestCookie.js';
import { GUEST_COOKIE_NAME } from '#config/cookiesConfig.js';
import { findUserOAuth } from '#utils/helpers/userHelpers.js';
import { getUserOAuthByUserId } from '#utils/helpers/userHelpers.js';
import { findOrCreateUserWithOAuth } from '#utils/helpers/oauthHelpers.js';
import { createUserSessionAndTokens } from '#utils/helpers/authSessionHelpers.js';
import {
  logGoogleOAuthAttempt,
  logGoogleOAuthSuccess,
  logGoogleOAuthFailure,
} from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const oauth2Client = new OAuth2Client(
  process.env.CLIENT_GOOGLE_ID,
  process.env.CLIENT_GOOGLE_SECRET,
  'postmessage',
);

const googleOAuthRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 Google OAuth requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Слишком много попыток входа через Google с этого IP. Попробуйте позже.',
  },
});

router.post('/auth/oauth/google', googleOAuthRateLimiter, async (req, res) => {
  const { ipAddress, userAgent } = getRequestInfo(req);
  const { code, captchaToken } = req.body;
  const guestUuid = req.cookies[GUEST_COOKIE_NAME];

  // Логгируем попытку входа через Google OAuth
  logGoogleOAuthAttempt('login', '', '', ipAddress, userAgent);

  if (!code) {
    logGoogleOAuthFailure('login', '', '', ipAddress, 'code missing', userAgent);
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

  try {
    const { tokens } = await oauth2Client.getToken({
      code,
      redirect_uri: 'postmessage',
    });

    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.CLIENT_GOOGLE_ID,
    });
    const {
      sub: googleSub,
      email,
      email_verified: emailVerified,
      given_name,
      picture: pic,
    } = ticket.getPayload();
    if (!googleSub)
      return res.status(400).json({ error: 'Некорректный токен Google' });
    if (!email || !emailVerified) {
      logGoogleOAuthFailure('login', googleSub || '', '', ipAddress, 'email missing or not verified', userAgent);
      return res
        .status(400)
        .json({ error: 'Некорректный или неподтверждённый email Google' });
    }

    let user = null;
    const avatarUrl = pic;

    const userByEmail = await prisma.user.findFirst({ where: { email } });
    const userOAuth = await findUserOAuth('google', googleSub);

    if (userByEmail) {
      if (!userByEmail.isActive) {
        return res.status(403).json({ error: 'Аккаунт заблокирован. Обратитесь в поддержку.' });
      }
      const userGoogleOAuth = await getUserOAuthByUserId(userByEmail.id, 'google');
      if (userGoogleOAuth && userGoogleOAuth.providerId === googleSub) {
        if (userByEmail.isDeleted) {
          await prisma.user.update({ where: { id: userByEmail.id }, data: { isDeleted: false, deletedAt: null } });
          await prisma.userOAuth.updateMany({ where: { userId: userByEmail.id, provider: 'google', providerId: googleSub }, data: { enabled: true } });
        }
        user = userByEmail;
      } else if (userGoogleOAuth && userGoogleOAuth.providerId !== googleSub) {
        return res.status(403).json({ error: 'Email уже привязан к другому Google аккаунту' });
      } else if (userByEmail.isDeleted) {
        return res.status(403).json({ error: 'Аккаунт с этой почтой был удален. Пожалуйста, используйте другую почту или обратитесь в поддержку для восстановления аккаунта.' });
      } else {
        return res.status(403).json({ error: 'Аккаунт с таким email существует, но не привязан к Google. Войдите через пароль или привяжите Google аккаунт.' });
      }
    } else if (userOAuth) {
      if (userOAuth.user.isDeleted) {
        return res.status(403).json({ error: 'Google аккаунт был связан с удаленным профилем. Пожалуйста, используйте другой Google аккаунт или обратитесь в поддержку.' });
      } else {
        return res.status(403).json({ error: 'Google аккаунт уже связан с другим профилем. Пожалуйста, используйте другой Google аккаунт.' });
      }
    }

    if (!user) {
      user = await findOrCreateUserWithOAuth({
        provider: 'google',
        providerId: googleSub,
        email,
        guestUuid,
        givenName: given_name,
        req,
        res,
      });
      if (guestUuid) {
        res.clearCookie(GUEST_COOKIE_NAME, getGuestCookieOptions());
      }
    }

    if (avatarUrl) {
      const hasAvatar = Boolean(user.avatarUrl);
      let isCloud = false;
      if (user.avatarUrl) {
        try {
          const parsedUrl = new URL(user.avatarUrl);
          isCloud = parsedUrl.hostname === 'res.cloudinary.com';
        } catch {
          isCloud = false;
        }
      }
      if (!hasAvatar || !isCloud) {
        await uploadAvatarAndUpdateUser(
          user.id,
          avatarUrl,
          `google_${googleSub}`,
        );
      }
    }

    if (user.isDeleted || !user.isActive) {
      logGoogleOAuthFailure('login', googleSub || '', email, ipAddress, 'deleted or inactive', userAgent);
      return res
        .status(403)
        .json({ error: 'Аккаунт недоступен. Обратитесь в поддержку.' });
    }

    if (user.role === 'guest') {
      logGoogleOAuthFailure('login', googleSub || '', email, ipAddress, 'guest', userAgent);
      return res
        .status(403)
        .json({ error: 'Гостевые аккаунты не могут использовать OAuth.' });
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

    const googleOAuthEnabled = Boolean(await getUserOAuthByUserId(user.id, 'google'));
    logGoogleOAuthSuccess('login', googleSub || '', user.id || user.uuid, email, ipAddress, userAgent);
    return res.status(200).json({
      accessToken,
      csrfToken,
      googleOAuthEnabled,
    });
  } catch (error) {
    logGoogleOAuthFailure('login', '', '', ipAddress, error?.message || 'unknown error', userAgent);
    if (!res.headersSent) {
      handleRouteError(res, error, {
        logPrefix: 'Ошибка при логине через Google',
        status: 500,
        message: 'Ошибка при логине через Google. Попробуйте позже.',
      });
    }
  }
});

export default {
  path: '/',
  router,
};
