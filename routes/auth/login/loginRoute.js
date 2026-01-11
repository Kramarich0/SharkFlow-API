import { Router } from 'express';
import { loginValidate } from '#utils/validators/loginValidate.js';
import { validateMiddleware } from '#middlewares/http/validateMiddleware.js';
import bcrypt from 'bcrypt';
import { normalizeEmail } from '#utils/validators/normalizeEmail.js';
import {
  checkLoginRateLimit,
  incrementLoginAttempts,
  resetLoginAttempts,
} from '#utils/rateLimiters/authRateLimiters.js';
import {
  logLoginSuccess,
  logLoginFailure,
  maskEmail,
  logLoginAttempt,
} from '#utils/loggers/authLoggers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { generateUUID } from '#utils/generators/generateUUID.js';
import { setUserTempData } from '#store/userTempData.js';
import { findUserByEmail } from '#utils/helpers/userHelpers.js';
import { getUserOAuthEnabledByUserId } from '#utils/helpers/userHelpers.js';
import {
  createAuthTokens,
  setAuthCookies,
} from '#utils/helpers/authHelpers.js';
import { verifyTurnstileCaptcha } from '#utils/helpers/verifyTurnstileCaptchaHelper.js';
import {
  createOrUpdateDeviceSession,
  getGeoLocation,
  validateDeviceId,
} from '#utils/helpers/deviceSessionHelper.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/auth/login',
  loginRateLimiter,
  validateMiddleware(loginValidate),
  async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const { user, captchaToken } = req.validatedBody;
    const { email, password, rememberMe } = user;
    const deviceId = validateDeviceId(req, res);
    if (!deviceId) return;

    logLoginAttempt(email, ipAddress, userAgent);

    // if (process.env.NODE_ENV === 'production') {
    //   if (!captchaToken) {
    //     return res
    //       .status(400)
    //       .json({ error: 'Пожалуйста, подтвердите, что вы не робот!' });
    //   }

    //   const turnstileUuid = generateUUID();

    //   try {
    //     const captchaSuccess = await verifyTurnstileCaptcha(
    //       captchaToken,
    //       ipAddress,
    //       turnstileUuid,
    //     );
    //     if (!captchaSuccess) {
    //       return res
    //         .status(400)
    //         .json({ error: 'Captcha не пройдена. Попробуйте еще раз' });
    //     }
    //   } catch (error) {
    //     return res.status(500).json({ error: error.message });
    //   }
    // }

    const normalizedEmail =
      typeof email === 'string' ? normalizeEmail(email) : null;

    if (!normalizedEmail) {
      return res.status(400).json({ error: 'Некорректный email' });
    }

    const rateLimitCheck = checkLoginRateLimit(ipAddress, normalizedEmail);
    if (rateLimitCheck.blocked) {
      return res.status(429).json({
        error: `Слишком много попыток входа. Попробуйте через ${rateLimitCheck.timeLeft} минут`,
      });
    }

    const geoLocation = await getGeoLocation(ipAddress);

    const deletedUser = await findUserByEmail(normalizedEmail, true, {
      id: true,
      uuid: true,
      password: true,
      login: true,
      email: true,
      role: true,
      twoFactorEnabled: true,
      isDeleted: true,
      avatarUrl: true,
    });

    if (deletedUser && deletedUser.isDeleted) {
      if (!(await bcrypt.compare(password, deletedUser.password))) {
        incrementLoginAttempts(ipAddress, normalizedEmail);
        return res.status(401).json({ error: 'Неправильный email или пароль' });
      }
      const maskedEmail = maskEmail(deletedUser.email);
      const restoreKey = generateUUID();
      await setUserTempData('restoreUser', restoreKey, {
        userUuid: deletedUser.uuid,
      });

      return res.status(200).json({
        login: deletedUser.login,
        email: maskedEmail,
        avatarUrl: deletedUser.avatarUrl,
        isDeleted: deletedUser.isDeleted,
        restoreKey,
      });
    }

    try {
      const user = await findUserByEmail(normalizedEmail, false, {
        id: true,
        uuid: true,
        password: true,
        login: true,
        email: true,
        role: true,
        twoFactorEnabled: true,
      });

      if (!user || !user.password) {
        incrementLoginAttempts(ipAddress, normalizedEmail);
        return res.status(401).json({ error: 'Неправильный email или пароль' });
      }

      if (!(await bcrypt.compare(password, user.password))) {
        incrementLoginAttempts(ipAddress, normalizedEmail);
        logLoginFailure(normalizedEmail, ipAddress);
        return res.status(401).json({ error: 'Неправильный email или пароль' });
      }

      if (user.twoFactorEnabled) {
        const sessionKey = generateUUID();
        await setUserTempData('twoFactorAuth', sessionKey, {
          uuid: user.uuid,
          twoFactorEnabled: user.twoFactorEnabled,
          rememberMe,
          ipAddress,
          userAgent,
          timestamp: Date.now(),
        });
        return res.status(200).json({
          twoFactorEnabled: user.twoFactorEnabled,
          sessionKey,
          message:
            'Требуется двуфакторная аутентификация. Введите код из приложения',
        });
      }

      resetLoginAttempts(ipAddress, normalizedEmail);

      const deviceSession = await createOrUpdateDeviceSession({
        userId: user.id,
        deviceId,
        userAgent,
        ipAddress,
        referrer: req.get('Referer') || null,
        geoLocation,
      });

      const tokens = await createAuthTokens(user, rememberMe, deviceSession.id);

      setAuthCookies(res, tokens.refreshToken, rememberMe);

      logLoginSuccess(normalizedEmail, user.uuid, ipAddress);

      const githubOAuthEnabled = user
        ? await getUserOAuthEnabledByUserId(user.id, 'github')
        : false;

      return res.status(200).json({
        accessToken: tokens.accessToken,
        csrfToken: tokens.csrfToken,
        deviceId: deviceSession.deviceId,
        githubOAuthEnabled,
      });
    } catch (error) {
      incrementLoginAttempts(ipAddress, normalizedEmail);
      handleRouteError(res, error, {
        message: 'Ошибка при логине. Попробуйте позже',
        status: 500,
        logPrefix: 'Ошибка при логине',
      });
    }
  },
);

export default {
  path: '/',
  router,
};
