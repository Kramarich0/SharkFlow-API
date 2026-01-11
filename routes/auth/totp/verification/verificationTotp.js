import { Router } from 'express';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import {
  createAuthTokens,
  getRequestInfo,
  setAuthCookies,
} from '#utils/helpers/authHelpers.js';
import { resetLoginAttempts, totpVerifyRateLimiter } from '#utils/rateLimiters/authRateLimiters.js';
import { logLoginSuccess, logTotpVerifyAttempt } from '#utils/loggers/authLoggers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { deleteUserTempData } from '#store/userTempData.js';
import { getUserTempData } from '#store/userTempData.js';
import {
  verifyTotpCode,
  validateTotpCodeFormat,
} from '#utils/helpers/totpHelpers.js';
import {
  createOrUpdateDeviceSession,
  getGeoLocation,
} from '#utils/helpers/deviceSessionHelper.js';

const router = Router();

router.post('/auth/totp/verify', totpVerifyRateLimiter, async (req, res) => {
  const { totpCode, sessionKey } = req.body;
  const {ipAddress,userAgent} = getRequestInfo(req)

  logTotpVerifyAttempt(sessionKey, totpCode, ipAddress, userAgent);

  try {
    const session = await getUserTempData('twoFactorAuth', sessionKey);
    if (!session) {
      return res
        .status(401)
        .json({ error: 'Сессия 2FA истекла или не найдена' });
    }

    if (!validateTotpCodeFormat(totpCode)) {
      return res.status(400).json({ error: 'Код должен состоять из 6 цифр' });
    }

    const { uuid, rememberMe, ipAddress, userAgent } = session;

    const user = await findUserByUuidOrThrow(uuid, false, {
      id: true,
      uuid: true,
      password: true,
      login: true,
      email: true,
      role: true,
      twoFactorEnabled: true,
      twoFactorSecret: true,
    });

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res
        .status(400)
        .json({ error: '2FA не настроена для пользователя' });
    }

    if (!verifyTotpCode(user, totpCode)) {
      return res.status(403).json({ error: 'Неверный или просроченный код' });
    }

    resetLoginAttempts(ipAddress, user.email);

    const deviceId = req.headers['x-device-id'];
    if (!deviceId) {
      return res.status(401).json({ error: 'Устройство не найдено' });
    }

    const geoLocation = await getGeoLocation(ipAddress);

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

    logLoginSuccess(user.email, user.uuid, ipAddress);
    await deleteUserTempData('twoFactorAuth', sessionKey);
    return res
      .status(200)
      .json({ accessToken: tokens.accessToken, csrfToken: tokens.csrfToken });
  } catch (error) {
    handleRouteError(res, error, {
      message: 'Ошибка при логине. Попробуйте позже',
      status: 500,
      logPrefix: 'Ошибка при логине',
    });
  }
});

export default {
  path: '/',
  router,
};
