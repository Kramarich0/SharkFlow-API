import { Router } from 'express';
import rateLimit from 'express-rate-limit';

import prisma from '#utils/prismaConfig/prismaClient.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import { verifyTotpCode } from '#utils/helpers/totpHelpers.js';
import { deleteUserTempData } from '#store/userTempData.js';
import { deleteConfirmationCode } from '#store/userVerifyStore.js';
import { validateTotpCodeFormat } from '#utils/helpers/totpHelpers.js';
import { getUserTempData } from '#store/userTempData.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { logAccountRestoreSuccess, logAccountRestoreFailure, logAccountRestoreTotpAttempt } from '#utils/loggers/authLoggers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';

const router = Router();

const restoreTotpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/auth/restore/verify/totp', restoreTotpLimiter, async (req, res) => {
  const { totpCode, restoreKey } = req.body;
  const { ipAddress, userAgent } = getRequestInfo(req);

  logAccountRestoreTotpAttempt(restoreKey, ipAddress, userAgent, totpCode);

  try {
    const session = await getUserTempData('twoFactorAuth', restoreKey);
    if (!session) {
      logAccountRestoreFailure('', ipAddress, 'Сессия 2FA истекла или не найдена');
      return res
        .status(401)
        .json({ error: 'Сессия 2FA истекла или не найдена' });
    }

    if (!validateTotpCodeFormat(totpCode)) {
      logAccountRestoreFailure('', ipAddress, 'Код TOTP неверного формата');
      return res.status(400).json({ error: 'Код должен состоять из 6 цифр' });
    }

    const { uuid, twoFactorEnabled, ipAddress, userAgent, timestamp } = session;

    const user = await findUserByUuidOrThrow(uuid, true, {
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
      logAccountRestoreFailure(user.email, ipAddress, '2FA не настроена для пользователя');
      return res
        .status(400)
        .json({ error: '2FA не настроена для пользователя' });
    }

    if (!verifyTotpCode(user, totpCode)) {
      logAccountRestoreFailure(user.email, ipAddress, 'Неверный или просроченный код TOTP');
      return res.status(403).json({ error: 'Неверный или просроченный код' });
    }

    await prisma.user.update({
      where: { uuid: user.uuid },
      data: {
        isDeleted: false,
      },
    });
    logAccountRestoreSuccess(user.email, user.uuid, ipAddress);

    await deleteUserTempData('restoreUser', restoreKey);

    await deleteConfirmationCode('restoreUser', user.uuid);

    await deleteUserTempData('twoFactorAuth', restoreKey);

    return res
      .status(200)
      .json({ message: 'Верификация успешна, аккаунт восстановлен' });
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
