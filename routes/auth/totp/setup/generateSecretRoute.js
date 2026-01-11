import { Router } from 'express';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import speakeasy from 'speakeasy';
import { encrypt } from '#utils/crypto/encrypt.js';
import { decrypt } from '#utils/crypto/decrypt.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { validateAndDeleteConfirmationCode } from '#utils/helpers/confirmationHelpers.js';
import { createOtpAuthUrl } from '#utils/helpers/totpHelpers.js';
import { getUserTempData, setUserTempData } from '#store/userTempData.js';
import rateLimit from 'express-rate-limit';

const router = Router();

const totpSetupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 TOTP setup requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Слишком много попыток настройки 2FA, повторите позже',
  },
});

router.post('/auth/totp', authenticateMiddleware, totpSetupLimiter, async (req, res) => {
  try {
    const userUuid = req.userUuid;
    const { confirmationCode } = req.body;

    const user = await findUserByUuidOrThrow(userUuid, false, {
      email: true,
    });

    const storedData = await getUserTempData(
      'twoFactorPendingSecret',
      userUuid,
    );

    const validation = await validateAndDeleteConfirmationCode(
      userUuid,
      'setupTotp',
      confirmationCode,
    );

    if (!validation.isValid) {
      return res.status(400).json({ error: validation.error });
    }

    let secret;
    let encryptedSecret;

    if (storedData?.encryptedSecret) {
      encryptedSecret = storedData.encryptedSecret;
      secret = decrypt(encryptedSecret);
    } else {
      const generated = speakeasy.generateSecret({
        length: 20,
        name: `SharkFlow (${user.email})`,
      });
      secret = generated.base32;
      encryptedSecret = encrypt(secret);
      await setUserTempData('twoFactorPendingSecret', userUuid, {
        encryptedSecret,
      });
    }

    const otpauthUrl = createOtpAuthUrl(secret, user.email);

    return res.json({
      message: 'Код подтверждения верен',
      otpauthUrl,
      encryptedSecret,
    });
  } catch (error) {
    handleRouteError(res, error, {
      logPrefix: 'Ошибка генерации или получения TOTP secret',
      status: 500,
      message: 'Ошибка при генерации 2FA',
    });
  }
});

export default {
  path: '/',
  router,
};
