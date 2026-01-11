import { Router } from 'express';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import crypto from 'crypto';
import { v2 as cloudinary } from 'cloudinary';
import '#config/cloudinaryConfig.js';
import {
  logCloudinarySignatureAttempt,
  logCloudinarySignatureSuccess,
  logCloudinarySignatureFailure,
} from '#utils/loggers/authLoggers.js';

const router = Router();

router.get(
  '/cloudinary-signature',
  authenticateMiddleware,
  async (req, res) => {
    const userUuid = req.userUuid;
    const ip = req.ip;
    logCloudinarySignatureAttempt(userUuid, ip);
    const { api_key, api_secret } = cloudinary.config();

    if (!api_key || !api_secret) {
      logCloudinarySignatureFailure(userUuid, ip, 'Конфигурация отсутствует');
      return res.status(500).json({ error: 'Конфигурация отсутствует' });
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const upload_preset =
      process.env.NODE_ENV === 'production'
        ? process.env.CLOUDINARY_UPLOAD_PRECET
        : 'Precet-SharkFlow';
    const paramsToSign = {
      timestamp,
      upload_preset,
    };

    const toSign = Object.keys(paramsToSign)
      .sort()
      .map((key) => `${key}=${paramsToSign[key]}`)
      .join('&');

    const signature = crypto
      .createHmac('sha256', api_secret)
      .update(toSign)
      .digest('hex');

    logCloudinarySignatureSuccess(userUuid, ip);
    console.info(`Подпись: ${api_key} ${timestamp} ${signature}`);

    return res.json({
      api_key,
      timestamp,
      signature,
    });
  },
);

export default {
  path: '/',
  router,
};
