import express from 'express';
import { Router } from 'express';
import { deleteOldGuests } from '#utils/jobs/deleteOldGuests.js';
import { Receiver } from '@upstash/qstash';
import {
  logCronJobStart,
  logCronJobComplete,
  logCronJobError,
} from '#utils/loggers/systemLoggers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import rateLimit from 'express-rate-limit';

const receiver = new Receiver({
  currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
  nextSigningKey: process.env.QSTASH_NEXT_SIGNING_KEY,
});

const deleteOldGuestsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 1, // allow at most 1 request per window
  standardHeaders: true,
  legacyHeaders: false,
});

const router = Router();

router.post(
  deleteOldGuestsLimiter,
  '/cron/delete-old-guests',
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
  async (req, res) => {
    const signature = req.headers['upstash-signature'];
    const body = req.rawBody;
    const url = 'https://sharkflow-api.onrender.com/api/v1/cron/delete-old-guests';

    const {ipAddress, userAgent} = getRequestInfo(req)

    if (!receiver.verify({ body, signature, url })) {
      return res.status(403).send('Invalid signature');
    }

    try {
      logCronJobStart('deleteOldGuests', ipAddress);
      await deleteOldGuests();
      logCronJobComplete('deleteOldGuests', ipAddress, 'Success');
      res.json({ message: 'Cron job completed successfully' });
    } catch (err) {
      logCronJobError('deleteOldGuests', err, ipAddress);
      res.status(500).json({ error: 'Internal server error' });
    }
  },
);

export default {
  path: '/',
  router,
};
