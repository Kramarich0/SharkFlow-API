import express from 'express';
import { adminRouter } from './admin.js';
import rateLimit from 'express-rate-limit';

const app = express();

app.use('/admin', express.static('public'));
app.get('/admin', (req, res) => {
  res.redirect('/admin/resources/User');
});

if (process.env.NODE_ENV === 'production') {
  app.use('/admin', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
}

app.use('/admin', adminRouter);

import compression from 'compression';
import corsMiddleware from './middlewares/http/corsMiddleware.js';
import { limiterMiddleware } from './middlewares/http/limiterMiddleware.js';
import loadRoutes, { joinPaths } from './utils/routesLoader/loadRoutes.js';

import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import { logDatabaseError } from './utils/loggers/systemLoggers.js';
import { logInfo } from './utils/loggers/baseLogger.js';

app.use(
  morgan('combined', {
    stream: {
      write: (message) => logInfo('HTTP', 'request', message.trim()),
    },
  }),
);

import helmet from 'helmet';
import hpp from 'hpp';

app.use(helmet());
app.use(
  '/admin',
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
      },
    },
  }),
);

app.use(hpp());
app.use(corsMiddleware);

app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.set('trust proxy', true);

app.use('/auth', limiterMiddleware);
app.use('/tasks', limiterMiddleware);
app.use('/boards', limiterMiddleware);
app.use('/users', limiterMiddleware);

const routes = await loadRoutes();
routes.forEach(({ path, router }) => {
  const fullPath = '/' + joinPaths(process.env.API_PREFIX, path); 
  app.use(fullPath, router);

  if (router.stack) {
    router.stack.forEach(layer => {
      if (layer.route) {
        const methods = Object.keys(layer.route.methods)
          .map(m => m.toUpperCase())
          .join(', ');
        console.log(`${methods} ${fullPath}${layer.route.path}`);
      }
    });
  }
});

logInfo('System', 'routesLoaded', `Routes loaded: ${routes.length}`);

/**
 * Global Express error handling middleware.
 * Logs database-related errors and returns a JSON response with status code and error message.
 * 
 * @param {Error} err - The error object encountered.
 * @param {import('express').Request} req - The request object.
 * @param {import('express').Response} res - The response object.
 * @param {import('express').NextFunction} next - The next middleware function.
 */
app.use((err, req, res, next) => {
  logDatabaseError('unhandledError', err);
  const status = err.status || 500;
  return res.status(status).json({
    error: err.message || 'Внутренняя ошибка сервера',
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
});

/**
 * Fallback 404 middleware for handling undefined routes.
 * 
 * @param {import('express').Request} req - The request object.
 * @param {import('express').Response} res - The response object.
 * @returns {import('express').Response} A JSON response indicating the resource was not found.
 */
app.use((req, res) => {
  return res.status(404).json({ error: 'Ресурс не найден' });
});

export default app;