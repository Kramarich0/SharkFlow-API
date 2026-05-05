import jwt from 'jsonwebtoken';
import { isValidUUID } from '#utils/validators/boardValidators.js';
import { logAuthMiddlewareError } from '#utils/loggers/middlewareLoggers.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';

/**
 * Middleware to authenticate incoming HTTP requests using JWT and CSRF tokens.
 *
 * This middleware performs the following validation steps:
 * 1. Checks for a valid 'Authorization' header with a Bearer token.
 * 2. Verifies the JWT access token using the secret key.
 * 3. Validates that the user UUID in the token is a valid UUID format.
 * 4. Checks for the presence of an 'x-csrf-token' header.
 * 5. Verifies the CSRF token and ensures it matches the user UUID from the access token.
 *
 * If authentication succeeds, `userUuid` and `userRole` are attached to the request object.
 * If authentication fails, a 401 Unauthorized response is sent and the error is logged.
 *
 * @param {Object} req - The Express request object.
 * @param {Object} req.headers - Request headers.
 * @param {string} [req.headers.authorization] - Bearer token for authentication.
 * @param {string} [req.headers['x-csrf-token']] - CSRF token for cross-site request forgery protection.
 * @param {Object} res - The Express response object.
 * @param {Function} next - The Express next middleware function.
 * @returns {Object|void} Returns a 401 JSON response on failure, or calls next() on success.
 */
export function authenticateMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const csrfHeader = req.headers['x-csrf-token'];
  const { ipAddress, userAgent } = getRequestInfo(req);

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logAuthMiddlewareError(
      'invalidHeader',
      ipAddress,
      userAgent,
      new Error('Invalid auth header'),
    );
    return res
      .status(401)
      .json({ error: 'Недействительный заголовок авторизации' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
    });

    if (!isValidUUID(decoded.userUuid)) {
      logAuthMiddlewareError(
        'invalidUserUuid',
        ipAddress,
        userAgent,
        new Error('Invalid userUuid in token'),
      );
      return res.status(401).json({ error: 'Недействительный токен' });
    }

    if (!csrfHeader) {
      logAuthMiddlewareError(
        'missingCsrf',
        ipAddress,
        userAgent,
        new Error('Missing CSRF token'),
      );
      return res.status(401).json({ error: 'Отсутствует CSRF токен' });
    }

    try {
      const csrfPayload = jwt.verify(csrfHeader, process.env.JWT_CSRF_SECRET, {
        algorithms: ['HS256'],
      });

      if (csrfPayload.userUuid !== decoded.userUuid) {
        logAuthMiddlewareError(
          'csrfMismatch',
          ipAddress,
          userAgent,
          new Error('CSRF token mismatch'),
        );
        return res.status(401).json({ error: 'Недействительный CSRF токен' });
      }
    } catch (csrfErr) {
      logAuthMiddlewareError('invalidCsrf', ipAddress, userAgent, csrfErr);
      return res.status(401).json({ error: 'Недействительный CSRF токен' });
    }

    req.userUuid = decoded.userUuid;
    req.userRole = decoded.role || 'user';
    next();
  } catch (error) {
    logAuthMiddlewareError('invalidToken', ipAddress, userAgent, error);
    return res.status(401).json({ error: 'Недействительный токен' });
  }
}
