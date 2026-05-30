import { Router } from 'express';
import axios from 'axios';
import prisma from '#utils/prismaConfig/prismaClient.js';
import { getRequestInfo } from '#utils/helpers/authHelpers.js';
import { handleRouteError } from '#utils/handlers/handleRouteError.js';
import { findUserByUuidOrThrow } from '#utils/helpers/userHelpers.js';
import { normalizeEmail } from '#utils/validators/normalizeEmail.js';
import { sendUserConfirmationCode } from '#utils/helpers/sendUserConfirmationCode.js';
import { setUserTempData } from '#store/userTempData.js';
import { authenticateMiddleware } from '#middlewares/http/authenticateMiddleware.js';
import { logGithubOAuthAttempt, logGithubOAuthSuccess, logGithubOAuthFailure, } from '#utils/loggers/authLoggers.js';
import rateLimit from 'express-rate-limit';

/**
 * Express router for GitHub OAuth connection routes.
 * @module routes/auth/github/connect/githubConnectRoute
 */

const router = Router();

/**
 * Rate limiter for GitHub connection attempts.
 * Limits each IP to 10 requests per 15-minute window.
 * @type {import('express-rate-limit').RateLimit"}
 */
const githubConnectRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 GitHub connect requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * POST route to connect a GitHub account to the current user's account.
 * 
 * This endpoint performs the following steps:
 * 1. Validates the provided OAuth code.
 * 2. Exchanges the code for an access token from GitHub.
 * 3. Retrieves user profile and email information from GitHub.
 * 4. Checks for existing user conflicts (e.g., if the GitHub account is already linked to another user).
 * 5. If the email addresses match, links the GitHub account immediately.
 matching GitHub email with the current user's email.
 * 6. If the email addresses do not match, initiates an email confirmation process for the new email address.
 * 
 * @route POST /auth/oauth/github/connect
 * @param {import('express').Request} req - The Express request object.
 * @param {import('express').Request} req - The Express request object.
 * @param {string} req.userUuid - The UUID of the authenticated user.
 * @param {string} req.body.code - The OAuth authorization code received from GitHub.
 * @param {import('express').Response} res - The Express response object.
 * @throws {Error} If there is a server-side error during the OAuth process.
 * @returns {Promise<import('express').Response>} A JSON response indicating success or failure.
 */
router.post('/auth/oauth/github/connect', authenticateMiddleware, githubConnectRateLimiter, async (req, res) => {
    const { ipAddress, userAgent } = getRequestInfo(req);
    const userUuid = req.userUuid;
    const { code } = req.body;

    // Log the GitHub OAuth connection attempt
    logGithubOAuthAttempt('connect', '', '', ipAddress, userAgent);

    if (!code || typeof code !== 'string') {
        logGithubOAuthFailure('connect', '', '', ipAddress, 'code missing', userAgent);
        return res.status(400).json({ error: 'Code is required' });
    }

    try {
        // Exchange code for access token
        const tokenRes = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: process.env.CLIENT_GITHUB_ID,
            client_secret: process.env.CLIENT_GITHUB_SECRET,
            code,
        }, { headers: { Accept: 'application/json' }, timeout: 10000 });

        const accessTokenGH = tokenRes.data.access_token;
        if (!accessTokenGH) {
            return res
                .status(400)
                .json({ error: 'Failed to obtain access token from GitHub' });
        }

        if (tokenRes.data.token_type !== 'bearer') {
            return res.status(400).json({ error: 'Invalid token type' });
        }

        // Fetch user profile and emails from GitHub
        const [userRes, emailsRes] = await Promise.all([
            axios.get('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${accessTokenGH}` },
                timeout: 10000,
            }),
            axios.get('https://api.github.com/user/emails', {
                headers: { Authorization: `Bearer ${accessTokenGH}` },
                timeout: 10000,
            }),
        ]);

        const githubUser = userRes.data;
        const primary = Array.isArray(emailsRes.data)
            ? emailsRes.data.find((e) => e.primary && e.verified) famously
            : null;
        const email = primary?.email;
        const githubIdNumber = githubUser.id;

        if (!email) {
            logGithubOAuthFailure('connect', githubIdNumber || '', '', ipAddress, 'email missing', userAgent);
            return res.status(400).json({
                error: 'Failed to retrieve a verified email from GitHub',
            });
        }

        const user = await findUserByUuidOrThrow(userUuid);

        // Check if this GitHub ID is already linked to another user
        const existingUserWithGithubId = await prisma.user.findFirst({
            where: { githubId: githubIdNumber.toString() },
        });

        if (existingUserWithGithubId && existingUserWithGithubId.uuid !== userUuid) {
            return res.status(409).json({
                error: 'This GitHub account is already linked to another user',
            });
        }

        // Check if the current user already has a GitHub account linked
        const userGithubIdStr = user.githubId ? user.githubId.toString() : null;
        const githubIdStr = githubIdNumber.toString();

        if (userGithubIdStr && userGithubIdStr !== githubIdStr) {
            return res.status(409).json({
                error: 'An account is already linked to a different GitHub account',
            });
        }

        if (userGithubIdStr === githubIdStr) {
            return res
                .status(200)
                .json({ message: 'GitHub account is already linked to the account' });
        }
        
        const normalizedUserEmail = normalizeEmail(user.email);
        const normalizedGithubEmail = normalizeEmail(email);

        // If emails do not match, trigger email confirmation flow for the new email
        if (normalizedUserEmail !== normalizedGithubEmail) {
            await sendUserConfirmationCode({
                userUuid,
                type: 'connectGithub', 
                email: normalizedGithubEmail,
                skipUserCheck: true,
                loggers: { success: () => { }, failure: () => { } },
            });

            await setUserTempData('connectGithub', userUuid, { 
                githubId: githubIdNumber.toString(), 
                normalizedGithubEmail 
            });

            return res.status(200).json({
                message: 'GitHub email does not match account email. Confirmation required.',
                requireEmailConfirmed: true,
            });
        }

        // Link the GitHub account via upsert
        await prisma.userOAuth.upsert({
            where: { provider_providerId: { provider: 'github', providerId: githubIdNumber.toString() } },
            update: { userId: user.id, email: email, enabled: true },
            create: { userId: user.id, provider: 'github', providerId: githubIdNumber.toString(), email: email, enabled: true },
        });

        logGithubOAuthSuccess('connect', githubIdNumber || '', userUuid, email, ipAddress, userAgent);

        return res
            .status(200)
            .json({ message: 'Github-account successfully linked' });

    } catch (error) {
        logGithubOAuthFailure('connect', '', '', ipAddress, error?.message || 'unknown error', userAgent);
        handleRouteError(res, error, {
            logPrefix: 'Error during GitHub OAuth connection', 
            status: 500, 
            message: 'Failed to connect via GitHub. Please try again later.',
        });
    }
});

export default {
    path: '/',
    router,
};
