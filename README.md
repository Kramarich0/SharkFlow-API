# System Identity & Onboarding Blueprint

## Executive Summary
The system is a high-availability API backend (SharkFlow API) designed for task management and team collaboration. It leverages [[app.js]] as the core Express entrypoint, backed by a PostgreSQL database managed via Prisma ORM and a Redis instance for session state, rate limiting, and caching. The platform provides secure authentication (OAuth2, TOTP), real-time task board management, and integration with a Telegram bot for asynchronous task operations.

## Primary Entrypoints
*   [[app.js]]: The primary Express application bootstrap. Start here to understand the middleware chain, route mounting, and security configurations.
*   [[server.js]]: The HTTP server entrypoint. This initializes the server runtime and integrates the WebSocket layer.
*   [[socket/index.js]]: The entrypoint for WebSocket communication, essential for understanding real-time data synchronization.

## Knowledge Holders & Ownership Risks
*   **Ownership Status:** Unknown.
*   **Risk Analysis:** The repository exhibits a high bus-factor risk as key authentication and session management logic reside in highly complex, high-churn modules such as [[utils/helpers/authHelpers.js]] and [[routes/auth/login/loginRoute.js]]. Early inspection of these modules is strongly recommended for any architectural audit.

## Quick Start, Setup & Verification
### Prerequisites
*   Node.js (LTS version)
*   PostgreSQL instance
*   Redis instance

### Environment Configuration
Create a local `.env` file based on [[.env.example]]. Ensure the following critical variables are set:
*   `DATABASE_URL`: Connection string for your PostgreSQL instance.
*   `UPSTASH_REDIS_REST_URL` & `UPSTASH_REDIS_REST_TOKEN`: Credentials for Redis connectivity.
*   `TELEGRAM_BOT_TOKEN`: Required for bot functionality.

### Setup Instructions
1. Install dependencies:
   ```bash title="package.json"
   npm install
   ```
2. Generate Prisma client:
   ```bash title="package.json"
   npm run prisma:generate
   ```
3. Start the development environment:
   ```bash title="package.json"
   npm run dev
   ```

### Smoke Test / Verification
Verify the local build by querying the monitoring endpoint:
```bash
curl -X GET http://localhost:3000/api/v1/monitor
```
> [!NOTE]
> Ensure your `API_PREFIX` in `.env` matches the path used in the curl command. The expected response is `{"status":"ok"}`.

## Operating Model & Next Steps
The system operates as a stateful Express application relying on Redis for ephemeral data (e.g., confirmation codes, temporary registration data) and PostgreSQL for persistent domain state.

### Core Runtimes
*   **HTTP Layer:** Standard RESTful operations protected by `corsMiddleware` and `limiterMiddleware`.
*   **WebSocket Layer:** Real-time events managed in [[socket/handlers.js]].
*   **Background Tasks:** Cron jobs for maintenance tasks like guest account cleanup, managed in [[routes/cron/deleteOldGuestsRoute.js]].

### Recommended Documentation Review
1. Review [[prisma/schema.prisma]] to understand the data model relationships.
2. Examine [[utils/routesLoader/loadRoutes.js]] to understand how the API surface is dynamically constructed.
3. Consult the JSDoc generated documentation in [[docs/jsdoc-docolatte/]] for detailed function-level specifications.

> [!TIP]
> Before modifying authentication logic, review [[utils/handlers/handleRouteError.js]] to ensure consistent error reporting across all routes.