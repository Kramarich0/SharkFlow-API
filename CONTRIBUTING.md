# Development Guide & Quality Standards

## Local Setup & Testing
Ensure you have Node.js and a running PostgreSQL instance. The project uses `nodemon` for development and `prisma` for database management.

1.  **Install dependencies:**
    ```bash
    npm install
    ```
2.  **Database Setup:**
    Ensure your `DATABASE_URL` is configured in your environment, then run:
    ```bash
    npm run prisma:generate
    npm run prisma:migrate
    ```
3.  **Run Development Server:**
    ```bash
    npm run dev
    ```
4.  **Verification:**
    The application will start via [[server.js]], which bootstraps [[app.js]] and [[socket/index.js]].

## Pre-Commit Verification Checklist (Fragile Zones)
Before committing, verify changes in these high-risk modules. If modified, ensure you run relevant integration tests.

- [ ] [[utils/helpers/authHelpers.js]]: Warning: High inbound dependency coupling. Verify authentication flow integrity.
- [ ] [[utils/loggers/authLoggers.js]]: Warning: High churn and central dependency. Ensure logging does not crash on invalid input.
- [ ] [[utils/handlers/handleRouteError.js]]: Warning: Used by almost all routes. Verify error response consistency.
- [ ] [[utils/prismaConfig/prismaClient.js]]: Warning: Central DB connection. Ensure connection pooling is not leaked.
- [ ] [[utils/helpers/userHelpers.js]]: Warning: Core user logic. Validate user profile and session updates.
- [ ] [[middlewares/http/authenticateMiddleware.js]]: Warning: Critical security gate. Audit for unauthorized access bypass.

## Pre-Commit Security Checks
- **Secrets:** Never commit `.env` files. Use [[.env.example]] as a template.
- **SQL Injection:** The project uses [[prisma/schema.prisma]] with Prisma ORM. Ensure all raw queries (if any) use parameterized inputs.
- **Input Validation:** Use [[middlewares/http/validateMiddleware.js]] for all incoming request bodies.
- **Dependency Vulnerabilities:** The `package.json` includes `overrides` for `handlebars` and `axios`. Do not remove these without verifying updated versions are secure.

## PR Quality Standards & Review Gates
- **Branch Naming:** Use `feat/`, `fix/`, or `refactor/` prefixes followed by a short description (e.g., `feat/github-auth-fix`).
- **Documentation:** If adding new routes, update the internal route registry in [[utils/routesLoader/loadRoutes.js]].
- **Validation:** Every new route must implement validation using [[middlewares/http/validateMiddleware.js]].
- **Logging:** Use appropriate loggers (e.g., [[utils/loggers/authLoggers.js]], [[utils/loggers/taskLoggers.js]]) for all error paths.

## Change Playbooks

### Adding a New API Route
1.  Create the route file in the appropriate `routes/` subdirectory (e.g., [[routes/users/get/getUserRoute.js]]).
2.  Import necessary handlers and middlewares:
    *   [[middlewares/http/authenticateMiddleware.js]] for security.
    *   [[utils/handlers/handleRouteError.js]] for error wrapping.
3.  Register the route in [[utils/routesLoader/loadRoutes.js]].
4.  Add appropriate validation in [[middlewares/http/validateMiddleware.js]].

### Modifying Authentication Logic
1.  If changing the core auth flow, edit [[utils/helpers/authHelpers.js]].
2.  If adding a new OAuth provider, follow the pattern in [[routes/auth/github/connect/githubAuthRoute.js]].
3.  Always update the session handling in [[utils/helpers/authSessionHelpers.js]] if tokens or cookies are affected.

### Refactoring Database Models
1.  Modify [[prisma/schema.prisma]].
2.  Run migration: `npm run prisma:migrate`.
3.  Update dependent helpers:
    *   If user models changed, update [[utils/helpers/userHelpers.js]].
    *   If board/task models changed, update [[utils/helpers/boardHelpers.js]] or [[utils/helpers/taskHelpers.js]].