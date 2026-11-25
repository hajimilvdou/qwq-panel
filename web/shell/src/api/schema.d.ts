// SPDX-License-Identifier: AGPL-3.0-only
// 由 scripts/gen-api.mjs 从 api/public/v1/openapi.yaml 生成，不要手改。
export type paths = {
    "/healthz": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Liveness probe
         * @description Returns 200 while the process is alive. Carries no internal detail; use `qwq doctor` for diagnostics.
         */
        get: operations["getHealth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/readyz": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Readiness probe
         * @description Returns 200 once the host accepts requests (database open, migrations applied, local agent
         *     connected), otherwise 503 `UNAVAILABLE`. Used by upgrades (ARCH §12) and load balancers.
         */
        get: operations["getReadiness"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/setup": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Report whether the installation is initialized
         * @description Unauthenticated. The Shell uses it to decide between the setup page and the login page.
         */
        get: operations["getSetupStatus"];
        put?: never;
        /**
         * Create the first administrator with the one-time setup token
         * @description ARCH §4.1.1. The installer prints a one-time link `https://<host>/setup#token=<setup_token>`
         *     (the token is in the fragment so it never reaches access logs), or the host listens only on
         *     `127.0.0.1` for setup over an SSH tunnel. The Shell posts the token with the first
         *     administrator's credentials. The token is compared in constant time, is rate limited and is
         *     invalidated on success. On success the response sets the session cookie, exactly like login.
         *     After setup this endpoint returns `409 STATE_CONFLICT`. A wrong or used token returns
         *     `401 UNAUTHENTICATED`.
         */
        post: operations["completeSetup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Log in with username and password
         * @description Without a second factor: `201`, sets the session cookie and returns the `Session`.
         *     With TOTP enabled: `200` with an `MfaChallenge` and no cookie; complete it with
         *     `POST /api/v1/sessions/mfa`. Failures return `401 UNAUTHENTICATED` without saying which
         *     part was wrong. Throttling is progressive per account and client IP (`429`), never a hard
         *     lockout (ARCH §4.1.1). The session ID is rotated on every login.
         */
        post: operations["createSession"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/mfa": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Complete login with a TOTP or recovery code
         * @description Second login step. A challenge is single use and expires after 5 minutes. A wrong code returns
         *     `401 UNAUTHENTICATED`; repeated failures are throttled like passwords.
         */
        post: operations["verifySessionMfa"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/current": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Return the current session and its CSRF token
         * @description The Shell calls this after a page load to obtain the CSRF token (kept in memory only) and the
         *     signed-in user. Returns `401` when the cookie is missing, expired or revoked.
         */
        get: operations["getCurrentSession"];
        put?: never;
        post?: never;
        /**
         * Log out
         * @description Revokes the session and clears the cookie. Repeating it is harmless.
         */
        delete: operations["deleteCurrentSession"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/current/mfa/totp": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Start a TOTP enrollment for the signed-in user
         * @description Returns a new secret and its `otpauth://` URL for the QR code, shown in this response only;
         *     confirm it with `POST /api/v1/sessions/current/mfa/totp/confirm` before `expires_at`.
         *     Starting again replaces an unconfirmed secret. When the user already has a second factor,
         *     the session must have passed it recently (15 minutes by default), otherwise
         *     `403 MFA_REQUIRED`: a stolen session must not swap the second factor. Human browser session
         *     with CSRF token only.
         */
        post: operations["beginTotpEnrollment"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/current/mfa/totp/confirm": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Confirm the pending TOTP secret and turn the second factor on
         * @description Verifies a code of the pending secret, turns the second factor on and returns the recovery
         *     codes, shown in this response only. The session keeps its cookie and CSRF token and is not
         *     counted as having passed a second factor: the code only proves the secret this session just
         *     created. Replacing a second factor that is already on needs a recent one (`403 MFA_REQUIRED`).
         *     No enrollment in progress, or an expired one, is `409 STATE_CONFLICT`; a wrong code is
         *     `400 VALIDATION_FAILED`. Human browser session with CSRF token only.
         */
        post: operations["confirmTotpEnrollment"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/current/mfa/totp/disable": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Turn the signed-in user's second factor off
         * @description Requires a current TOTP code or an unused recovery code in the body. A wrong code is
         *     `403 MFA_REQUIRED` and is charged to the same progressive backoff as approval codes (`429`).
         *     Deletes the TOTP secret and every recovery code. A POST rather than a DELETE because the
         *     code travels in a body. Human browser session with CSRF token only.
         */
        post: operations["disableTotp"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sessions/current/profile": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /**
         * Change the signed-in user's display name
         * @description Runs `host.account.update` on the caller's own user; the outcome's `result` is the updated
         *     `User`. Every role may change its own profile; the permission is human-only, so no AI
         *     operator or service account reaches it. `expected_revision` is the user's revision
         *     (`409 REVISION_CONFLICT` when stale). Human browser session with CSRF token only.
         */
        patch: operations["updateProfile"];
        trace?: never;
    };
    "/api/v1/sessions/current/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Change the signed-in user's password
         * @description Verifies the current password and applies the same policy as setup to the new one
         *     (violations point at `/new_password`). A wrong current password is `403 PERMISSION_DENIED`,
         *     not `401`, so the Shell stays signed in; guesses are throttled progressively (`429`).
         *     On success this session stays valid and every other session of the user is revoked.
         *     Human browser session with CSRF token only.
         */
        put: operations["changePassword"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollments": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Redeem an enrollment link into a first password and a session
         * @description The token comes from `POST /api/v1/users/{user_id}/enrollment-token`, handed to the user out
         *     of band. Sets the first password (same policy as setup) and, on success, sets the session
         *     cookie exactly like login. The token is single use: a wrong, used or expired token is
         *     `401 UNAUTHENTICATED` without saying which. Unauthenticated writes are rate limited per
         *     client IP (`429`).
         */
        post: operations["redeemEnrollment"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/private-exports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Prepare a session-bound private export
         * @description Prepares a five-minute handoff grant for the current human session. The grant binds the
         *     producer, action, node, instance, purpose and subject and does not authorize key generation.
         *     Generation still uses an approved operation. Private PEM never appears in its result.
         */
        post: operations["preparePrivateExport"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/private-exports/{export_id}/consume": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description ID of the private export prepared by this same human session. */
                export_id: string;
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Consume private material exactly once
         * @description Only the original live human session may consume a ready export. Consumption, audit and
         *     encrypted-secret removal commit together before delivery. Connection loss never reissues
         *     the private key. The response is a download, never an operation result or a JSON envelope.
         */
        post: operations["consumePrivateExport"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/private-exports/{export_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description ID of a grant prepared by this same human session. */
                export_id: string;
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Cancel a private handoff
         * @description Removes encrypted material in the original human session; already imported public keys are managed separately.
         */
        delete: operations["cancelPrivateExport"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List users
         * @description Cursor-paginated. Supports `fields` and `since_revision`.
         */
        get: operations["listUsers"];
        put?: never;
        /**
         * Create a user
         * @description Creates an operation for `host.users.create`. The caller never chooses the initial password:
         *     the result (`user`, `enrollment_pending`, `enrollment_expires_at`) only reports that the new
         *     user still has to enroll, and an administrator issues the one-time enrollment link with
         *     `POST /api/v1/users/{user_id}/enrollment-token`. No secret is ever part of the result.
         */
        post: operations["createUser"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users/{user_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get a user
         * @description Supports `fields`.
         */
        get: operations["getUser"];
        put?: never;
        post?: never;
        /**
         * Delete a user
         * @description Destructive: revokes the user's sessions and delegations. `expected_revision` is a query
         *     parameter because DELETE carries no body. Deleting the last administrator fails with
         *     `409 STATE_CONFLICT`.
         */
        delete: operations["deleteUser"];
        options?: never;
        head?: never;
        /**
         * Update a user's display name, role or disabled flag
         * @description Absent members are left unchanged. `expected_revision` is required.
         */
        patch: operations["updateUser"];
        trace?: never;
    };
    "/api/v1/users/{user_id}/enrollment-token": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Issue a one-time enrollment link for a user without a password
         * @description Returns the token of the link with which a new user chooses their first password; hand it
         *     to the user out of band, for example in the fragment of a URL so it never reaches access
         *     logs. The token is shown in this response only: it is never part of an operation, an event
         *     or the audit log, and the idempotent replay omits it. Issuing a link retires the user's
         *     earlier unused links. Enrollment never replaces a password: a user who already has one, or
         *     is disabled, gets `409 STATE_CONFLICT`.
         *
         *     **Human browser session with CSRF token only**, with `host.users:update` and a fresh second
         *     factor: either the session passed one recently (15 minutes by default) or the request
         *     carries a current `mfa_code`. Without one, or with a wrong code, the answer is
         *     `403 MFA_REQUIRED`; a delegation or service-account token gets `403 PERMISSION_DENIED`.
         */
        post: operations["issueEnrollmentToken"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/service-accounts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List automation service accounts (without bearer tokens)
         * @description Returns metadata for automation service accounts; plaintext bearer tokens are never returned.
         */
        get: operations["listServiceAccounts"];
        put?: never;
        /**
         * Create an automation service account (returns bearer token once)
         * @description Creates a scoped automation service account and returns its one-time bearer token in the creation response.
         */
        post: operations["createServiceAccount"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/service-accounts/{service_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Revoke a service account immediately
         * @description Revokes the specified service account immediately with optimistic revision concurrency.
         */
        delete: operations["deleteServiceAccount"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/service-accounts/renewal-bootstrap": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create a restricted account for a confirmed renewal policy
         * @description A current human session creates an operator account after high-risk approval. The host
         *     reads the certificate, DNS, CA, consumers and expiry from the confirmed private policy;
         *     callers cannot supply account permissions or credentials. The policy revision is checked
         *     again inside the account creation transaction. A matching valid account is reused.
         *     The operation result contains only `service_account_id`; no bearer token is returned.
         *     Attaching the account to the policy is a separate approved operation.
         */
        post: operations["bootstrapRenewalServiceAccount"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/delegations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the caller's delegations
         * @description Administrators may pass `owner=all`. Human sessions only.
         */
        get: operations["listDelegations"];
        put?: never;
        /**
         * Issue a delegation token for an AI operator
         * @description ADR-0004 D4. The effective permission of the token is always the owner's RBAC ∩ the policy
         *     below ∩ plugin capabilities. The token is returned once, in this response only; the stored
         *     idempotent replay omits `token` (revoke and issue a new delegation if it was lost).
         *     Human browser sessions only: a delegation or service-account token gets `403 PERMISSION_DENIED`.
         */
        post: operations["createDelegation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/delegations/{delegation_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Delegation identifier. */
                delegation_id: components["parameters"]["DelegationIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get a delegation
         * @description Never returns the token.
         */
        get: operations["getDelegation"];
        put?: never;
        post?: never;
        /**
         * Revoke a delegation
         * @description The token stops working immediately. Operations it already created keep running unless canceled.
         */
        delete: operations["deleteDelegation"];
        options?: never;
        head?: never;
        /**
         * Suspend, resume or narrow a delegation
         * @description Follow mode "pause" sets `status=suspended`; "take over" deletes the delegation (ADR-0004 D9).
         *     Suspension takes effect for new calls immediately; running operations are not canceled.
         */
        patch: operations["updateDelegation"];
        trace?: never;
    };
    "/api/v1/nodes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List managed nodes
         * @description A standalone installation returns exactly one node, `local` (ADR-0005 Q8).
         */
        get: operations["listNodes"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/enrollment-tokens": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Issue a one-time short-lived enrollment token for a remote node agent
         * @description Issues a one-time short-lived enrollment token for pairing a remote node agent via mTLS.
         */
        post: operations["createNodeEnrollmentToken"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/{node_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node identifier; `local` in a standalone installation. */
                node_id: components["parameters"]["NodeIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get a node
         * @description Supports `fields`.
         */
        get: operations["getNode"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/{node_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Revoke a remote node's mTLS certificate and disconnect its live session
         * @description Revokes a remote node's mTLS client certificate and disconnects any active agent session immediately.
         */
        post: operations["revokeNode"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List installed plugins
         * @description One entry per plugin with its local version rows, newest first.
         */
        get: operations["listPlugins"];
        put?: never;
        /**
         * Install a plugin from an uploaded package
         * @description Installs the package staged by `POST /api/v1/plugin-packages`. The plugin id and version are
         *     read from the signed manifest, never from the request. The caller must list the capabilities
         *     it accepts; the updater refuses capabilities the manifest does not declare and any new
         *     capability that was not accepted. The answer is synchronous because the host runs the install
         *     saga before responding; a long install is bounded by the updater's timeout.
         */
        post: operations["installPlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-packages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Upload a plugin package for installation
         * @description Stages a signed package in the host's private staging directory for at most 15 minutes. The
         *     multipart filename is ignored; only the bytes of the `package` part are used, and the package
         *     is not executed or verified until it is installed. `upload_id` is the only handle the later
         *     install/update call needs.
         */
        post: operations["uploadPluginPackage"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-packages/fetch": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Fetch a plugin package from a remote HTTPS URL
         * @description Downloads a signed `.qwqpkg` package from a public HTTPS URL (such as a GitHub Release
         *     asset) and stages it in the host's private staging directory through the same path as
         *     `POST /api/v1/plugin-packages`. The downloader enforces `https://` only, blocks loopback,
         *     RFC 1918, RFC 4193, link-local, CGNAT, multicast and unspecified IPs on both the initial
         *     request and every redirect hop, bounds the transfer to 64 MiB and 60 seconds, and verifies
         *     `expected_sha256` when provided.
         */
        post: operations["fetchPluginPackage"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-catalog": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List pre-built official plugins available for one-click install
         * @description Returns the official optional plugin catalog matched to this host's release version and
         *     CPU architecture (`linux/amd64` or `linux/arm64`), annotated with local installation and
         *     update availability status. Fetches and caches `plugins-index.json` from the official
         *     release mirror for 5 minutes and degrades cleanly to embedded metadata when offline.
         */
        get: operations["getPluginCatalog"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-trust-keys": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List trusted plugin publisher public keys
         * @description Returns all currently active Ed25519 publisher public keys trusted by the host, combining
         *     read-only official system keys (`/etc/qwq/trust`) and administrator-managed custom
         *     developer keys (`<data_dir>/trust/publishers`).
         */
        get: operations["listPluginTrustKeys"];
        put?: never;
        /**
         * Add a custom trusted plugin publisher public key
         * @description Validates and persists an Ed25519 PKIX public key PEM under the custom trust root so
         *     third-party plugins signed by that key pass inspection and installation immediately without
         *     restarting the controller. Human browser session only; requires a fresh second factor or
         *     `X-QWQ-MFA-Code` when the signed-in administrator has MFA enabled.
         */
        post: operations["addPluginTrustKey"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-trust-keys/{key_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Trusted publisher Ed25519 key identifier (`ed25519:<64 lower-case hex>`). */
                key_id: components["parameters"]["PluginTrustKeyIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Remove a custom trusted plugin publisher public key
         * @description Removes an administrator-added custom publisher key from the dynamic trust root and
         *     invalidates cached package inspections immediately. Official system keys cannot be removed
         *     (`403 PERMISSION_DENIED`). Human browser session only; requires a fresh second factor or
         *     `X-QWQ-MFA-Code` when MFA is enabled.
         */
        delete: operations["deletePluginTrustKey"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugin-packages/{upload_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque upload handle returned by `POST /api/v1/plugin-packages`. */
                upload_id: components["parameters"]["PluginUploadIdPath"];
            };
            cookie?: never;
        };
        /**
         * Inspect a staged plugin package
         * @description Verifies and parses a staged package without installing it: the signature verdict against the
         *     trust root, the manifest the package claims, the install-time compatibility problems and the
         *     memory and disk capacity preflights. Only the principal that uploaded the package may look;
         *     anyone else gets `404`, exactly like an unknown id. A signature refusal is still `200` with
         *     `signature.valid = false`, and the manifest is present whenever it parses safely. The result
         *     is cached per upload until it expires, so a repeated lookup does not verify the package
         *     again. Nothing is consumed: install and update still accept the same `upload_id`.
         */
        get: operations["inspectPluginPackage"];
        put?: never;
        post?: never;
        /**
         * Discard a staged plugin package
         * @description Deletes a staged plugin package owned by the calling principal so failed preflights or
         *     cancelled installs immediately release the per-account staging slot.
         */
        delete: operations["deletePluginPackage"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get an installed plugin
         * @description Supports `fields`.
         */
        get: operations["getPlugin"];
        put?: never;
        post?: never;
        /**
         * Uninstall a plugin, keeping its data by default
         * @description Uninstall (ARCH §6.6), always a job: `202` with the Operation, then the removal runs as a
         *     sequence of idempotent steps (stop the instances, remove the unit and version trees through
         *     the privileged helper, delete the rows), so a retry after a crash continues where it stopped.
         *     Configuration revisions and the plugin token are retained unless `purge_data=true`, which is
         *     destructive and requires a fresh second factor (`403 MFA_REQUIRED` otherwise). Blocked with
         *     `409 STATE_CONFLICT` while dependents exist; the problem's `dependents` lists them.
         */
        delete: operations["uninstallPlugin"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/update": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Update a plugin from an uploaded package
         * @description Replaces the active version with the package staged by `POST /api/v1/plugin-packages`. The
         *     systemd unit is per plugin, so the host always uses the controlled-restart strategy: the old
         *     process stops briefly and the new one starts. The version and plugin id come from the signed
         *     manifest; a package of another plugin is refused.
         */
        post: operations["updatePlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/rollback": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Roll a plugin back to its retained previous version
         * @description Switches the plugin back to its most recently activated retained version. The current version
         *     keeps its files, so a later update can move forward again. `expected_revision` optionally
         *     guards the active version the caller saw.
         */
        post: operations["rollbackPlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/restart": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Restart a plugin instance
         * @description Stops the running instance and starts it again with the active version and the active
         *     configuration. Like install, update and rollback this runs in the runtime's own lifecycle
         *     rather than the host operation executor's transaction, so it produces no operation record;
         *     the route writes the audit row. `reason` is optional free text for that row. The response is
         *     the refreshed plugin, so a card can update its runtime state without a second request.
         */
        post: operations["restartPlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/enable": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Enable a plugin
         * @description Persists the enablement flag and starts the active version. The flag survives a host restart:
         *     every unit start goes through the same gate, so a disabled plugin is never started by a
         *     dispatch, a recovery or a rollback. Queued as a job because the runtime call must not run
         *     inside the operation's write transaction.
         */
        post: operations["enablePlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/disable": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Disable a plugin
         * @description Persists the enablement flag and stops every instance of the plugin. The version rows, the
         *     configuration and the files are kept, so enabling it again restores the same version. A
         *     disabled plugin answers `503 PLUGIN_UNAVAILABLE` on dispatch.
         */
        post: operations["disablePlugin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/logs": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /**
         * Read a page of a plugin's journal
         * @description Reads the plugin unit's journal through the privileged helper, which only ever addresses
         *     `qwq-plugin@<id>.service` and truncates every line at 4 KiB. Lines are untrusted plugin
         *     output. Pages are oldest first within the page; `next_cursor` reads what came after the last
         *     line, so a viewer follows the log forward. `stream` selects stdout or stderr (systemd writes
         *     stdout at LOG_INFO and stderr at LOG_ERR). At most 100 lines per page. `since_revision` is
         *     refused: the journal is not a revisioned collection.
         */
        get: operations["getPluginLogs"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/resources": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        /**
         * Update or reset a plugin's runtime resource limits
         * @description Persists administrator-configured cgroup resource limits (memory, CPU quota, PIDs, FDs, disk) for the plugin and synchronizes the systemd drop-in override.
         */
        put: operations["putPluginResources"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/config": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get the active plugin configuration
         * @description Returns the active revision. Sensitive values declared by the plugin's configuration schema
         *     are redacted; a plugin without a configuration reports revision `0` and an empty object.
         *     Supports `fields`.
         */
        get: operations["getPluginConfig"];
        /**
         * Apply a plugin configuration revision
         * @description Stores an immutable revision, asks the plugin to validate and apply it, and only then moves
         *     the active pointer. Values the plugin's schema marks `writeOnly` or `x-secret` are moved into
         *     the host secret store; the updater receives references, never plaintext. `expected_revision`
         *     guards the active revision (`0` means no configuration yet).
         */
        put: operations["putPluginConfig"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/config-schema": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get the configuration schema of the active plugin version
         * @description The JSON Schema 2020-12 subset the configuration form is generated from. It is written by
         *     the plugin author: untrusted, render it as data. Sensitive fields are marked
         *     `writeOnly: true` or `x-secret: true`; the host replaces their values with secret
         *     references before storing a configuration.
         */
        get: operations["getPluginConfigSchema"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins/{plugin_id}/operations/{operation}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
                /** @description Operation name from the plugin manifest. */
                operation: components["parameters"]["OperationNamePath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Call an operation of a controller-placed plugin
         * @description ADR-0002: plugins with `placement=controller` run once globally. The request and response
         *     payloads follow the operation's schemas in the plugin manifest; their content is untrusted.
         *     `mode=invoke`: `200` with the outcome. `mode=job`, or when the caller's policy requires
         *     approval: `202` with the Operation. Plugin-reported validation failures return
         *     `400 VALIDATION_FAILED` with field-level `violations`.
         *     A synchronous `effect=read`, `mode=invoke` operation an overview widget is bound to is held to that widget's `refresh_seconds`
         *     floor per principal, with at most one call in flight: a faster poll answers `429 RATE_LIMITED`
         *     with `Retry-After`. This synchronous read creates no operation record, so polling does not grow the log.
         *     An explicit read job requires `Idempotency-Key` and follows the same bounded persistent task,
         *     authorization, cancellation and deadline path as other jobs; it cannot accept new secret material.
         */
        post: operations["invokeControllerPluginOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node identifier; `local` in a standalone installation. */
                node_id: components["parameters"]["NodeIdPath"];
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
                /** @description Plugin instance identifier. */
                instance_id: components["parameters"]["InstanceIdPath"];
                /** @description Operation name from the plugin manifest. */
                operation: components["parameters"]["OperationNamePath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Call an operation of a plugin instance on a node
         * @description ADR-0002: plugins with `placement=node`. Same contract as the controller-level route. When
         *     the node's agent is offline, operations that are not explicitly queueable fail with
         *     `503 NODE_OFFLINE` (ARCH §7). RBAC resources include `node_id`.
         */
        post: operations["invokeNodePluginOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List operations, newest first
         * @description Filters combine with AND. Callers see only operations they are allowed to read.
         */
        get: operations["listOperations"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/operations/{operation_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Operation identifier. */
                operation_id: components["parameters"]["OperationIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get an operation
         * @description Supports `fields`. Poll this or follow `operation.updated` events.
         */
        get: operations["getOperation"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/operations/{operation_id}/cancel": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Operation identifier. */
                operation_id: components["parameters"]["OperationIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Cancel an operation
         * @description `PENDING`, `AWAITING_APPROVAL` and `APPROVED` operations become `CANCELED` at once (`200`).
         *     A `RUNNING` operation gets `cancel_requested=true` and `202`; it ends as `CANCELED`, or as
         *     `SUCCEEDED`/`FAILED` if it could not stop in time. A terminal operation returns
         *     `409 STATE_CONFLICT`. No `expected_revision`: progress updates change the revision constantly
         *     and cancel must not race with them.
         */
        post: operations["cancelOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Preview an action without side effects
         * @description ADR-0004 D7. Validates the arguments, asks the plugin's `PlanOperation` when the action is
         *     plannable, computes the effective risk and records preconditions. Soft problems are returned
         *     inside the plan (`violations`, `warnings`, `executable=false`) so a caller sees all of them at
         *     once; only malformed requests and unknown actions fail with an error status. A plan is
         *     private to the principal that created it and expires after `plan_ttl_seconds`.
         *     Non-plannable actions still get a plan with empty `changes`, so plan → execute works for all.
         */
        post: operations["createPlan"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plan identifier. */
                plan_id: components["parameters"]["PlanIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get a plan
         * @description Only the principal that created the plan, and administrators, can read it.
         */
        get: operations["getPlan"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}/execute": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plan identifier. */
                plan_id: components["parameters"]["PlanIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create the operation that a plan previewed
         * @description A plan executes at most once. The host atomically re-checks host-side preconditions and passes
         *     plugin-side preconditions to the plugin; any mismatch fails the operation with
         *     `PRECONDITION_FAILED` (`409` when detected before the operation starts). An expired plan
         *     returns `409 PLAN_EXPIRED`; a plan with blocking violations returns `400 VALIDATION_FAILED`;
         *     a plan that already has an operation returns `409 STATE_CONFLICT` with that `operation_id`.
         *     Response codes follow the plugin operation routes: `200` when finished, `202` otherwise
         *     (including `AWAITING_APPROVAL`).
         */
        post: operations["executePlan"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/approvals": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List approvals
         * @description Approvals the caller can decide or has requested. Service accounts and the agent `read` tool
         *     can see the approvals of their own operations.
         */
        get: operations["listApprovals"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/approvals/{approval_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Approval identifier. */
                approval_id: components["parameters"]["ApprovalIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get an approval with its confirmation card data
         * @description `facts` are established by the host; `plugin_preview` comes from the plugin's PlanOperation
         *     and is untrusted. The Shell renders the confirmation card from these two parts only; no text
         *     written by the requesting AI is included (ADR-0004 D6).
         */
        get: operations["getApproval"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/approvals/{approval_id}/decision": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Approval identifier. */
                approval_id: components["parameters"]["ApprovalIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve or reject a pending approval
         * @description **Human browser session with CSRF token only.** A delegation token or service-account token
         *     always gets `403 PERMISSION_DENIED`, whatever its policy says (ADR-0004 D6, acceptance 3).
         *     When the action's effect is `destructive`, `mfa_code` is required; a missing or wrong code
         *     returns `403 MFA_REQUIRED` (the session stays valid). Codes are checked before the approval
         *     is looked up and count against a progressive backoff per user and client: after repeated
         *     wrong codes the endpoint returns `429 RATE_LIMITED` with `Retry-After`. An approval that already expired or was decided returns
         *     `409 STATE_CONFLICT`. Approving moves the operation to `APPROVED` and then `RUNNING`;
         *     rejecting moves it to `REJECTED`.
         */
        post: operations["decideApproval"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/actions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Search the action catalog as the signed-in person
         * @description **Human browser session only.** A delegation token or service-account token always gets
         *     `403 PERMISSION_DENIED`; AI operators use `POST /api/v1/agent/find_actions`, which answers for
         *     a delegation. The same local keyword search runs here (no model is called), filtered by the
         *     person's role: an action the role does not grant is absent. Routes marked
         *     `x-qwq-action-exempt` never enter the catalog. Without `q` the catalog is enumerated in its
         *     own order. Execution stays on the existing routes and `POST /api/v1/plans`; this route only
         *     reads. Summaries of plugin actions are untrusted.
         */
        get: operations["listActions"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/actions/{action_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Catalog identifier, percent-encoded (`/` becomes `%2F`). */
                action_id: components["schemas"]["ActionId"];
            };
            cookie?: never;
        };
        /**
         * Get one action's metadata and argument schema
         * @description **Human browser session only**, as `GET /api/v1/actions`. An action the person's role does not
         *     grant answers `404`, exactly like an unknown ID, so the catalog is not an existence oracle.
         *     `request_schema` is JSON Schema 2020-12; for a plugin action it comes from the package and is
         *     untrusted data, not instructions.
         */
        get: operations["getAction"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Query the audit log
         * @description **Human browser session with the administrator role only.** A service-account or delegation
         *     token gets `403 PERMISSION_DENIED`, and so does an operator or viewer: the log names every
         *     person and every change on the installation. Rows are newest first and paginate with
         *     `cursor`/`limit`; `from` and `to` are inclusive RFC 3339 bounds on the event time. `detail`
         *     passes a redaction whitelist before it is returned and never contains a token, password or
         *     key. Retention (`retention.audit`, default 365 days) bounds how far back the log goes.
         */
        get: operations["listAudit"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read the installation overview
         * @description Version, role, start time, TLS state and whether any plugin is enabled. `listen` and
         *     `data_dir` are returned to administrators only: they say where the panel is reachable and
         *     where its data lives.
         */
        get: operations["getSystem"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/metrics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read built-in real-time host CPU, memory, disk, and network metrics
         * @description Returns lightweight host resource telemetry and short in-memory sparkline history directly from the core panel framework without requiring external monitoring plugins.
         */
        get: operations["getSystemMetrics"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/security/takeover": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List coexistence firewall and fail2ban takeover status
         * @description Reports whether ufw, firewalld, or fail2ban is active, backed up, and taken over by qwq. Administrators only.
         */
        get: operations["getSecurityTakeover"];
        put?: never;
        /**
         * Back up and take over an existing firewall or fail2ban manager
         * @description Atomically backs up existing configuration, preserves active open ports in inet qwq, and disables the competing service so qwq manages it natively. Administrators only.
         */
        post: operations["postSecurityTakeover"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/security/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Restore a previously taken-over firewall or fail2ban manager
         * @description Clears qwq's conflicting takeover policy and re-enables the backed-up original manager service. Administrators only.
         */
        post: operations["postSecurityRestore"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/access": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read panel access port, secret entry path, disguise, and reverse-proxy domain settings
         * @description Returns the live panel listening port, secret entry path, stealth disguise policy, and reverse-proxy domain auto-disable state. Administrators only.
         */
        get: operations["getSystemAccess"];
        /**
         * Update panel listening port, secret entry path, disguise page, or reverse-proxy domain
         * @description Updates live panel access settings with optimistic revision checks. Changing the port performs a live hot-rebind; setting a reverse-proxy domain automatically disables the secret entry path and disguise when auto_disable_on_domain is enabled. Administrators only.
         */
        put: operations["putSystemAccess"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/backups": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List consistent system backup archives
         * @description Lists available host backup archives stored in the data directory backups folder. Administrators only.
         */
        get: operations["listSystemBackups"];
        put?: never;
        /**
         * Create a consistent system backup archive
         * @description Creates a new consistent tar.gz backup containing the database snapshot, master key, TLS material, agent workspace, configuration, and plugin state. Administrators only.
         */
        post: operations["createSystemBackup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/backups/{filename}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Download a system backup archive
         * @description Streams a validated backup tar.gz archive from the backups directory with Cache-Control no-store. Administrators only.
         */
        get: operations["downloadSystemBackup"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/support-bundle": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Export a redacted diagnostic support bundle
         * @description Generates and streams a redacted tar.gz diagnostic bundle containing build info, system status, scrubbed configuration, and recent logs. Administrators only.
         */
        post: operations["createSystemSupportBundle"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/network/facts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read live host IPv4/IPv6 addresses and default route facts
         * @description Inspects live host IPv4 and IPv6 addresses together with default route facts.
         */
        get: operations["getNetworkFacts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/network/policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read node dual-stack inbound/outbound network policy
         * @description Returns the current dual-stack inbound and outbound network policy for the node.
         */
        get: operations["getNetworkPolicy"];
        /**
         * Update node dual-stack inbound/outbound network policy
         * @description Updates the node dual-stack inbound and outbound network policy with optimistic revision concurrency.
         */
        put: operations["putNetworkPolicy"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/routing/profile": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read China split routing profile and active rule bundle digest
         * @description Returns the current China split routing profile and active rule bundle metadata.
         */
        get: operations["getRoutingProfile"];
        /**
         * Update China split routing profile and custom rules
         * @description Updates the China split routing profile and custom rules with optimistic revision concurrency.
         */
        put: operations["putRoutingProfile"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/routing/update-bundle": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Verify SHA-256 and atomically swap the MIT routing rule bundle
         * @description Verifies the SHA-256 digest and atomically activates a new MIT routing rule bundle.
         */
        post: operations["updateRoutingBundle"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/routing/preview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Preview client split decision, first-hop endpoints and second-hop outbound policy
         * @description Evaluates a target hostname or URL against the active routing profile and returns a read-only preview.
         */
        post: operations["previewRoutingTwoHop"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the caller's agent sessions
         * @description Only the sessions the caller owns. `status=attention` returns the sessions a floating window
         *     has to show (`waiting_approval` or `failed`); `status` may also be one exact
         *     `AgentSessionStatus`. Sessions are ordered newest first and paginate with `cursor`/`limit`;
         *     `since_revision` returns only sessions whose revision is newer.
         */
        get: operations["listAgentSessions"];
        put?: never;
        /**
         * Create an agent session
         * @description Creates a session owned by the caller. `core` is `native` by default and `permission_mode` is
         *     `safe` by default; `config` holds the core configuration of ADR-0010 and never a secret nor a
         *     secret reference (`api_key_secret` is rejected): the native core's API key is stored with
         *     `PUT /api/v1/agent-sessions/{session_id}/api-key`. An unknown `core`,
         *     `permission_mode` or an invalid config returns `422`.
         */
        post: operations["createAgentSession"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /**
         * Get a session with its recent transcript and pending approvals
         * @description A session of another principal answers `404`, whatever its identifier is. `messages` is the
         *     retained window (the host keeps the newest 200 messages); `content_json` carries the
         *     structured tool-call fragments.
         */
        get: operations["getAgentSession"];
        put?: never;
        post?: never;
        /**
         * Close a session and remove its transcript
         * @description Cancels a running turn, closes the event streams and deletes the session with its messages and
         *     tool calls. The operations audit keeps the record of what the agent did. `expected_revision`
         *     is optional; when present and stale the answer is `409 REVISION_CONFLICT`.
         */
        delete: operations["deleteAgentSession"];
        options?: never;
        head?: never;
        /**
         * Change a session's title or permission mode
         * @description Only the session's owner can change its permission mode; the mode is also never read from an
         *     agent turn, so an AI client cannot widen its own permissions (ADR-0010 §2.1). Switching to
         *     `read_only` rejects a pending write tool call that is waiting for approval; an operation that
         *     was already approved is not affected.
         */
        patch: operations["updateAgentSession"];
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/export": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /**
         * Export a session transcript as Markdown or JSON
         * @description Downloads the full retained transcript and metadata of the caller's agent session as a Markdown (.md) or JSON (.json) file.
         */
        get: operations["exportAgentSession"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/messages": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /**
         * Page backwards through a session's transcript
         * @description The retained messages with `seq` lower than `before_seq`, the newest `limit` of them,
         *     oldest first. Without `before_seq` the page starts at the newest message; without `limit`
         *     the snapshot window of `GET /api/v1/agent-sessions/{id}` is used. Only the owner reads a
         *     session: another principal's identifier answers `404`.
         */
        get: operations["listAgentMessages"];
        put?: never;
        /**
         * Send a user message and start the turn that answers it
         * @description The message is stored and the core runs asynchronously; progress arrives on the session event
         *     stream. A second send while a turn is running or waiting for an approval answers
         *     `409 STATE_CONFLICT`. `client_message_id` makes a retry idempotent: the same value returns the
         *     message the first attempt created instead of appending a second one.
         */
        post: operations["sendAgentMessage"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/api-key": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        /**
         * Store the native core's API key of a session
         * @description Replaces the session's API key. The key is encrypted as a secret owned by the session and is
         *     only ever sent as the bearer token of that session's model requests; it is deleted with the
         *     session. Only the owner can set it. Neither the key nor its reference is ever returned.
         */
        put: operations["setAgentSessionAPIKey"];
        post?: never;
        /**
         * Remove the native core's API key of a session
         * @description Deletes the session's API key; later model requests carry no Authorization header. Clearing
         *     a session without a key changes nothing.
         */
        delete: operations["clearAgentSessionAPIKey"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/cancel": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Cancel the current turn or a paused approval turn
         * @description Cooperative: a running turn is cancelled through its context (its tool calls are cancelled
         *     through operations), a turn waiting for an approval is rejected and ended. The terminal
         *     `turn.completed` event carries `cancelled`. Cancelling an idle session changes nothing.
         */
        post: operations["cancelAgentSession"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/events": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /**
         * Session event stream (SSE)
         * @description `text/event-stream`. Every domain frame has `id: <seq>` (the session's monotonic sequence,
         *     shared by messages and tool calls) and one `data:` line of a JSON `AgentSessionEvent`, in the
         *     order the host published it. `event: resync` precedes the backlog when the requested position
         *     is older than the retained ring; the client then reloads `GET /agent-sessions/{id}` and
         *     continues from `head_sequence`. `event: ready` carries the head and the heartbeat interval;
         *     `event: heartbeat` follows every 15 s while the turn is quiet. Resume with the
         *     `Last-Event-ID` header or the `last_event_id` query parameter. A closed browser does not
         *     cancel the turn.
         */
        get: operations["streamAgentSession"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-sessions/{session_id}/approvals": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /**
         * Pending approvals of one session
         * @description The tool calls of the session that wait for a human decision, with the plugin author's
         *     confirmation text. Deciding is done on `POST /api/v1/approvals/{approval_id}/decision` by a
         *     human browser session; the agent itself can never approve.
         */
        get: operations["listAgentSessionApprovals"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-cores": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the agent cores this host can run
         * @description The four cores of ADR-0010 in fixed order. `native` is the built-in core; the external
         *     CLIs are announced with `available: false` and a fixed reason until P6 wires their
         *     adapters. Any signed-in principal may read the list; a session picks a core at creation.
         */
        get: operations["listAgentCores"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-cores/auth": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List installation and official login status for external CLI agent cores
         * @description Returns installation detection, persistent official OAuth/token login state, and (for administrators) active device-code authorization progress for Codex, Claude Code, and OpenCode.
         */
        get: operations["listAgentCoreAuth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-cores/{core}/login": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description External CLI core identifier (codex, claude-code or opencode). */
                core: "codex" | "claude-code" | "opencode";
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Start official device-code login or import a setup token for an external CLI agent core
         * @description Starts an isolated official OAuth/device-code login process or stores an imported OAuth setup token / auth JSON under the core's isolated persistent credential directory. Administrators only.
         */
        post: operations["startAgentCoreLogin"];
        /**
         * Cancel active login or clear persisted official login credentials for an external CLI core
         * @description Cancels any in-flight login process and removes persisted official OAuth/token credentials for the specified external CLI core. Administrators only.
         */
        delete: operations["logoutAgentCore"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/entries": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List folders and files in the agent interactive exchange folder
         * @description Lists subfolders and files inside the shared agent interactive file exchange directory.
         */
        get: operations["listAgentExchangeEntries"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/mkdir": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create a subfolder inside the agent interactive exchange folder
         * @description Creates a new subfolder (including nested paths) inside the shared agent interactive exchange folder.
         */
        post: operations["mkdirAgentExchange"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/upload": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Upload one or more files into the agent interactive exchange folder
         * @description Accepts multipart/form-data file uploads into the root or a target subfolder of the agent interactive exchange folder.
         */
        post: operations["uploadAgentExchange"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/download": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Download a file or zipped subfolder from the agent interactive exchange folder
         * @description Streams a single file (or a .zip archive when targeting a folder) from the interactive exchange folder.
         */
        get: operations["downloadAgentExchange"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/preview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Preview a file inside the agent interactive exchange folder
         * @description Returns bounded inline text content or metadata for a file in the interactive exchange folder.
         */
        get: operations["previewAgentExchange"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/file": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Create or update a text file inside the agent interactive exchange folder
         * @description Atomically writes UTF-8 text content to a relative file path inside the interactive exchange folder.
         */
        put: operations["putAgentExchangeFile"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/rename": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Rename or move a file or folder inside the agent interactive exchange folder
         * @description Renames or moves a file or subfolder strictly within the interactive exchange folder.
         */
        post: operations["renameAgentExchange"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-exchange/entry": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Delete a file or subfolder from the agent interactive exchange folder
         * @description Deletes a file or subfolder recursively inside the interactive exchange folder.
         */
        delete: operations["deleteAgentExchangeEntry"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-workspace/files": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List files in the separated MCP, Skills, or per-core Prompts directory
         * @description Lists user-managed files inside the strictly separated agent workspace area (mcp, skills, or prompts). Administrators only.
         */
        get: operations["listAgentWorkspaceFiles"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-workspace/file": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read one file from the separated MCP, Skills, or Prompts directory
         * @description Returns the text content of a workspace file (such as CLAUDE.md, AGENTS.md, SYSTEM.md, SKILL.md, or servers.json). Administrators only.
         */
        get: operations["getAgentWorkspaceFile"];
        /**
         * Create, update, or upload a file into MCP, Skills, or Prompts
         * @description Saves edited text or a drag-and-drop uploaded file into the isolated agent workspace directory and mirrors per-core prompt files to their CLI home. Administrators only.
         */
        put: operations["putAgentWorkspaceFile"];
        post?: never;
        /**
         * Delete a file or skill directory from MCP, Skills, or Prompts
         * @description Removes a file or a skill folder inside the isolated agent workspace area. Administrators only.
         */
        delete: operations["deleteAgentWorkspaceFile"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-registry": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Search built-in official Skills and MCP repositories
         * @description Searches the curated and live-cached official repositories (anthropics/skills, openai/skills, modelcontextprotocol/servers) with installation status.
         */
        get: operations["searchAgentRegistry"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent-registry/install": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Download and install an official Skill or MCP server into the agent workspace
         * @description Downloads an official Skill SKILL.md from the whitelisted upstream repository or adds an official MCP server entry into mcp/servers.json. Administrators only.
         */
        post: operations["installAgentRegistryItem"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ai/providers/fetch-models": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Fetch available model identifiers from an OpenAI or Anthropic compatible endpoint
         * @description Queries the endpoint's /models list through the host's outbound egress policy, using either an existing provider_id or unsaved base_url + api_key values. Administrators only.
         */
        post: operations["fetchAIProviderModels"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ai/providers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the global AI providers
         * @description Every configured provider, ordered by identifier. An administrator sees the full resource
         *     including `base_url`; every other signed-in principal gets the reduced projection
         *     (`provider_id`, `name`, `model`, `is_default`, `has_api_key`) — the address of the
         *     installation's model traffic is an administrator's concern (GAPS 缺口 2). The list is
         *     bounded and not paginated.
         */
        get: operations["listAIProviders"];
        put?: never;
        /**
         * Add a global AI provider
         * @description Runs `host.ai_providers.create` on the caller; the outcome's `result` of `OperationDone` is
         *     the created `AiProvider`. Administrator only and human browser session only (ADR-0017): the
         *     resource decides where the installation sends model traffic, so no AI operator and no
         *     service account reaches it (the permission is human-only). `is_default` makes the new
         *     provider the one sessions without their own endpoint use and clears the previous default.
         *     The API key is not part of the resource; store it with `PUT …/api-key` afterwards.
         */
        post: operations["createAIProvider"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ai/providers/{provider_id}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Remove a global AI provider and its API key
         * @description Runs `host.ai_providers.delete` on the provider; the stored API key is deleted in the same
         *     transaction. `expected_revision` is a query parameter because DELETE carries no body. The
         *     default provider is refused with `409 STATE_CONFLICT` while another provider exists, so a
         *     delete cannot leave the installation without a usable default by accident. Administrator
         *     only, human browser session only. Destructive: the operation's approval needs a second
         *     factor (ADR-0004 D6).
         */
        delete: operations["deleteAIProvider"];
        options?: never;
        head?: never;
        /**
         * Change a global AI provider
         * @description Runs `host.ai_providers.update` on the provider; the outcome's `result` is the updated
         *     `AiProvider`. Absent members are left unchanged; `expected_revision` is required
         *     (`409 REVISION_CONFLICT` when stale). Changing `base_url` removes the stored API key: the
         *     key is bound to the address it was entered for, so the new address never receives it
         *     (re-enter the key after moving a provider). Administrator only, human browser session only.
         */
        patch: operations["updateAIProvider"];
        trace?: never;
    };
    "/api/v1/ai/providers/{provider_id}/api-key": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        /**
         * Store or replace a provider's API key
         * @description The key is encrypted as a secret owned by `ai_providers/<provider_id>` with the purpose
         *     `agent.native.api_key` and is only ever sent as the Authorization header of requests to
         *     this provider's `base_url`; it is deleted with the provider and when `base_url` changes.
         *     Catalog-exempt: the plaintext must not reach an operation record or an idempotent replay
         *     (GAPS 缺口 2); the audit row records the change without the value. Administrator only,
         *     human browser session only.
         */
        put: operations["setAIProviderAPIKey"];
        post?: never;
        /**
         * Remove a provider's API key
         * @description Deletes the provider's stored key; later requests to the provider carry no Authorization
         *     header. Clearing a provider without a key changes nothing. Catalog-exempt; audited.
         *     Administrator only, human browser session only.
         */
        delete: operations["clearAIProviderAPIKey"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ai/providers/{provider_id}/test": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Probe a provider's connectivity
         * @description One GET of `{base_url}/models` through the same outbound-controlled client the session
         *     turns use (AGT-03): a private destination is refused unless `agent.model_egress_allow`
         *     opens it. The answer only says whether it worked, how long it took and, on failure, the
         *     class — never the address, the exact status code or the response body. Administrator only,
         *     human browser session only.
         */
        post: operations["testAIProvider"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Subscribe to the event stream (SSE)
         * @description Server-sent events (`text/event-stream`). One connection per browser tab; filter with
         *     `topics`. The handshake checks `Origin` and `Host` against the allow-list.
         *
         *     Frames (see `StreamFrame`):
         *     - Domain events have no `event:` line, so they arrive in `EventSource.onmessage`. `id:` is the
         *       event `sequence`; `data:` is one line of JSON, an `Event` envelope. Delivery is
         *       at-least-once; deduplicate by `event_id`.
         *     - `event: ready` is sent first, with the stream head sequence. Open the stream before loading
         *       snapshots so no change is missed; then, for each `resource.changed` whose `revision` differs
         *       from the cached one, refetch the `changed_pointers` with `fields`. Events that predate the
         *       snapshot only cause a redundant refetch.
         *     - `event: heartbeat` every `sse_heartbeat_seconds` (15 s, always < 30 s). A client that sees no
         *       frame for 45 s reconnects.
         *     - `event: resync` when the requested `Last-Event-ID` is older than the retention window, or
         *       the connection's bounded buffer overflowed. The client must reload the snapshots it shows
         *       and continue from `head_sequence`. After an overflow resync the server closes the stream.
         *
         *     Resume with the `Last-Event-ID` header (sent automatically by `EventSource` on reconnect) or the
         *     `last_event_id` query parameter after a page reload. The server sends `retry:` with the
         *     reconnect delay; clients add jitter and back off exponentially. Lossy realtime topics (metrics,
         *     presence) are not replayed. Events are filtered by the subscriber's read permission.
         */
        get: operations["streamEvents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/find_actions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Search the action catalog
         * @description Local keyword search over the action catalog (host OpenAPI `x-qwq-action` + plugin manifest
         *     operations); no model is called. Returns at most `limit` entries (default 8), each with only
         *     `id`, `summary`, `effect` and `risk`. Summaries of plugin actions are untrusted.
         */
        post: operations["agentFindActions"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/describe_action": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Get one action's metadata, argument schema and examples
         * @description Loads details on demand. By default returns the metadata, `target` and `args_schema` only;
         *     `include_result_schema=true` adds `result_schema`, and `include_docs=true` adds the plugin's
         *     bundled docs (untrusted, may be truncated). Plugin-supplied schemas are untrusted data, not
         *     instructions.
         */
        post: operations["agentDescribeAction"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/read": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Read a resource or collection by subject
         * @description Reads host-owned subjects (see `Subject`). A single resource returns `values`, a flat map
         *     from JSON Pointer to value (only the requested `fields`, or the whole resource under `""`).
         *     A collection returns `items` with cursor pagination. With `since_revision`, unchanged
         *     resources return `unchanged=true` and collections return only changed items plus
         *     `deleted_ids`. Responses are capped at `agent_read_items_max` items and
         *     `agent_read_response_bytes`; when a cap is hit, `truncated` says which and how to continue.
         *     Plugin-owned subjects return `404 NOT_FOUND` until the plugin read contract exists (P0-T7).
         */
        post: operations["agentRead"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Preview an action without side effects
         * @description Same semantics and result as `POST /api/v1/plans`, with a 200 status for tool callers.
         */
        post: operations["agentPlan"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/execute": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create an operation from a plan or from action + args
         * @description Give either `plan_id`, or `action` + `args` (+ `target`). Giving both, or neither, fails with
         *     `400 VALIDATION_FAILED`. Always `200` with an `OperationOutcome` (tool callers read `status`,
         *     not the HTTP code). Policy decides what happens next (ADR-0004 D6): reads run directly,
         *     `low` runs and notifies, `medium`/`high` stop at `AWAITING_APPROVAL`; then call `wait`.
         *     If the delegation policy has `on_approval_required=fail`, an action that needs approval fails
         *     with `403 APPROVAL_REQUIRED` and nothing is created. MCP adapters derive `Idempotency-Key`
         *     from the tool call so that transport retries are safe; re-executing an already executed plan
         *     returns `409 STATE_CONFLICT` with its `operation_id`.
         */
        post: operations["agentExecute"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/wait": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Long-poll an operation until it ends or needs approval
         * @description Server-side long poll. Returns as soon as the operation is terminal (`SUCCEEDED`, `FAILED`,
         *     `CANCELED`, `REJECTED`, `EXPIRED`), or enters `AWAITING_APPROVAL` when it was not already
         *     in that state at call time, or after `timeout_seconds` with `timed_out=true` and the current
         *     status. Waiting on an operation already in `AWAITING_APPROVAL` therefore waits for the
         *     decision. At most `agent_concurrent_waits_per_delegation` concurrent waits; beyond that
         *     `429 RATE_LIMITED`. `timeout_seconds` is capped below common reverse-proxy read timeouts.
         */
        post: operations["agentWait"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/agent/cancel": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Cancel an operation
         * @description Same semantics as `POST /api/v1/operations/{operation_id}/cancel`, always `200` with the
         *     outcome (a running operation shows `cancel_requested=true`). A delegation can cancel only
         *     operations it created.
         */
        post: operations["agentCancel"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
};
export type webhooks = Record<string, never>;
export type components = {
    schemas: {
        /**
         * @description RFC 9457 Problem Details with qwq extension members. `type` is `urn:qwq:problem:<code>`,
         *     `title` is the fixed English title of the code, `detail` describes this occurrence.
         *     Never contains stack traces, SQL or file paths.
         */
        Problem: {
            /**
             * Format: uri-reference
             * @description Problem type URI, derived from `code`.
             */
            type: string;
            /** @description Short fixed title of the code. */
            title: string;
            /**
             * Format: int32
             * @description HTTP status code.
             */
            status: number;
            /** @description Human-readable explanation. Untrusted when `code` is `PLUGIN_ERROR` (plugin text). */
            detail?: string;
            /**
             * Format: uri-reference
             * @description Request path or operation URL.
             */
            instance?: string;
            code: components["schemas"]["ProblemCode"];
            /** @description Whether repeating the same request may succeed. */
            retryable: boolean;
            /**
             * Format: int32
             * @description Seconds before a retry; mirrors `Retry-After`.
             */
            retry_after?: number;
            /** @description Host-generated request ID, also in the `X-Request-Id` response header. */
            request_id: string;
            /** @description Field-level problems (`VALIDATION_FAILED`); at most `violations_max`. */
            violations?: components["schemas"]["FieldViolation"][];
            /** @description More violations existed than were returned. */
            violations_truncated?: boolean;
            current_revision?: components["schemas"]["Revision"];
            /** @description `PRECONDITION_FAILED`: the preconditions that no longer hold. */
            failed_preconditions?: components["schemas"]["FailedPrecondition"][];
            /** @description The operation this error belongs to, or the existing operation for `STATE_CONFLICT` on plan execution. */
            operation_id?: string;
            node_id?: components["schemas"]["NodeId"];
            effective_risk?: components["schemas"]["RiskLevel"];
            /** @description `PAYLOAD_TOO_LARGE` and `RATE_LIMITED`: which limit was hit. */
            limit?: {
                /** @description Limit name from `x-qwq-limits`, e.g. `max_body_bytes`. */
                name: string;
                /**
                 * Format: int64
                 * @description The configured maximum.
                 */
                max: number;
            };
            /** @description With `STATE_CONFLICT` on a removal, the plugins that still require it. */
            dependents?: components["schemas"]["PluginId"][];
            /** @description `PLUGIN_ERROR`: the machine-readable code reported by the plugin. */
            plugin_code?: string;
        };
        /**
         * @description Machine-readable error code. New codes may be added without a breaking change; clients treat an
         *     unknown code like its HTTP status class. Mapping:
         *
         *     | code | HTTP | retryable | meaning |
         *     |---|---|---|---|
         *     | `VALIDATION_FAILED` | 400 | no | Malformed request or invalid arguments; see `violations` |
         *     | `UNAUTHENTICATED` | 401 | no | Missing/expired credentials, failed login or setup token |
         *     | `MFA_REQUIRED` | 403 | no | Destructive approval or enrollment link without a fresh second factor |
         *     | `CSRF_FAILED` | 403 | no | Missing or wrong CSRF token, or cross-site request |
         *     | `PERMISSION_DENIED` | 403 | no | RBAC, delegation policy or credential type not allowed |
         *     | `APPROVAL_REQUIRED` | 403 | no | Needs approval and the policy says `on_approval_required=fail` |
         *     | `NOT_FOUND` | 404 | no | No such resource or route, or not visible to the caller |
         *     | `METHOD_NOT_ALLOWED` | 405 | no | Route exists, method does not |
         *     | `REVISION_CONFLICT` | 409 | no | `expected_revision` differs; see `current_revision` |
         *     | `PRECONDITION_FAILED` | 409 | no | A plan precondition no longer holds; plan again |
         *     | `PLAN_EXPIRED` | 409 | no | The plan passed `expires_at`; plan again |
         *     | `STATE_CONFLICT` | 409 | no | Not allowed in the resource's current state |
         *     | `IDEMPOTENCY_IN_PROGRESS` | 409 | yes | Same key still processing; retry after `retry_after` |
         *     | `PAYLOAD_TOO_LARGE` | 413 | no | Body size or JSON depth limit; see `limit` |
         *     | `UNSUPPORTED_MEDIA_TYPE` | 415 | no | Body is not `application/json` |
         *     | `IDEMPOTENCY_KEY_REUSED` | 422 | no | Same key with a different request fingerprint |
         *     | `PLUGIN_ERROR` | 422 | per plugin | Plugin-reported failure; see `plugin_code` |
         *     | `RATE_LIMITED` | 429 | yes | Rate or quota limit; retry after `retry_after` |
         *     | `INTERNAL` | 500 | yes | Unexpected host error; details only in logs under `request_id` |
         *     | `UNAVAILABLE` | 503 | yes | Host not ready (startup, upgrade, maintenance) |
         *     | `INSUFFICIENT_STORAGE` | 507 | yes | Not enough free disk space for a plugin package; retry after cleanup or an expiry |
         *     | `NODE_OFFLINE` | 503 | yes | Target node's agent is disconnected; see `node_id` |
         *     | `PLUGIN_UNAVAILABLE` | 503 | yes | Plugin not running, cold-starting or quarantined |
         *     | `TIMEOUT` | 504 | yes | Plugin or node missed the operation deadline |
         *
         *     Plugin errors whose code matches a host code (`VALIDATION_FAILED`, `PRECONDITION_FAILED`,
         *     `REVISION_CONFLICT`) are passed through with that code; all others become `PLUGIN_ERROR`.
         *     `INTERNAL` is retryable only together with the same `Idempotency-Key`.
         * @enum {string}
         */
        ProblemCode: "VALIDATION_FAILED" | "UNAUTHENTICATED" | "MFA_REQUIRED" | "CSRF_FAILED" | "PERMISSION_DENIED" | "APPROVAL_REQUIRED" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" | "REVISION_CONFLICT" | "PRECONDITION_FAILED" | "PLAN_EXPIRED" | "STATE_CONFLICT" | "IDEMPOTENCY_IN_PROGRESS" | "PAYLOAD_TOO_LARGE" | "UNSUPPORTED_MEDIA_TYPE" | "IDEMPOTENCY_KEY_REUSED" | "PLUGIN_ERROR" | "RATE_LIMITED" | "INTERNAL" | "UNAVAILABLE" | "INSUFFICIENT_STORAGE" | "NODE_OFFLINE" | "PLUGIN_UNAVAILABLE" | "TIMEOUT";
        /**
         * @description One field-level problem; same shape as proto `FieldViolation`. Also used for warnings.
         *     For body fields `pointer` is an RFC 6901 JSON Pointer into the request body; for parameters it
         *     is `/<parameter name>` and `in` names the location.
         */
        FieldViolation: {
            /**
             * @description Where the offending value is.
             * @default body
             * @enum {string}
             */
            in: "body" | "query" | "header" | "path";
            pointer: components["schemas"]["JsonPointer"];
            /** @description Machine-readable reason, e.g. `REQUIRED`, `PORT_IN_USE`. */
            code: string;
            /** @description Human-readable message; untrusted when produced by a plugin. */
            message: string;
        };
        /** @description Optimistic concurrency guard captured by a plan; same shape as proto `Precondition`. */
        Precondition: {
            subject: components["schemas"]["Subject"];
            revision: components["schemas"]["Revision"];
        };
        /** @description A precondition that did not hold at execution time. */
        FailedPrecondition: {
            subject: components["schemas"]["Subject"];
            expected_revision: components["schemas"]["Revision"];
            /** @description Current revision; null when the resource no longer exists. */
            current_revision?: components["schemas"]["Revision"] | null;
        };
        /**
         * @description Opaque resource version. Changes on every committed modification. Compare for equality only;
         *     do not parse, order or do arithmetic on it. On collections it is a watermark for `since_revision`.
         * @example 42
         */
        Revision: string;
        /** @description Opaque pagination cursor. */
        Cursor: string;
        /**
         * @description RFC 6901 JSON Pointer; `""` is the whole document.
         * @example /inbounds/0/port
         */
        JsonPointer: string;
        /** @description Opaque host-assigned identifier. */
        ResourceId: string;
        /**
         * @description Node identifier; a standalone installation has the single node `local`.
         * @example local
         */
        NodeId: string;
        /**
         * @description Plugin identifier; same pattern as the manifest `id`.
         * @example com.example.monitor
         */
        PluginId: string;
        /**
         * @description Plugin instance identifier, unique per node and plugin. The first instance is `default`.
         * @example default
         */
        InstanceId: string;
        /**
         * @description Operation name; same pattern as the manifest `operations[].name`.
         * @example scan.run
         */
        OperationName: string;
        /**
         * @description Catalog identifier. Host actions: `host.<resource>.<verb>` (from `x-qwq-action.id`). Plugin
         *     actions: `<plugin_id>/<operation>`. The `/` cannot occur in host IDs, so the two never collide.
         * @example host.users.create
         * @example com.example.monitor/scan.run
         */
        ActionId: string;
        /**
         * @description Canonical resource name used in events, preconditions and the agent `read` tool: the resource
         *     path relative to `/api/v1/`. Host-owned: `users/<id>`, `nodes/<id>`, `plugins/<id>`,
         *     `operations/<id>`, `approvals/<id>`, `delegations/<id>`, and the collections `users`, `nodes`,
         *     `plugins`, `operations`, `approvals`. Plugin-owned (the host prefixes what the plugin reports):
         *     `nodes/<node_id>/plugins/<plugin_id>/instances/<instance_id>/resources/<path>` for node
         *     placement and `plugins/<plugin_id>/resources/<path>` for controller placement.
         * @example users/u_01J9Z3
         * @example nodes/local/plugins/com.example.monitor/instances/default/resources/alerts/cpu
         */
        Subject: string;
        /** @description Event journal sequence (uint64 as a decimal string, so JavaScript keeps full precision). */
        Sequence: string;
        /** @description Idempotency key token. */
        IdempotencyKeyValue: string;
        /**
         * Format: date-time
         * @description RFC 3339 timestamp in UTC.
         */
        Timestamp: string;
        /**
         * @description Risk level (ADR-0004 D6).
         * @enum {string}
         */
        RiskLevel: "low" | "medium" | "high";
        /**
         * @description What an action does to state (ADR-0004 D5).
         * @enum {string}
         */
        Effect: "read" | "write" | "destructive";
        /**
         * @description `invoke` answers synchronously; `job` is long-running and returns 202.
         * @enum {string}
         */
        Mode: "invoke" | "job";
        /**
         * @description When the host asks the user before running an operation (ADR-0010 §2). `auto`: only the host
         *     hard rules ask; `confirm`: every call asks; `ai_confirm`: calls from an `ai_agent` (a
         *     delegation) ask, people and service accounts do not. A plugin operation without a
         *     declaration derives it from its effect: read → `auto`, write and destructive → `confirm`.
         *     A destructive effect and an effective risk of `high` always ask (a host hard rule), except
         *     that a `full` permission mode drops the risk rule.
         * @enum {string}
         */
        ApprovalLevel: "auto" | "confirm" | "ai_confirm";
        /**
         * @description User-selected permission mode of an agent session or a delegation (ADR-0010 §2.1); safe by
         *     default. It is a ceiling: `read_only` refuses every write operation without queueing an
         *     approval; `safe` asks for `confirm`, `ai_confirm`, destructive and high-risk operations;
         *     `full` skips the plugin-level approvals and the high-risk rule but still asks for an
         *     irreversible destructive operation; `custom` keeps the level-based rule and will grow
         *     per-item overrides. An AI client can never change the mode: it comes from the session or
         *     delegation record, never from a request body.
         * @enum {string}
         */
        PermissionMode: "read_only" | "safe" | "full" | "custom";
        /**
         * @description Operator type (ADR-0004 D4); proto `ActorKind` without the `ACTOR_KIND_` prefix.
         * @enum {string}
         */
        ActorKind: "human" | "ai_agent" | "service" | "system";
        /**
         * @description Who caused a change; set by the host, mirrors proto `Actor`. `id` is a user ID (`human`),
         *     a delegation ID (`ai_agent`), a service-account ID (`service`) or a host component name
         *     (`system`, e.g. `reconciler`). `on_behalf_of` is the user whose authority is used, for
         *     `ai_agent` and `service`.
         */
        Actor: {
            kind: components["schemas"]["ActorKind"];
            /** @description Actor identifier. */
            id: string;
            /** @description User ID of the delegating human. */
            on_behalf_of?: string;
            /** @description Host-known display name, e.g. "AI (on behalf of alice)". */
            display_name?: string;
        };
        /**
         * @description Where an action runs. Host actions use only `subject`. Node-placed plugin actions need
         *     `node_id`, `plugin_id` and `instance_id`; controller-placed ones need `plugin_id`.
         *     `subject` names the resource being changed, when there is one.
         */
        Target: {
            node_id?: components["schemas"]["NodeId"];
            plugin_id?: components["schemas"]["PluginId"];
            instance_id?: components["schemas"]["InstanceId"];
            subject?: components["schemas"]["Subject"];
        };
        /** @description `Target` as accepted in requests. */
        TargetInput: {
            node_id?: components["schemas"]["NodeId"];
            plugin_id?: components["schemas"]["PluginId"];
            instance_id?: components["schemas"]["InstanceId"];
            subject?: components["schemas"]["Subject"];
        };
        /**
         * @description Catalog metadata of an action; the same fields as a plugin manifest operation (ADR-0004 D5) and
         *     as the `x-qwq-action` extension on host routes. `risk` here is the effective risk
         *     (declared risk raised to the capability floor); `declared_risk` is what the author declared.
         */
        ActionMeta: {
            id: components["schemas"]["ActionId"];
            /** @description One-line summary; untrusted for plugin actions. */
            summary: string;
            effect: components["schemas"]["Effect"];
            risk: components["schemas"]["RiskLevel"];
            declared_risk?: components["schemas"]["RiskLevel"];
            mode: components["schemas"]["Mode"];
            /** @description Repeating the action with the same arguments has no further effect. */
            idempotent: boolean;
            /** @description The action implements a structured preview (`PlanOperation`). */
            plannable: boolean;
            undo?: components["schemas"]["ActionId"];
            /** @description Shell route for follow mode. */
            ui_route?: string;
            /** @description RBAC permission, e.g. `host.users:create`. */
            permission?: string;
            /**
             * Format: int32
             * @description Execution deadline.
             */
            timeout_ms?: number;
            /**
             * @description Whether the action is defined by the host or a plugin.
             * @enum {string}
             */
            source: "host" | "plugin";
            plugin_id?: components["schemas"]["PluginId"];
            /**
             * @description Plugin placement; absent for host actions.
             * @enum {string}
             */
            placement?: "node" | "controller";
            approval?: components["schemas"]["ApprovalLevel"];
            /** @description Confirmation-card title written by the plugin author; absent for host actions. */
            approval_summary?: string;
            /** @description Expandable confirmation text written by the plugin author (Markdown, plain text only); absent for host actions. */
            approval_description?: string;
            /**
             * @description The action can cut the administrator off from the server or the panel (firewall, SSH,
             *     panel listener or TLS; ADR-0016). The host clamps such an action to risk `high` and
             *     approval at least `ai_confirm` when the manifest is loaded, forces the flag from the
             *     capabilities the action may use, and shows a lockout warning before it runs.
             */
            reachability?: boolean;
        };
        /** @description Compact catalog entry returned by `find_actions`. */
        ActionSummary: {
            id: components["schemas"]["ActionId"];
            /** @description One-line summary; untrusted for plugin actions. */
            summary: string;
            effect: components["schemas"]["Effect"];
            risk: components["schemas"]["RiskLevel"];
        };
        /**
         * @description One page of the catalog as the signed-in person may use it. Actions their role does not grant
         *     are absent, and `truncated` says more matches exist than this page shows.
         */
        ActionList: {
            items: components["schemas"]["ActionMeta"][];
            /** @description More matches exist than this page shows. */
            truncated: boolean;
        };
        /** @description `ActionMeta` plus the argument schema, which a list page leaves out. */
        ActionDetail: components["schemas"]["ActionMeta"] & {
            /** @description JSON Schema of the request payload; for a plugin action it comes from the package. */
            request_schema: Record<string, unknown>;
        };
        /**
         * @description Result of the audited event.
         * @enum {string}
         */
        AuditOutcome: "success" | "failure" | "denied";
        /**
         * @description One audit row. `detail` has passed a redaction whitelist: only reviewed non-secret members
         *     are returned, never a token, password, key or secret reference, and never a nested object.
         */
        AuditEntry: {
            audit_id: components["schemas"]["ResourceId"];
            at: components["schemas"]["Timestamp"];
            actor: components["schemas"]["Actor"];
            /** @description Stable dotted name, e.g. `host.users.create` or `auth.login`. */
            action: string;
            /** @description Resource subject; empty for authentication events. */
            subject: string;
            outcome: components["schemas"]["AuditOutcome"];
            operation_id?: components["schemas"]["ResourceId"];
            node_id?: components["schemas"]["NodeId"];
            /** @description Gateway request identifier of the event. */
            request_id?: string;
            /** @description Whitelisted non-secret facts; absent when nothing passed the whitelist. */
            detail?: Record<string, unknown>;
        };
        /**
         * @description One page of the audit log, newest first. The pagination members live under `meta`: audit rows
         *     carry no revision, so this is not a revisioned collection and `since_revision` does not apply.
         */
        AuditPage: {
            items: components["schemas"]["AuditEntry"][];
            /** @description Pagination of the audit log. */
            meta: {
                next_cursor?: components["schemas"]["Cursor"];
            };
        };
        /**
         * @description ADR-0004 D7 state machine:
         *
         *     ```text
         *     PENDING ─▶ AWAITING_APPROVAL ─▶ APPROVED ─▶ RUNNING ─▶ SUCCEEDED / FAILED / CANCELED
         *                    ├─▶ REJECTED
         *                    └─▶ EXPIRED      (approval not decided within approval_ttl_seconds)
         *     PENDING ─▶ RUNNING              (no approval needed)
         *     PENDING / AWAITING_APPROVAL / APPROVED ─▶ CANCELED   (cancel before start)
         *     PENDING / APPROVED ─▶ FAILED                         (e.g. PRECONDITION_FAILED before start)
         *     ```
         *
         *     Terminal: `SUCCEEDED`, `FAILED`, `CANCELED`, `REJECTED`, `EXPIRED`.
         * @enum {string}
         */
        OperationStatus: "PENDING" | "AWAITING_APPROVAL" | "APPROVED" | "REJECTED" | "EXPIRED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "CANCELED";
        /** @description Latest progress report of a job; mirrors proto `JobProgress`. */
        OperationProgress: {
            /**
             * Format: int32
             * @description Completion estimate.
             */
            percent?: number;
            /** @description Machine-readable step ID, used by follow mode. */
            step?: string;
            /** @description Progress text from the plugin or node. Untrusted; render as plain text. */
            message?: string;
        };
        /**
         * @description The unified record of a state change (ARCH §7). `operation_id + attempt` identifies one
         *     execution; non-idempotent operations are never retried automatically.
         */
        Operation: {
            operation_id: components["schemas"]["ResourceId"];
            action: components["schemas"]["ActionId"];
            status: components["schemas"]["OperationStatus"];
            target: components["schemas"]["Target"];
            actor: components["schemas"]["Actor"];
            effective_risk: components["schemas"]["RiskLevel"];
            plan_id?: components["schemas"]["ResourceId"];
            approval_id?: components["schemas"]["ResourceId"];
            /**
             * Format: int32
             * @description Execution attempt, starting at 1.
             */
            attempt: number;
            /** @description A cancel was requested while running. */
            cancel_requested?: boolean;
            progress?: components["schemas"]["OperationProgress"];
            /**
             * @description Result payload when `SUCCEEDED`; follows the action's response schema. Untrusted for plugin
             *     actions. Secret fields are replaced by references. Only the actor that started the operation
             *     and callers that hold the permission of its action see it; other readers get the operation
             *     without `result`.
             */
            result?: unknown;
            error?: components["schemas"]["Problem"];
            /** @description Shell route of the action, for follow mode. */
            ui_route?: string;
            created_at: components["schemas"]["Timestamp"];
            updated_at: components["schemas"]["Timestamp"];
            finished_at?: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description Compact view of an operation for synchronous answers and agent tools: only what a caller needs
         *     to decide its next step. `operation_id` is empty for synchronous `effect=read`, `mode=invoke` plugin actions (no record).
         */
        OperationOutcome: {
            /** @description Operation identifier; empty only for synchronous read invokes. */
            operation_id: string;
            action: components["schemas"]["ActionId"];
            status: components["schemas"]["OperationStatus"];
            effective_risk?: components["schemas"]["RiskLevel"];
            approval_id?: components["schemas"]["ResourceId"];
            /** @description A cancel was requested while running. */
            cancel_requested?: boolean;
            progress?: components["schemas"]["OperationProgress"];
            /** @description Result payload when `SUCCEEDED`. Untrusted for plugin actions. */
            result?: unknown;
            error?: components["schemas"]["Problem"];
            /** @description `wait` only: the timeout elapsed before a state worth reporting. */
            timed_out?: boolean;
            revision?: components["schemas"]["Revision"];
        };
        /** @description Optional cancel details. */
        CancelRequest: {
            /** @description Recorded in the audit log. */
            reason?: string;
        };
        /**
         * @description Pagination and increment metadata shared by list responses. `revision` is the collection
         *     watermark to pass as `since_revision` next time; on multi-page reads it is fixed by the first
         *     page, so use the value from the last page. `next_cursor` is absent on the last page.
         */
        ListMeta: {
            next_cursor?: components["schemas"]["Cursor"];
            revision: components["schemas"]["Revision"];
            /** @description `true`: only changes since `since_revision`; `false`: a full snapshot. */
            delta: boolean;
            /** @description With `delta=true`, IDs removed since `since_revision`. */
            deleted_ids?: string[];
        };
        /** @description A page of operations. */
        OperationList: components["schemas"]["ListMeta"] & {
            /** @description Operations. */
            items: components["schemas"]["Operation"][];
        };
        /**
         * @description What to preview. For host actions, `args` holds the route's path parameters and body members
         *     flattened into one object (including `expected_revision`); for plugin actions it is the
         *     operation payload. `expected_revision` + `target.subject` add a precondition on that subject.
         */
        PlanRequest: {
            action: components["schemas"]["ActionId"];
            /** @description Action arguments, validated against the action's schema. */
            args: Record<string, unknown>;
            target?: components["schemas"]["TargetInput"];
            expected_revision?: components["schemas"]["Revision"];
        };
        /**
         * @description One change a plan would make; mirrors proto `PlannedChange`. `source=plugin` entries come from
         *     the plugin's `PlanOperation` and are untrusted previews; `source=host` entries are computed by
         *     the host. Secret values appear only as references.
         */
        PlannedChange: {
            /**
             * @description Change kind.
             * @enum {string}
             */
            kind: "create" | "update" | "delete";
            subject: components["schemas"]["Subject"];
            pointer?: components["schemas"]["JsonPointer"];
            /** @description Value before the change (absent for create). */
            before?: unknown;
            /** @description Value after the change (absent for delete). */
            after?: unknown;
            /** @description The author claims this change can be undone. */
            reversible?: boolean;
            /**
             * @description Who produced this entry.
             * @enum {string}
             */
            source: "host" | "plugin";
            plugin_id?: components["schemas"]["PluginId"];
        };
        /**
         * @description Side-effect free preview bound to a later execution (ADR-0004 D7). `args_digest` is the SHA-256
         *     of the RFC 8785 canonical arguments; execution uses exactly these arguments.
         */
        Plan: {
            plan_id: components["schemas"]["ResourceId"];
            action: components["schemas"]["ActionId"];
            target: components["schemas"]["Target"];
            /** @description Public arguments with sensitive values and internal references redacted. An opaque argument object is represented by {"$redacted":true}. */
            args?: Record<string, unknown>;
            /** @description Digest of the canonical arguments. */
            args_digest: string;
            /** @description `false`: the action has no structured preview and `changes` is empty. */
            plannable: boolean;
            /** @description Previewed changes. */
            changes: components["schemas"]["PlannedChange"][];
            /** @description More changes existed than were returned. */
            changes_truncated?: boolean;
            /** @description Blocking problems; any entry makes `executable=false`. */
            violations: components["schemas"]["FieldViolation"][];
            /** @description Non-blocking problems. */
            warnings: components["schemas"]["FieldViolation"][];
            /** @description Revisions that must still hold at execution. */
            preconditions: components["schemas"]["Precondition"][];
            effective_risk: components["schemas"]["RiskLevel"];
            /** @description Executing this plan as the current caller will stop at `AWAITING_APPROVAL`. */
            requires_approval: boolean;
            /** @description The approval will require a second factor. */
            requires_mfa?: boolean;
            /** @description No blocking violations. */
            executable: boolean;
            /** @description Set once the plan was executed. */
            operation_id?: string;
            created_at: components["schemas"]["Timestamp"];
            expires_at: components["schemas"]["Timestamp"];
        };
        /**
         * @description `CANCELED`: the operation was canceled while waiting.
         * @enum {string}
         */
        ApprovalStatus: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CANCELED";
        /**
         * @description What the host itself knows about the operation, rendered first on the confirmation card
         *     (ADR-0004 D6). Nothing here is written by the requesting AI, and the only plugin-authored
         *     members are the catalog `summary` and the `approval_summary`/`approval_description` text of
         *     ADR-0010, all marked untrusted. `permission_mode` says which mode the calling session or
         *     delegation ran with, so the approver can see why the decision was asked for.
         */
        ApprovalFacts: {
            action: components["schemas"]["ActionMeta"];
            /** @description Public execution arguments with sensitive values and internal references redacted. An opaque argument object is represented by {"$redacted":true}. */
            args: Record<string, unknown>;
            /** @description Digest of the canonical arguments. */
            args_digest?: string;
            target: components["schemas"]["Target"];
            /** @description Host-known display name of the target node. */
            node_name?: string;
            /** @description Capabilities the action uses (name + scope), which determine the risk floor. */
            required_capabilities: {
                /** @description Capability name. */
                name: string;
                /** @description Capability scope. */
                scope: string;
            }[];
            effect: components["schemas"]["Effect"];
            declared_risk: components["schemas"]["RiskLevel"];
            effective_risk: components["schemas"]["RiskLevel"];
            /** @description An `undo` action exists for this action. */
            reversible: boolean;
            undo?: components["schemas"]["ActionId"];
            requested_by: components["schemas"]["Actor"];
            /** @description The plugin author's confirmation-card title, shown as "from plugin"; absent for host actions. */
            approval_summary?: string;
            /** @description The plugin author's explanation behind "show details"; Markdown rendered as plain text; absent for host actions. */
            approval_description?: string;
            permission_mode?: components["schemas"]["PermissionMode"];
        };
        /** @description A request for a human decision on one operation. */
        Approval: {
            approval_id: components["schemas"]["ResourceId"];
            operation_id: components["schemas"]["ResourceId"];
            plan_id?: components["schemas"]["ResourceId"];
            status: components["schemas"]["ApprovalStatus"];
            facts: components["schemas"]["ApprovalFacts"];
            /** @description The plan's changes and warnings as reported by the plugin; shown as "from plugin". */
            plugin_preview?: {
                /** @description Previewed changes. */
                changes?: components["schemas"]["PlannedChange"][];
                /** @description Warnings. */
                warnings?: components["schemas"]["FieldViolation"][];
            };
            /** @description Deciding requires `mfa_code` (destructive actions). */
            requires_mfa: boolean;
            decided_by?: components["schemas"]["Actor"];
            decided_at?: components["schemas"]["Timestamp"];
            /** @description The approver's comment. */
            comment?: string;
            created_at: components["schemas"]["Timestamp"];
            expires_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /** @description A page of approvals. */
        ApprovalList: components["schemas"]["ListMeta"] & {
            /** @description Approvals. */
            items: components["schemas"]["Approval"][];
        };
        /** @description The decision. */
        ApprovalDecisionRequest: {
            /**
             * @description Approve or reject.
             * @enum {string}
             */
            decision: "approve" | "reject";
            expected_revision: components["schemas"]["Revision"];
            /** @description Optional comment, recorded in the audit log. */
            comment?: string;
            /** @description Current TOTP code; required when `requires_mfa`. */
            mfa_code?: string;
        };
        /**
         * @description Session lifecycle (design §2). `idle`: no turn is running; `running`: one turn is running;
         *     `waiting_approval`: the turn paused on a human decision; `cancelled` and `failed`: the last
         *     turn ended that way, and a new message may start another one. `attention` is only valid as
         *     the `status` list filter: it selects `waiting_approval` and `failed` for the floating window.
         * @enum {string}
         */
        AgentSessionStatus: "idle" | "running" | "waiting_approval" | "cancelled" | "failed" | "attention";
        /**
         * @description The replaceable core of a session. `native` is the host's built-in OpenAI-compatible core;
         *     the external CLI/ACP cores (`claude-code`, `codex`, `opencode`, `dsh`, `acp`) answer
         *     `503 UNAVAILABLE` on send when their backing CLI binary is unavailable on the host (ADR-0010 §6).
         * @enum {string}
         */
        AgentCore: "native" | "claude-code" | "codex" | "opencode" | "dsh" | "acp";
        /**
         * @description State of one tool call an agent proposed.
         * @enum {string}
         */
        AgentToolStatus: "proposed" | "running" | "awaiting_approval" | "succeeded" | "failed" | "rejected" | "cancelled";
        /**
         * @description One agent session (design §2). `config` is the core configuration and never contains a
         *     secret: the native core's API key is write-only and only shown as `has_api_key`. `revision` is the concurrency guard
         *     of the session row; `last_seq` is the highest published session sequence.
         */
        AgentSession: {
            session_id: components["schemas"]["ResourceId"];
            plugin_id: components["schemas"]["PluginId"];
            /** @description Title chosen by the user; rendered as plain text. */
            title: string;
            core: components["schemas"]["AgentCore"];
            permission_mode: components["schemas"]["PermissionMode"];
            status: components["schemas"]["AgentSessionStatus"];
            /** @description Core configuration; never contains a secret or a secret reference. */
            config: Record<string, unknown>;
            /** @description Whether the owner stored an API key for the native core (PUT .../api-key). */
            has_api_key: boolean;
            /**
             * Format: int64
             * @description Highest session sequence published so far.
             */
            last_seq: number;
            /**
             * Format: int32
             * @description Tool calls waiting for a human decision.
             */
            pending_approvals: number;
            last_message_at?: components["schemas"]["Timestamp"];
            /** @description Head of the newest transcript entry (plain text */
            last_message_preview?: string;
            created_at: components["schemas"]["Timestamp"];
            updated_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One transcript entry. `content` is plain text for a client; `content_json` is the structured
         *     fragment of a tool call (an assistant step) or of a tool result. Both can carry text produced
         *     by a model or a plugin and are untrusted.
         */
        AgentSessionMessage: {
            /**
             * Format: int64
             * @description Session sequence; also the SSE event id.
             */
            seq: number;
            /** @description Stable message identifier. */
            message_id: string;
            /**
             * @description Author of the entry.
             * @enum {string}
             */
            role: "user" | "assistant" | "system" | "tool";
            /** @description Plain-text form; model or plugin output is untrusted. */
            content: string;
            /** @description Structured tool-call or tool-result fragment. */
            content_json?: unknown;
            operation_id?: components["schemas"]["ResourceId"];
            approval_id?: components["schemas"]["ResourceId"];
            created_at: components["schemas"]["Timestamp"];
        };
        /**
         * @description One awaiting tool call with the confirmation-card text of the operation. `summary` and
         *     `description` are written by the plugin author (ADR-0010 §4) and are untrusted.
         */
        AgentSessionApproval: {
            /** @description Tool call identifier. */
            call_id: string;
            approval_id: components["schemas"]["ResourceId"];
            operation_id?: components["schemas"]["ResourceId"];
            action: components["schemas"]["ActionId"];
            /** @description Proposed arguments with sensitive values and internal references redacted. An opaque argument object is represented by {"$redacted":true}. */
            args?: Record<string, unknown>;
            /** @description Confirmation-card title from the plugin author. */
            summary?: string;
            /** @description Expandable confirmation text from the plugin author (plain text). */
            description?: string;
            risk?: components["schemas"]["RiskLevel"];
            approval?: components["schemas"]["ApprovalLevel"];
            status: components["schemas"]["AgentToolStatus"];
            deadline?: components["schemas"]["Timestamp"];
            created_at: components["schemas"]["Timestamp"];
        };
        /** @description The pending approvals of a session. */
        AgentSessionApprovalList: {
            /** @description Pending approvals */
            items: components["schemas"]["AgentSessionApproval"][];
        };
        /** @description One page of a session transcript (GET /agent-sessions/{id}/messages). */
        AgentSessionMessageList: {
            /** @description Messages with seq below before_seq */
            items: components["schemas"]["AgentSessionMessage"][];
        };
        /** @description In-memory buffered streaming content of an active turn not yet persisted to SQLite. */
        AgentSessionInFlight: {
            /** @description Identifier of the assistant message currently streaming. */
            message_id: string;
            /** @description Buffered reasoning/thinking text so far. */
            reasoning?: string;
            /** @description Buffered assistant reply text so far. */
            content: string;
            /**
             * Format: int64
             * @description Latest runtime event sequence covered by this snapshot.
             */
            head_seq: number;
        };
        /** @description A session with its recent transcript and pending approvals. */
        AgentSessionDetail: components["schemas"]["AgentSession"] & {
            /** @description Retained transcript */
            messages: components["schemas"]["AgentSessionMessage"][];
            /** @description Pending approvals of this session. */
            approvals: components["schemas"]["AgentSessionApproval"][];
            /** @description Present when a turn is actively streaming unpersisted tokens. */
            in_flight?: components["schemas"]["AgentSessionInFlight"];
        };
        /** @description A page of agent sessions. */
        AgentSessionList: components["schemas"]["ListMeta"] & {
            /** @description Sessions */
            items: components["schemas"]["AgentSession"][];
        };
        /**
         * @description Session settings. Every member is optional: the defaults are the title "New session", core
         *     `native`, permission mode `safe` and the empty config.
         */
        AgentSessionCreateRequest: {
            /** @description Display title; control characters are rejected. */
            title?: string;
            core?: components["schemas"]["AgentCore"];
            permission_mode?: components["schemas"]["PermissionMode"];
            /** @description Core configuration; `api_key_secret` is a secret reference, never a plaintext key. */
            config?: Record<string, unknown>;
        };
        /**
         * @description Members to change; at least one of `title`, `permission_mode`, and `config` must be present.
         *     `expected_revision` is the revision the client last saw.
         */
        AgentSessionUpdateRequest: {
            /** @description New display title. */
            title?: string;
            permission_mode?: components["schemas"]["PermissionMode"];
            /** @description Partial core configuration patch (provider_id, auth_mode, model, reasoning_effort, max_context_tokens, plan_mode); plaintext secrets are rejected. */
            config?: Record<string, unknown>;
            expected_revision: components["schemas"]["Revision"];
        };
        /** @description One user message. */
        AgentSendMessageRequest: {
            /** @description Message text; the core receives it as untrusted input. */
            content: string;
            /** @description Optional idempotency key of the send; a retry with the same value returns the stored message. */
            client_message_id?: string;
        };
        /** @description The stored message and the session state the turn was started for. */
        AgentSendMessageResponse: {
            session: components["schemas"]["AgentSession"];
            message: components["schemas"]["AgentSessionMessage"];
        };
        /** @description The native core's API key. Write-only; never returned. */
        AgentSessionAPIKeyRequest: {
            /** @description Visible ASCII; surrounding whitespace is dropped. */
            api_key: string;
        };
        /** @description Optional reason recorded with the cancelled turn. */
        AgentSessionCancelRequest: {
            /** @description Free-text reason shown in the transcript. */
            reason?: string;
        };
        /**
         * @description One event of a session stream. `seq` is the session sequence and the SSE `id`; the sequence is
         *     shared by messages and tool calls and only grows. `turn.completed.status` is one of `idle`,
         *     `waiting_approval`, `cancelled` and `failed`.
         */
        AgentSessionEvent: {
            /**
             * @description Event type.
             * @enum {string}
             */
            type: "message.delta" | "message.completed" | "tool_call" | "tool_result" | "approval_required" | "approval_decided" | "turn.completed" | "error";
            /**
             * Format: int64
             * @description Session sequence.
             */
            seq: number;
            session_id?: components["schemas"]["ResourceId"];
            /** @description Message this frame belongs to. */
            message_id?: string;
            /** @description Text appended to the assistant message (message.delta). */
            delta?: string;
            /** @description Tool call this frame belongs to. */
            call_id?: string;
            action?: components["schemas"]["ActionId"];
            /** @description Proposed tool arguments with sensitive values and internal references redacted. An opaque argument object is represented by {"$redacted":true}. */
            args?: Record<string, unknown>;
            risk?: components["schemas"]["RiskLevel"];
            approval?: components["schemas"]["ApprovalLevel"];
            /** @description Tool status (tool_result) or turn outcome (turn.completed). */
            status?: string;
            /** @description Tool result as reported by operations. */
            result?: unknown;
            error?: components["schemas"]["AgentSessionError"];
            approval_id?: components["schemas"]["ResourceId"];
            operation_id?: components["schemas"]["ResourceId"];
            /** @description Plugin author's confirmation-card title (approval_required). */
            summary?: string;
            /** @description Plugin author's confirmation text (approval_required). */
            description?: string;
            deadline?: components["schemas"]["Timestamp"];
            /**
             * @description The human decision (approval_decided).
             * @enum {string}
             */
            decision?: "approve" | "reject";
            /** @description The approver's comment (approval_decided). */
            comment?: string;
            /** @description Stable problem code (error). */
            code?: string;
            /** @description Human-readable error detail (error). */
            detail?: string;
            /** @description The calls of an assistant step (message.completed). */
            tool_calls?: components["schemas"]["AgentSessionMessageToolCall"][];
            at?: components["schemas"]["Timestamp"];
        };
        /** @description Error code and detail inside a session event. */
        AgentSessionError: {
            /** @description Stable error code (ProblemCode). */
            code: string;
            /** @description Human-readable detail. */
            detail?: string;
        };
        /** @description One tool call proposed by an assistant step. */
        AgentSessionMessageToolCall: {
            /** @description Tool call identifier. */
            call_id: string;
            action: components["schemas"]["ActionId"];
            /** @description Arguments as proposed, with secret values replaced by references. */
            arguments: Record<string, unknown>;
        };
        /**
         * @description A global AI provider (ADR-0017). An administrator sees every member; other principals get
         *     the reduced projection without `base_url`, the timestamps and `revision` (GAPS
         *     缺口 2). The API key is never part of the resource: only `has_api_key` is exposed.
         */
        AiProvider: {
            provider_id: components["schemas"]["ResourceId"];
            /** @description Display name; unique among providers. */
            name: string;
            /**
             * @description Endpoint wire protocol (`openai_compatible` or `anthropic_compatible`).
             * @enum {string}
             */
            kind?: "openai_compatible" | "anthropic_compatible";
            /** @description Endpoint base URL; administrator projection only. */
            base_url?: string;
            /** @description Default model a session uses unless its config overrides it. */
            model: string;
            /** @description Cached list of available model identifiers discovered from or configured for this provider. */
            models?: string[];
            /** @description Custom reasoning/thinking effort code (e.g. minimal */
            reasoning_effort?: string;
            /**
             * Format: int64
             * @description Default context window size in tokens (0 auto-matches the model catalog).
             */
            max_context_tokens?: number;
            /** @description Whether an API key is stored. The key is write-only and never returned. */
            has_api_key: boolean;
            /** @description Whether sessions without their own endpoint use this provider; at most one provider is the default. */
            is_default: boolean;
            created_at?: components["schemas"]["Timestamp"];
            updated_at?: components["schemas"]["Timestamp"];
            revision?: components["schemas"]["Revision"];
        };
        /** @description Every provider, ordered by identifier; the list is bounded and not paginated. */
        AiProviderList: {
            /** @description Providers. */
            items: components["schemas"]["AiProvider"][];
        };
        /** @description A provider to add. The API key is not here; store it with the api-key route afterwards. */
        AiProviderCreateRequest: {
            /** @description Display name; unique among providers. */
            name: string;
            /**
             * @description Endpoint wire protocol; defaults to `openai_compatible`.
             * @enum {string}
             */
            kind?: "openai_compatible" | "anthropic_compatible";
            /** @description Absolute http or https URL without credentials, query or fragment. */
            base_url: string;
            /** @description Default model a session uses unless its config overrides it. */
            model: string;
            /** @description Optional cached model list available on this provider. */
            models?: string[];
            /** @description Custom reasoning/thinking effort code (e.g. minimal */
            reasoning_effort?: string;
            /**
             * Format: int64
             * @description Default context window size in tokens (0 auto-matches the model catalog).
             */
            max_context_tokens?: number;
            /** @description Make this the provider sessions without their own endpoint use; clears the previous default. */
            is_default?: boolean;
        };
        /** @description Members to change; at least one editable field must be present. Changing `base_url` removes the stored API key. */
        AiProviderUpdateRequest: {
            expected_revision: components["schemas"]["Revision"];
            /** @description New display name. */
            name?: string;
            /**
             * @description New endpoint wire protocol.
             * @enum {string}
             */
            kind?: "openai_compatible" | "anthropic_compatible";
            /** @description New endpoint base URL; removes the stored API key. */
            base_url?: string;
            /** @description New default model. */
            model?: string;
            /** @description Updated cached model list available on this provider. */
            models?: string[];
            /** @description New custom reasoning/thinking effort code; empty restores auto-matching against the built-in model catalog with fallback to high. */
            reasoning_effort?: string;
            /**
             * Format: int64
             * @description New default context window size in tokens (0 restores automatic model matching).
             */
            max_context_tokens?: number;
            /** @description Whether this provider is the default; setting it clears the previous default. */
            is_default?: boolean;
        };
        /** @description Parameters for discovering available models from a saved provider or an unsaved endpoint. */
        AiProviderFetchModelsRequest: {
            provider_id?: components["schemas"]["ResourceId"];
            /**
             * @description Endpoint wire protocol.
             * @enum {string}
             */
            kind?: "openai_compatible" | "anthropic_compatible";
            /** @description Endpoint base URL (required when provider_id is omitted). */
            base_url?: string;
            /** @description Optional write-only API key for unsaved endpoints. */
            api_key?: string;
        };
        /** @description Result of model discovery; never returns raw upstream error bodies. */
        AiProviderFetchModelsResult: {
            /** @description Whether model discovery succeeded. */
            ok: boolean;
            /** @description Sorted deduplicated model identifiers returned by the endpoint. */
            models: string[];
            /**
             * Format: int64
             * @description Round-trip time in milliseconds.
             */
            latency_ms?: number;
            /**
             * @description Sanitized failure category when ok is false.
             * @enum {string}
             */
            category?: "auth" | "network" | "denied" | "4xx" | "5xx";
        };
        /** @description In-flight or recently completed official CLI login process state. */
        AgentCoreLoginState: {
            /**
             * @description Login lifecycle state.
             * @enum {string}
             */
            state: "pending" | "succeeded" | "failed" | "cancelled" | "expired";
            /** @description Official OAuth/device verification URL to open in a browser. */
            verification_url?: string;
            /** @description One-time device authorization code. */
            user_code?: string;
            /** @description Human-readable status guidance. */
            message?: string;
            /** @description Recent sanitized CLI login log lines (tokens redacted). */
            output_tail?: string[];
            started_at?: components["schemas"]["Timestamp"];
            updated_at?: components["schemas"]["Timestamp"];
        };
        /** @description Installation and official login state of one external CLI agent core. */
        AgentCoreAuthStatus: {
            /**
             * @description External CLI core identifier.
             * @enum {string}
             */
            core: "codex" | "claude-code" | "opencode";
            /** @description Human-readable core name. */
            display_name: string;
            /** @description CLI executable name. */
            binary: string;
            /** @description Whether the CLI binary is present in PATH. */
            installed: boolean;
            /** @description Recommended official installation command. */
            install_hint: string;
            /** @description Whether persistent official login credentials are present in the isolated agent home. */
            logged_in: boolean;
            /**
             * @description Active persistent login credential type.
             * @enum {string}
             */
            auth_method: "oauth" | "token" | "none";
            updated_at?: components["schemas"]["Timestamp"];
            active_login?: components["schemas"]["AgentCoreLoginState"];
        };
        /** @description Official login status for every supported external CLI agent core. */
        AgentCoreAuthList: {
            /** @description External CLI core auth entries. */
            items: components["schemas"]["AgentCoreAuthStatus"][];
        };
        /** @description Request to start official CLI login or import an OAuth setup token. */
        AgentCoreLoginRequest: {
            /**
             * @description Login flow mode (device launches official CLI login; token imports pasted setup token or auth JSON).
             * @enum {string}
             */
            mode?: "device" | "token";
            /** @description Write-only setup token or credentials JSON when mode is token. */
            token?: string;
        };
        /** @description Canonical custom prompt file for one agent core family. */
        AgentCorePromptTarget: {
            core: components["schemas"]["AgentCore"];
            /** @description Core display name. */
            display_name: string;
            /** @description Relative path inside prompts/. */
            rel_path: string;
            /** @description Canonical prompt filename (CLAUDE.md */
            file_name: string;
            /** @description Explanation of how this prompt file is loaded. */
            description: string;
        };
        /** @description Metadata of one file inside the agent workspace. */
        AgentWorkspaceFileEntry: {
            /**
             * @description Separated workspace area.
             * @enum {string}
             */
            area: "mcp" | "skills" | "prompts";
            /** @description Relative path within the area. */
            path: string;
            /** @description Basename of the file. */
            name: string;
            /** @description Skill slug or agent core family folder. */
            group?: string;
            /**
             * Format: int64
             * @description File size in bytes.
             */
            size: number;
            /** @description Whether the file can be edited inline as UTF-8 text. */
            is_text: boolean;
            updated_at: components["schemas"]["Timestamp"];
        };
        /** @description One file or subfolder in the agent interactive exchange folder. */
        AgentExchangeEntry: {
            /** @description Entry basename. */
            name: string;
            /** @description Relative path inside the exchange folder. */
            path: string;
            /** @description Whether the entry is a subfolder. */
            is_dir: boolean;
            /**
             * Format: int64
             * @description File size in bytes (0 for directories).
             */
            size: number;
            /**
             * Format: int32
             * @description Direct child count when is_dir is true.
             */
            child_count?: number;
            /** @description Whether the file is previewable/editable as UTF-8 text. */
            is_text: boolean;
            /** @description Whether the file is a previewable image. */
            is_image: boolean;
            /** @description Detected MIME type when known. */
            mime_type?: string;
            updated_at: components["schemas"]["Timestamp"];
        };
        /** @description Directory listing of one path inside the agent interactive exchange folder. */
        AgentExchangeListResult: {
            /** @description Current relative directory path (empty for root). */
            path: string;
            /** @description Parent relative directory path. */
            parent_path: string;
            /** @description Absolute host directory path of the exchange root. */
            root_hint: string;
            /** @description Folders and files inside this directory. */
            entries: components["schemas"]["AgentExchangeEntry"][];
            /**
             * Format: int32
             * @description Number of subfolders in this directory.
             */
            total_dirs: number;
            /**
             * Format: int32
             * @description Number of files in this directory.
             */
            total_files: number;
            /**
             * Format: int64
             * @description Combined file bytes in this directory.
             */
            total_bytes: number;
        };
        /** @description Bounded preview of one file inside the agent interactive exchange folder. */
        AgentExchangePreview: {
            /** @description Relative file path. */
            path: string;
            /** @description File basename. */
            name: string;
            /**
             * Format: int64
             * @description File size in bytes.
             */
            size: number;
            /** @description Whether inline text content is returned. */
            is_text: boolean;
            /** @description Whether the file is a previewable image. */
            is_image: boolean;
            /** @description Detected MIME type. */
            mime_type?: string;
            /** @description True when inline text was truncated to the preview cap. */
            truncated?: boolean;
            /** @description UTF-8 text preview content. */
            content?: string;
            updated_at: components["schemas"]["Timestamp"];
        };
        /** @description Request to create a subfolder inside the exchange folder. */
        AgentExchangeMkdirRequest: {
            /** @description Relative subfolder path to create. */
            path: string;
        };
        /** @description Request to create or update a text file inside the exchange folder. */
        AgentExchangeWriteRequest: {
            /** @description Relative file path. */
            path: string;
            /** @description UTF-8 text content. */
            content: string;
        };
        /** @description Request to rename or move a file or subfolder inside the exchange folder. */
        AgentExchangeRenameRequest: {
            /** @description Current relative path. */
            from: string;
            /** @description Target relative path. */
            to: string;
        };
        /** @description Summary of files uploaded into the interactive exchange folder. */
        AgentExchangeUploadResult: {
            /** @description Target subfolder path. */
            dir: string;
            /** @description Uploaded file entries. */
            items: components["schemas"]["AgentExchangeEntry"][];
            /**
             * Format: int32
             * @description Count of uploaded files.
             */
            total: number;
        };
        /** @description Listed files for one separated agent workspace directory. */
        AgentWorkspaceListResult: {
            /**
             * @description Separated workspace area.
             * @enum {string}
             */
            area: "mcp" | "skills" | "prompts";
            /** @description Isolated host directory path of this area. */
            directory_hint: string;
            /** @description Files currently stored in this area. */
            items: components["schemas"]["AgentWorkspaceFileEntry"][];
            /** @description Canonical per-core prompt targets when area is prompts. */
            prompt_targets?: components["schemas"]["AgentCorePromptTarget"][];
        };
        /** @description Inline text content of one workspace file. */
        AgentWorkspaceFileContent: {
            /**
             * @description Separated workspace area.
             * @enum {string}
             */
            area: "mcp" | "skills" | "prompts";
            /** @description Relative path within the area. */
            path: string;
            /** @description UTF-8 file text content. */
            content: string;
            /**
             * Format: int64
             * @description File size in bytes.
             */
            size: number;
            updated_at?: components["schemas"]["Timestamp"];
        };
        /** @description Request to write text or upload a file into a workspace area. */
        AgentWorkspaceWriteRequest: {
            /**
             * @description Target workspace area.
             * @enum {string}
             */
            area: "mcp" | "skills" | "prompts";
            /** @description Relative file path within the area. */
            path: string;
            /** @description UTF-8 text content. */
            content?: string;
            /** @description Optional base64-encoded file bytes for drag-and-drop uploads. */
            content_base64?: string;
        };
        /** @description Standard MCP server configuration entry stored in mcp/servers.json. */
        AgentMCPServerEntry: {
            /** @description Unique MCP server slug. */
            id: string;
            /** @description Display name. */
            name: string;
            /** @description Server summary. */
            description?: string;
            /**
             * @description Transport protocol.
             * @enum {string}
             */
            transport: "stdio" | "http";
            /** @description Executable for stdio transport. */
            command?: string;
            /** @description Command arguments for stdio transport. */
            args?: string[];
            /** @description Endpoint URL for HTTP transport. */
            url?: string;
            /** @description Environment variables passed to the MCP server. */
            env?: {
                [key: string]: string;
            };
            /** @description Whether this MCP server is enabled for agent turns. */
            enabled: boolean;
            /** @description Official repository source if installed from the registry. */
            source?: string;
        };
        /** @description Metadata of one built-in official Skills or MCP repository. */
        AgentRegistrySourceMeta: {
            /** @description Source identifier. */
            id: string;
            /** @description Official repository display name. */
            name: string;
            /**
             * @description Resource category provided by this repository.
             * @enum {string}
             */
            kind: "skill" | "mcp";
            /** @description GitHub owner/repo slug. */
            repo: string;
            /** @description Official repository homepage URL. */
            url: string;
            /** @description Short description. */
            description: string;
        };
        /** @description One searchable official Skill or MCP server entry. */
        AgentRegistryItem: {
            /** @description Stable registry item identifier. */
            id: string;
            /** @description Local folder or MCP id slug. */
            slug: string;
            /**
             * @description Item type.
             * @enum {string}
             */
            kind: "skill" | "mcp";
            /** @description Official source identifier. */
            source: string;
            /** @description Official source display name. */
            source_name: string;
            /** @description Display title. */
            name: string;
            /** @description Summary of capabilities. */
            description: string;
            /** @description Upstream GitHub owner/repo. */
            repo: string;
            /** @description Relative path inside upstream repository. */
            repo_path?: string;
            /** @description Upstream repository URL. */
            repo_url: string;
            /** @description Whitelisted raw SKILL.md URL. */
            raw_url?: string;
            /** @description Searchable tags. */
            tags?: string[];
            /** @description Whether already installed in the local agent workspace. */
            installed: boolean;
            mcp_template?: components["schemas"]["AgentMCPServerEntry"];
        };
        /** @description Result of searching built-in official Skills and MCP repositories. */
        AgentRegistrySearchResult: {
            /** @description Built-in official repository definitions. */
            sources: components["schemas"]["AgentRegistrySourceMeta"][];
            /** @description Matching official Skills and MCP servers. */
            items: components["schemas"]["AgentRegistryItem"][];
            /** @description True when live GitHub indexes were refreshed in this call. */
            live_refreshed: boolean;
            cached_at?: components["schemas"]["Timestamp"];
        };
        /** @description Request to download and install one official Skill or MCP server. */
        AgentRegistryInstallRequest: {
            /** @description Official registry item identifier. */
            id: string;
        };
        /** @description Result of installing an official Skill or MCP server. */
        AgentRegistryInstallResult: {
            /** @description Installed registry item identifier. */
            id: string;
            /**
             * @description Installed item type.
             * @enum {string}
             */
            kind: "skill" | "mcp";
            /** @description Always true on success. */
            installed: boolean;
            /** @description Written relative path inside the agent workspace. */
            target: string;
            /** @description True when downloaded directly from upstream GitHub raw content. */
            from_live: boolean;
            /** @description Human-readable confirmation message. */
            message: string;
        };
        /** @description The provider's API key. Write-only; never returned. */
        AiProviderKeyRequest: {
            /** @description Visible ASCII; surrounding whitespace is dropped. */
            api_key: string;
        };
        /** @description The outcome of one connectivity probe; never the address, the exact status or the body. */
        AiProviderTestResult: {
            /** @description Whether the endpoint answered 200 within the deadline. */
            ok: boolean;
            /**
             * Format: int64
             * @description Round-trip time of a successful probe.
             */
            latency_ms?: number;
            /**
             * @description Failure class; absent when `ok`. `denied` is the outbound policy, `auth` a 401/403.
             * @enum {string}
             */
            category?: "auth" | "network" | "denied" | "4xx" | "5xx";
        };
        /** @description One selectable agent core (ADR-0010 §5). */
        AgentCoreInfo: {
            core: components["schemas"]["AgentCore"];
            /** @description Whether the host can run this core now. */
            available: boolean;
            /** @description Why an unavailable core is unavailable; the interface shows it next to the core. */
            reason?: string;
        };
        /** @description The cores of ADR-0010 in fixed order. */
        AgentCoreList: {
            /** @description The four cores. */
            items: components["schemas"]["AgentCoreInfo"][];
        };
        /**
         * @description A managed node. Fields under `reported` come from the node's agent and are untrusted strings
         *     (ARCH §3.2 item 6); the rest is host-owned.
         */
        Node: {
            node_id: components["schemas"]["NodeId"];
            /** @description Display name set by an administrator. */
            name: string;
            /**
             * @description Connection state from the node session.
             * @enum {string}
             */
            status: "online" | "offline" | "enrolling" | "disabled";
            last_seen_at?: components["schemas"]["Timestamp"];
            /** @description Negotiated node protocol version. */
            protocol_version?: string;
            /** @description Self-reported by the agent; untrusted. */
            reported?: {
                /** @description Host name. */
                hostname?: string;
                /** @description Agent version. */
                agent_version?: string;
                /** @description Operating system description. */
                os?: string;
                /** @description CPU architecture. */
                arch?: string;
            };
            created_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description The installation overview. `listen` and `data_dir` are present only for an administrator;
         *     every other member is readable by any signed-in principal.
         */
        SystemInfo: {
            /** @description Release version of the running binary. */
            version: string;
            /** @description VCS revision the binary was built from; absent when unknown. */
            commit?: string;
            /** @description Deployment role of this host. */
            role: string;
            started_at: components["schemas"]["Timestamp"];
            server_time?: components["schemas"]["Timestamp"];
            /** @description TLS state of the management listener. */
            tls: {
                /** @description Certificate mode: self_signed, acme or proxy. */
                mode: string;
                /** @description SHA-256 fingerprint of the serving certificate. */
                fingerprint?: string;
                not_after?: components["schemas"]["Timestamp"];
                /** @description ACME domains of the configuration. */
                domains?: string[];
            };
            /** @description Listener address; administrators only. */
            listen?: string;
            /** @description Data directory; administrators only. */
            data_dir?: string;
            /** @description Whether any plugin has an active version. */
            plugins_enabled: boolean;
        };
        /** @description Live panel access port, secret entry path, stealth disguise, and reverse-proxy domain state. */
        PanelAccessSettings: {
            /** @description Bound listen IP or host. */
            listen_host: string;
            /**
             * Format: int32
             * @description Active TCP listening port.
             */
            port: number;
            /** @description Full host:port listen address. */
            listen: string;
            /** @description Active TLS mode (self_signed */
            tls_mode: string;
            /** @description Configured secret entry path segment without slashes. */
            entry_path: string;
            /** @description Currently enforced secret entry path; empty when disabled or bypassed by a reverse-proxy domain. */
            effective_entry_path: string;
            /** @description Whether requests without the secret entry path are gated and disguised. */
            entry_gate_active: boolean;
            /**
             * @description Active disguise response mode.
             * @enum {string}
             */
            disguise: "drop" | "nginx_404" | "nginx_403" | "blank_404" | "custom_html";
            /** @description Custom disguise HTML body. */
            disguise_html: string;
            /** @description Configured reverse-proxy domain for direct access. */
            panel_domain: string;
            /** @description Automatically disable the secret entry path and disguise when a reverse-proxy domain is configured. */
            auto_disable_on_domain: boolean;
            /** @description Reason the entry gate is currently bypassed (tls_proxy */
            bypass_reason?: string;
            /** @description True when a PUT request rebound the listener to a new TCP port. */
            port_changed?: boolean;
            /**
             * Format: int64
             * @description Monotonic revision counter for optimistic concurrency checks.
             */
            revision: number;
            updated_at: components["schemas"]["Timestamp"];
        };
        /** @description Metadata of one consistent host backup archive. */
        SystemBackupEntry: {
            /** @description Backup archive filename. */
            filename: string;
            /**
             * Format: int64
             * @description Archive size in bytes.
             */
            size_bytes: number;
            created_at: components["schemas"]["Timestamp"];
        };
        /** @description Collection of available system backup archives. */
        SystemBackupList: {
            /** @description Backup archives ordered newest first. */
            items: components["schemas"]["SystemBackupEntry"][];
        };
        /** @description A page of nodes. */
        NodeList: components["schemas"]["ListMeta"] & {
            /** @description Nodes. */
            items: components["schemas"]["Node"][];
        };
        /**
         * @description One version recorded by the updater. `status` follows the version lifecycle of ARCH §6.1;
         *     `install_status` is the separate installation axis of ARCH §6.6.
         */
        PluginVersion: {
            plugin_id: components["schemas"]["PluginId"];
            /** @description Exact SemVer version from the signed manifest. */
            version: string;
            /** @description Digest of the signed manifest bytes. */
            digest: string;
            /**
             * @description Version lifecycle state (ARCH §6.1).
             * @enum {string}
             */
            status: "STAGED" | "STARTING" | "CANDIDATE" | "ACTIVE" | "DRAINING" | "STOPPED" | "REJECTED" | "ROLLED_BACK" | "QUARANTINED";
            /**
             * @description Installation state (ARCH §6.6).
             * @enum {string}
             */
            install_status: "STAGED" | "INSTALLED" | "REMOVED";
            /** @description This version is the committed active one. */
            active: boolean;
            installed_at: components["schemas"]["Timestamp"];
            activated_at?: components["schemas"]["Timestamp"];
            /** @description Why the version was not activated. */
            rejected_reason?: string;
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description An installed plugin, assembled from its local version rows. `name`, `summary` and
         *     `publisher_id` come from the signed manifest but are written by the plugin author: untrusted.
         *     `versions` is ordered newest first. The optional members below come from the ACTIVE version's
         *     manifest; every text among them is untrusted too.
         */
        Plugin: {
            plugin_id: components["schemas"]["PluginId"];
            /** @description Manifest `name`. */
            name: string;
            /** @description Manifest `summary`. */
            summary: string;
            /** @description Manifest `publisher.id`. */
            publisher_id: string;
            /**
             * @description Manifest `placement`.
             * @enum {string}
             */
            placement: "node" | "controller";
            /** @description Version currently ACTIVE; absent when none. */
            active_version?: string;
            /**
             * @description Latest version state (ARCH §6.1); absent when no version is active.
             * @enum {string}
             */
            active_status?: "STAGED" | "STARTING" | "CANDIDATE" | "ACTIVE" | "DRAINING" | "STOPPED" | "REJECTED" | "ROLLED_BACK" | "QUARANTINED";
            /**
             * @description Installation state (ARCH §6.6); absent when no version is active.
             * @enum {string}
             */
            install_status?: "STAGED" | "INSTALLED" | "REMOVED";
            config_revision: components["schemas"]["Revision"];
            /** @description Version rows */
            versions: components["schemas"]["PluginVersion"][];
            created_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
            /** @description Manifest `description`; absent when the author wrote none. */
            description?: string;
            /**
             * @description Versioned URL of the manifest icon under the plugin static prefix (ADR-0018); absent
             *     without an icon. Render with `<img>` only, never inline.
             */
            icon_url?: string;
            /** @description Manifest `homepage`; a link the user may follow. */
            homepage?: string;
            /** @description Manifest `license` (SPDX expression). */
            license?: string;
            /** @description `true` when the plugin is a mandatory base plugin that cannot be uninstalled; absent otherwise. */
            builtin?: boolean;
            /** @description Whether the plugin is currently enabled on the host. */
            enabled?: boolean;
            /**
             * @description Lifecycle startup mode declared by the active manifest.
             * @enum {string}
             */
            startup?: "eager" | "on_demand";
            /** @description `false` when the active version declares no configuration schema; the settings tab is hidden then. */
            has_config?: boolean;
            /** @description Capabilities the manifest declares, with the host's sensitivity verdict. */
            capabilities?: components["schemas"]["PluginCapability"][];
            /** @description Actions of the active version, exactly as the host action catalog holds them (risk and approval already clamped). */
            operations?: components["schemas"]["ActionMeta"][];
            /** @description Plugin ids the active version depends on; uninstall is blocked while a dependent is installed. */
            dependencies?: components["schemas"]["PluginId"][];
            resources?: components["schemas"]["PluginResources"];
            ui?: components["schemas"]["PluginUi"];
            runtime?: components["schemas"]["PluginRuntime"];
        };
        /**
         * @description One capability the active manifest requests. `sensitive` is the host's verdict (ARCH §10.3
         *     高敏): a sensitive capability needs its own consent line in the install wizard. `reason` is
         *     the author's explanation, untrusted.
         */
        PluginCapability: {
            /** @description Capability name */
            name: string;
            /** @description Capability scope */
            scope: string;
            /** @description Why the plugin requests it. */
            reason: string;
            /** @description The host classifies this capability as high-sensitivity. */
            sensitive: boolean;
        };
        /** @description Resource budget of the active manifest (ARCH §5.3). `disk_max_mb` is a soft limit with periodic accounting and alerts. */
        PluginResources: {
            /**
             * Format: int64
             * @description MemoryMax of the plugin unit.
             */
            memory_max_mb: number;
            /**
             * Format: int64
             * @description CPUQuota of the plugin unit.
             */
            cpu_quota_percent: number;
            /**
             * Format: int64
             * @description TasksMax of the plugin unit.
             */
            pids_max: number;
            /**
             * Format: int64
             * @description LimitNOFILE of the plugin unit.
             */
            fds_max: number;
            /**
             * Format: int64
             * @description Soft disk budget under the plugin state root.
             */
            disk_max_mb: number;
        };
        /** @description One route the active version contributes to the Web Shell navigation. */
        PluginRoute: {
            /** @description Shell path */
            path: string;
            /** @description Navigation label written by the plugin author. */
            title: string;
            /** @description Show the route in the sidebar. */
            nav: boolean;
            /** @description RBAC permission required to open the route, e.g. `com.example.meta:read`. */
            permission: string;
        };
        /**
         * @description A declarative overview card the Web Shell draws natively (manifest schema 1.3, ADR-0018).
         *     The operation is an `effect=read`, `mode=invoke` operation of the same plugin that is polled with an empty payload
         *     every `refresh_seconds`; its result shape is fixed by `kind`.
         */
        PluginWidget: {
            /** @description Widget id */
            id: string;
            /** @description Card title written by the plugin author. */
            title: string;
            /**
             * @description Result shape the Shell expects.
             * @enum {string}
             */
            kind: "stat" | "series" | "checks" | "list";
            /** @description The plugin operation the card polls. */
            operation: string;
            /**
             * Format: int64
             * @description Poll interval; the host may throttle to keep a per-user
             */
            refresh_seconds: number;
            /**
             * @description Grid span class.
             * @enum {string}
             */
            size: "s" | "m" | "l";
            /** @description Shell icon name; an unknown name falls back to the icon of the kind. */
            icon?: string;
            /** @description Shell category color name. */
            color?: string;
        };
        /** @description UI contribution of the active version. Paths are versioned and served unauthenticated under `/plugin-ui` (ADR-0018); content is treated as public and sandboxed at the bridge and API layers. */
        PluginUi: {
            /** @description Versioned URL of the sandboxed entry document. */
            entry_url: string;
            /** @description Routes the plugin contributes. */
            routes: components["schemas"]["PluginRoute"][];
            /** @description Overview cards the Shell renders. */
            widgets: components["schemas"]["PluginWidget"][];
            /** @description HTTPS origins the sandboxed page may connect to (`connect-src` of its CSP). */
            connect_sources: string[];
        };
        /**
         * @description In-memory process state of the plugin. The list answers from memory and never queries
         *     systemd; `memory_bytes` is the cgroup usage at the time of the read and may lag.
         */
        PluginRuntime: {
            /**
             * @description Simplified process state; `standby` means an enabled on-demand plugin ready to wake on first request, `crashed` is a restart loop, `unknown` an unattributed failure.
             * @enum {string}
             */
            state: "running" | "standby" | "starting" | "stopped" | "crashed" | "quarantined" | "unknown";
            since?: components["schemas"]["Timestamp"];
            /**
             * Format: int32
             * @description Restarts observed while recovering this generation.
             */
            restarts?: number;
            /**
             * Format: int64
             * @description Current cgroup memory usage in bytes.
             */
            memory_bytes?: number;
            /**
             * Format: int64
             * @description MemoryMax of the plugin unit in bytes.
             */
            memory_max_bytes?: number;
            /** @description Last error or state note; render as plain text. */
            detail?: string;
        };
        /**
         * @description JSON Schema (Draft 2020-12 subset) of the plugin configuration, exactly as shipped in the
         *     signed package: untrusted data rendered by the Shell form generator. Sensitive fields are
         *     marked `writeOnly: true` or `x-secret: true`.
         */
        PluginConfigSchema: Record<string, unknown>;
        /** @description A page of installed plugins. */
        PluginList: components["schemas"]["ListMeta"] & {
            /** @description Plugins. */
            items: components["schemas"]["Plugin"][];
        };
        /**
         * @description Install the package staged by `POST /api/v1/plugin-packages`. The plugin id and version are
         *     read from the signed manifest. `accepted_capabilities` must cover every capability the
         *     manifest declares, proving the user saw the consent screen.
         */
        PluginInstallRequest: {
            /** @description Opaque id returned by the upload call. */
            upload_id: string;
            /** @description Capabilities the user accepted. A capability is identified by name + scope; omitting scope accepts the name only when the manifest declares it under a single scope. */
            accepted_capabilities: {
                /** @description Capability name. */
                name: string;
                /** @description Capability scope. */
                scope?: string;
            }[];
            expected_revision?: components["schemas"]["Revision"];
            resources?: components["schemas"]["PluginResourcesOverrideRequest"];
        };
        /** @description Optional administrator resource limit overrides for a plugin systemd unit. */
        PluginResourcesOverrideRequest: {
            /**
             * Format: int64
             * @description Hard memory limit in MiB.
             */
            memory_max_mb?: number;
            /**
             * Format: int64
             * @description CPU quota percentage.
             */
            cpu_quota_percent?: number;
            /**
             * Format: int64
             * @description Maximum tasks/processes limit.
             */
            pids_max?: number;
            /**
             * Format: int64
             * @description Maximum open file descriptors.
             */
            fds_max?: number;
            /**
             * Format: int64
             * @description Advisory persistent disk budget in MiB.
             */
            disk_max_mb?: number;
            /** @description When true */
            reset_default?: boolean;
        };
        /** @description Real-time built-in host resource metrics snapshot. */
        SystemHostMetrics: {
            /**
             * Format: date-time
             * @description RFC 3339 sample timestamp.
             */
            collected_at: string;
            /** @description Basic host identity and uptime. */
            host: {
                /** @description Hostname. */
                hostname: string;
                /** @description Operating system name. */
                os: string;
                /** @description Kernel release. */
                kernel: string;
                /** @description CPU architecture. */
                arch: string;
                /**
                 * Format: int64
                 * @description Host uptime in seconds.
                 */
                uptime_seconds: number;
            };
            /** @description CPU utilization, load averages, and recent history. */
            cpu: {
                /**
                 * Format: double
                 * @description CPU usage percentage.
                 */
                usage_percent: number;
                /**
                 * Format: int32
                 * @description Logical CPU core count.
                 */
                cores: number;
                /**
                 * Format: double
                 * @description 1-minute load average.
                 */
                load_1: number;
                /**
                 * Format: double
                 * @description 5-minute load average.
                 */
                load_5: number;
                /**
                 * Format: double
                 * @description 15-minute load average.
                 */
                load_15: number;
                /** @description Recent CPU usage percentages. */
                history: number[];
            };
            /** @description Memory and swap utilization. */
            memory: {
                /**
                 * Format: int64
                 * @description Used RAM bytes.
                 */
                used_bytes: number;
                /**
                 * Format: int64
                 * @description Total RAM bytes.
                 */
                total_bytes: number;
                /**
                 * Format: int64
                 * @description Available RAM bytes.
                 */
                available_bytes: number;
                /**
                 * Format: int64
                 * @description Buffers and cache bytes.
                 */
                cached_bytes: number;
                /**
                 * Format: double
                 * @description Memory usage percentage.
                 */
                usage_percent: number;
                /**
                 * Format: int64
                 * @description Used swap bytes.
                 */
                swap_used_bytes: number;
                /**
                 * Format: int64
                 * @description Total swap bytes.
                 */
                swap_total_bytes: number;
                /** @description Recent memory usage percentages. */
                history: number[];
            };
            /** @description Primary mount and monitored filesystem capacities. */
            disk: {
                /** @description Primary mount point. */
                mount: string;
                /**
                 * Format: int64
                 * @description Used bytes on primary mount.
                 */
                used_bytes: number;
                /**
                 * Format: int64
                 * @description Total bytes on primary mount.
                 */
                total_bytes: number;
                /**
                 * Format: double
                 * @description Disk usage percentage.
                 */
                usage_percent: number;
                /** @description Individual filesystem mounts. */
                mounts: {
                    /** @description Mount point path. */
                    mount: string;
                    /** @description Backing block device. */
                    device?: string;
                    /**
                     * Format: int64
                     * @description Used bytes.
                     */
                    used_bytes: number;
                    /**
                     * Format: int64
                     * @description Total bytes.
                     */
                    total_bytes: number;
                    /**
                     * Format: double
                     * @description Usage percentage.
                     */
                    usage_percent: number;
                }[];
            };
            /** @description Aggregate non-loopback network throughput and cumulative bytes. */
            network: {
                /**
                 * Format: double
                 * @description Current inbound bytes per second.
                 */
                rx_bytes_per_sec: number;
                /**
                 * Format: double
                 * @description Current outbound bytes per second.
                 */
                tx_bytes_per_sec: number;
                /**
                 * Format: int64
                 * @description Total received bytes.
                 */
                rx_total_bytes: number;
                /**
                 * Format: int64
                 * @description Total transmitted bytes.
                 */
                tx_total_bytes: number;
                /** @description Recent inbound throughput samples. */
                rx_history: number[];
                /** @description Recent outbound throughput samples. */
                tx_history: number[];
            };
        };
        /** @description Target coexistence manager for takeover or restoration. */
        SecurityTakeoverRequest: {
            /**
             * @description System security manager service name.
             * @enum {string}
             */
            manager: "ufw" | "firewalld" | "fail2ban";
        };
        /** @description Coexistence and backup status for one system firewall or brute-force manager. */
        SecurityTakeoverEntry: {
            /**
             * @description Manager identifier.
             * @enum {string}
             */
            manager: "ufw" | "firewalld" | "fail2ban";
            /** @description Whether the systemd unit is currently active. */
            active: boolean;
            /** @description Whether qwq has backed up and taken over this manager. */
            taken_over: boolean;
            /** @description Whether a restorable takeover backup exists on disk. */
            backup_exists: boolean;
            /** @description RFC 3339 timestamp when the backup was created. */
            backup_at?: string;
            /** @description Ports imported into inet qwq during takeover. */
            imported_ports?: number[];
            /** @description Human-readable status summary. */
            detail: string;
        };
        /** @description Snapshot of all manageable coexistence managers. */
        SecurityTakeoverStatus: {
            /** @description Status entries for ufw, firewalld, and fail2ban. */
            managers: components["schemas"]["SecurityTakeoverEntry"][];
        };
        /**
         * @description Replace the active version with the package staged by `POST /api/v1/plugin-packages`. The
         *     package must belong to the plugin in the path. `expected_revision` guards the active version
         *     the caller saw. A package from another publisher is refused with `PUBLISHER_CHANGED` unless
         *     a human session sets `accept_publisher_change`.
         */
        PluginUpdateRequest: {
            /** @description Opaque id returned by the upload call. */
            upload_id: string;
            /** @description Capabilities the user accepted. A capability is identified by name + scope; omitting scope accepts the name only when the manifest declares it under a single scope. */
            accepted_capabilities: {
                /** @description Capability name. */
                name: string;
                /** @description Capability scope. */
                scope?: string;
            }[];
            expected_revision?: components["schemas"]["Revision"];
            /** @description Accept that the package has another publisher than the active version. Human sessions only. */
            accept_publisher_change?: boolean;
        };
        /** @description Optional concurrency guard of a rollback. */
        PluginRollbackRequest: {
            expected_revision?: components["schemas"]["Revision"];
        };
        /** @description One journal line of a plugin; the text is untrusted plugin output. */
        PluginLogLine: {
            at: components["schemas"]["Timestamp"];
            /**
             * @description Which output stream the line came from.
             * @enum {string}
             */
            stream: "stdout" | "stderr";
            /** @description The line */
            line: string;
        };
        /**
         * @description One page of plugin journal lines, oldest first within the page. `next_cursor` reads what came
         *     after the last line; `truncated` says more lines were available than this page shows.
         */
        PluginLogPage: {
            items: components["schemas"]["PluginLogLine"][];
            next_cursor?: components["schemas"]["Cursor"];
            /** @description More lines were available than this page shows. */
            truncated: boolean;
        };
        /** @description Optional reason recorded in the audit log of a restart. */
        PluginRestartRequest: {
            /** @description Why the plugin is restarted. */
            reason?: string;
        };
        /** @description One signed plugin package. The filename is ignored; only the bytes are staged. */
        PluginPackageUploadRequest: {
            /**
             * Format: binary
             * @description The package file
             */
            package: string;
        };
        /** @description A staged package. It is not installed until an install or update call consumes the id. */
        PluginPackageUpload: {
            /** @description Opaque handle for the install or update call. */
            upload_id: string;
            /**
             * Format: int64
             * @description Package size in bytes.
             */
            size: number;
            /** @description SHA-256 of the package bytes. */
            sha256: string;
            expires_at: components["schemas"]["Timestamp"];
        };
        /** @description Request body to fetch and stage a signed `.qwqpkg` package from a public HTTPS URL. */
        PluginPackageFetchRequest: {
            /** @description Public HTTPS URL pointing to a `.qwqpkg` archive. */
            url: string;
            /** @description Optional expected SHA-256 checksum of the downloaded `.qwqpkg` file. */
            expected_sha256?: string;
        };
        /** @description Request body to add a custom Ed25519 publisher public key to the dynamic trust store. */
        PluginTrustKeyCreateRequest: {
            /** @description Human-readable label identifying the developer or organization. */
            label: string;
            /** @description PKIX `PUBLIC KEY` PEM block of an Ed25519 public key. */
            public_key_pem: string;
        };
        /** @description One trusted Ed25519 plugin publisher public key. */
        PluginTrustKey: {
            /** @description Canonical Ed25519 key identifier (`ed25519:` + SHA-256 of raw 32-byte public key). */
            key_id: string;
            /** @description Display label of the publisher key. */
            label: string;
            /**
             * @description Whether the key comes from the read-only system trust root (`official`) or administrator-managed custom keys (`custom`).
             * @enum {string}
             */
            source: "official" | "custom";
            /** @description Canonical PKIX `PUBLIC KEY` PEM encoding. */
            public_key_pem: string;
            /** @description Principal ID of the administrator who added a custom key. */
            added_by?: string;
            added_at?: components["schemas"]["Timestamp"];
        };
        /** @description List of all active official and custom trusted publisher public keys. */
        PluginTrustKeyList: {
            /** @description Active trusted publisher keys, official keys first. */
            items: components["schemas"]["PluginTrustKey"][];
        };
        /** @description One pre-built official optional plugin available from the release catalog. */
        PluginCatalogItem: {
            /** @description Canonical plugin identifier. */
            plugin_id: string;
            /** @description Display name of the plugin. */
            name: string;
            /** @description Concise description of the plugin's capabilities. */
            summary: string;
            /** @description Target release version available for download. */
            version: string;
            /** @description Display category used for store grouping and iconography. */
            category: string;
            /**
             * Format: int32
             * @description Declared cgroup memory cap in MiB.
             */
            memory_max_mb: number;
            /** @description Other official plugin IDs that should be installed before this plugin. */
            dependencies: string[];
            /** @description Direct HTTPS URL to the signed `.qwqpkg` package for this host's architecture. */
            download_url: string;
            /** @description Expected SHA-256 digest (`sha256:<hex>`) from `plugins-index.json` when fetched online. */
            sha256?: string;
            /**
             * Format: int64
             * @description Archive size in bytes when known.
             */
            size: number;
            /** @description Whether this plugin is currently installed on the host. */
            installed: boolean;
            /** @description Currently active version on this host when installed. */
            installed_version?: string;
            /** @description Current host revision for optimistic concurrency during updates. */
            installed_revision?: string;
            /** @description Whether the catalog version differs from the installed version. */
            update_available: boolean;
        };
        /** @description Official pre-built plugin catalog for the running host's architecture. */
        PluginCatalogResponse: {
            /** @description Release tag resolved for the catalog (for example `v0.1.11`). */
            release: string;
            /** @description Target OS and architecture (`linux/amd64` or `linux/arm64`). */
            platform: string;
            /**
             * @description Whether metadata came live from the release index or embedded fallback.
             * @enum {string}
             */
            source: "github_release" | "builtin_fallback";
            /** @description Whether the live release index was successfully reached. */
            online: boolean;
            fetched_at: components["schemas"]["Timestamp"];
            /** @description Pre-built official plugins available for one-click install or update. */
            items: components["schemas"]["PluginCatalogItem"][];
        };
        /**
         * @description The pre-install view of a staged package (GAPS gap 4), produced by verification and parsing
         *     without installing. All manifest texts are written by the plugin author: untrusted.
         */
        PluginPackageInspection: {
            /** @description Opaque handle of the inspected upload. */
            upload_id: string;
            /**
             * Format: int64
             * @description Package size in bytes.
             */
            size: number;
            /** @description SHA-256 of the package bytes. */
            sha256: string;
            expires_at: components["schemas"]["Timestamp"];
            signature: components["schemas"]["SignatureCheck"];
            /** @description The strictly parsed manifest; absent when the package could not be parsed safely. */
            manifest?: components["schemas"]["PluginPackageManifest"];
            compatibility: components["schemas"]["CompatibilityCheck"];
            memory: components["schemas"]["CapacityCheck"];
            disk: components["schemas"]["CapacityCheck"];
            /** @description The active version when the plugin is installed — the package is an update; absent for a fresh install. */
            installed?: components["schemas"]["InstalledPackageVersion"];
        };
        /** @description The install-time signature verdict of one package. */
        SignatureCheck: {
            /**
             * @description The signing key verifies the envelope over the manifest bytes and the publisher binding
             *     holds. `false` with `trusted: true` is a package tampered after signing; `false` with
             *     `trusted: false` an unknown or absent signing key. Neither installs.
             */
            valid: boolean;
            /** @description Signing key id from the signature envelope; empty when the package carries none. */
            key_id: string;
            /** @description The signing key is in the host's trust root. */
            trusted: boolean;
            /** @description Manifest `publisher.id` the package claims; empty when no manifest parsed. */
            publisher_id: string;
        };
        /**
         * @description Preview of the strictly parsed manifest of a staged package. Risk and approval of every
         *     operation are the values the catalog would publish (capability floors and the ADR-0016
         *     reachability clamp included). All texts are written by the plugin author: untrusted.
         */
        PluginPackageManifest: {
            id: components["schemas"]["PluginId"];
            /** @description Manifest version the package would install. */
            version: string;
            /** @description Manifest `name`. */
            name: string;
            /** @description Manifest `summary`. */
            summary: string;
            /** @description Manifest `description`; absent when the author wrote none. */
            description?: string;
            /**
             * @description Manifest `placement`.
             * @enum {string}
             */
            placement: "node" | "controller";
            /** @description Manifest `target`, e.g. `linux/amd64`. */
            target: string;
            /** @description Required platform ABI, `major.minor`. */
            abi: string;
            /** @description Capabilities the manifest declares, with the host's sensitivity verdict. */
            capabilities: components["schemas"]["PluginCapability"][];
            /** @description CSP `connect-src` origins the plugin UI declared. */
            connect_sources: string[];
            resources?: components["schemas"]["PluginResources"];
            /** @description Operations of the manifest with the host's effective risk and approval. */
            operations: components["schemas"]["PackageOperationPreview"][];
            /**
             * Format: int32
             * @description Number of UI routes the manifest declares.
             */
            ui_routes: number;
            /**
             * Format: int32
             * @description Number of overview widgets the manifest declares.
             */
            widgets: number;
        };
        /** @description One operation of an inspected package, with the host's effective risk and approval. */
        PackageOperationPreview: {
            name: components["schemas"]["OperationName"];
            /** @description One-line summary; untrusted. */
            summary: string;
            effect: components["schemas"]["Effect"];
            risk: components["schemas"]["RiskLevel"];
            approval?: components["schemas"]["ApprovalLevel"];
            /**
             * @description The operation can cut the administrator off from the server or the panel; the host
             *     clamps its risk to `high` and its approval to at least `ai_confirm` (ADR-0016). Absent
             *     when false.
             */
            reachability?: boolean;
        };
        /** @description Install-time compatibility of the package; `ok` is false exactly when `problems` is non-empty. */
        CompatibilityCheck: {
            /** @description An install would accept the package's manifest and content. */
            ok: boolean;
            /** @description Field violations the install would refuse with (schema version, publisher binding, extraction policy). */
            problems: components["schemas"]["FieldViolation"][];
        };
        /** @description One capacity preflight of the install, in integer megabytes. */
        CapacityCheck: {
            /**
             * Format: int64
             * @description What the package needs.
             */
            required_mb: number;
            /**
             * Format: int64
             * @description What the host has; 0 when the source is unreadable.
             */
            available_mb: number;
            /** @description The host has room */
            ok: boolean;
        };
        /** @description The active version of the plugin an inspected package would update. */
        InstalledPackageVersion: {
            /** @description Version currently ACTIVE. */
            version: string;
            revision: components["schemas"]["Revision"];
        };
        /** @description The committed saga of an install, update or rollback. */
        PluginUpdateResult: {
            saga_id: components["schemas"]["ResourceId"];
            plugin_id: components["schemas"]["PluginId"];
            /** @description Version replaced by the saga; absent for a fresh install. */
            from_version?: string;
            /** @description Version the saga activated. */
            to_version: string;
            /**
             * @description Update strategy (ARCH §6.3).
             * @enum {string}
             */
            strategy: "overlap" | "restart" | "install";
            /**
             * @description Saga state.
             * @enum {string}
             */
            state: "RUNNING" | "COMMITTED" | "ROLLED_BACK" | "FAILED";
            /** @description The service was briefly down because the restart strategy ran. */
            restarted: boolean;
            version: components["schemas"]["PluginVersion"];
        };
        /**
         * @description One immutable plugin configuration revision. Sensitive values are redacted on export and
         *     stored only as secret references.
         */
        PluginConfig: {
            plugin_id: components["schemas"]["PluginId"];
            revision: components["schemas"]["Revision"];
            /** @description The configuration object; sensitive values are redacted. */
            config: Record<string, unknown>;
            /** @description This revision is the applied one. */
            active: boolean;
            created_at?: components["schemas"]["Timestamp"];
            applied_at?: components["schemas"]["Timestamp"];
        };
        /**
         * @description One configuration snapshot. Values the plugin schema marks `writeOnly` or `x-secret` are
         *     moved into the host secret store before the snapshot is stored.
         */
        PluginConfigRequest: {
            /** @description The complete configuration object. */
            config: Record<string, unknown>;
            expected_revision?: components["schemas"]["Revision"];
        };
        /**
         * @description Envelope of a plugin operation call. `payload` follows the operation's request schema.
         *     `expected_revision` adds a precondition on `subject` (relative to the plugin instance, e.g.
         *     `alerts/cpu`), which the plugin checks atomically. `plan_id` binds the call to an earlier
         *     plan: the payload must match the plan's `args_digest` and the plan's preconditions apply.
         */
        PluginInvokeRequest: {
            /** @description Operation arguments; validated against the manifest schema. */
            payload: Record<string, unknown>;
            /** @description Plugin-relative subject the call modifies. */
            subject?: string;
            expected_revision?: components["schemas"]["Revision"];
            plan_id?: components["schemas"]["ResourceId"];
        };
        /**
         * @description Built-in roles (ADR-0005 Q7). Custom roles may be added later.
         * @enum {string}
         */
        Role: "admin" | "operator" | "viewer";
        /** @description Login name, lower case. */
        Username: string;
        /** @description A panel user. Credentials and TOTP secrets are never returned. */
        User: {
            user_id: components["schemas"]["ResourceId"];
            username: components["schemas"]["Username"];
            /** @description Display name. */
            display_name?: string;
            role: components["schemas"]["Role"];
            /** @description TOTP is enrolled. */
            mfa_enabled: boolean;
            /** @description The user cannot log in; sessions and delegations are revoked. */
            disabled: boolean;
            created_at: components["schemas"]["Timestamp"];
            updated_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /** @description A page of users. */
        UserList: components["schemas"]["ListMeta"] & {
            /** @description Users. */
            items: components["schemas"]["User"][];
        };
        /** @description New user. The user chooses the password with a one-time enrollment link (`POST /api/v1/users/{user_id}/enrollment-token`). */
        UserCreateRequest: {
            username: components["schemas"]["Username"];
            /** @description Display name. */
            display_name?: string;
            role: components["schemas"]["Role"];
        };
        /** @description A confirmed private renewal policy; the host supplies its exact account scope. */
        RenewalServiceBootstrapRequest: {
            policy_id: components["schemas"]["ResourceId"];
            expected_revision: components["schemas"]["Revision"];
        };
        /** @description Members to change; absent members are unchanged. */
        UserUpdateRequest: {
            expected_revision: components["schemas"]["Revision"];
            /** @description Display name. */
            display_name?: string;
            role?: components["schemas"]["Role"];
            /** @description Disable or re-enable the user. */
            disabled?: boolean;
        };
        /** @description The caller's new display name. */
        ProfileUpdateRequest: {
            /** @description Display name; empty clears it. */
            display_name: string;
            expected_revision: components["schemas"]["Revision"];
        };
        /** @description The second factor that makes the request fresh; `{}` when the session passed one recently. */
        EnrollmentTokenRequest: {
            /** @description Current TOTP code; required unless the session passed a second factor recently. */
            mfa_code?: string;
        };
        /** @description The one-time enrollment link of a user who has no password yet. */
        EnrollmentToken: {
            user_id: components["schemas"]["ResourceId"];
            /** @description Token of the link; only in the issuing response, absent in idempotent replays. */
            enrollment_token?: string;
            expires_at: components["schemas"]["Timestamp"];
        };
        /** @description Password; hashed with argon2id, never stored or logged in clear. */
        Password: string;
        /** @description Password login. */
        LoginRequest: {
            username: components["schemas"]["Username"];
            /** @description The user's password. */
            password: string;
        };
        /** @description Login needs a second factor; no session exists yet. */
        MfaChallenge: {
            /**
             * @description Discriminator.
             * @constant
             */
            status: "mfa_required";
            /** @description Single-use challenge to answer. */
            challenge_id: string;
            /** @description Accepted second factors. */
            methods: ("totp" | "recovery_code")[];
            expires_at: components["schemas"]["Timestamp"];
        };
        /** @description Answer to an `MfaChallenge`. */
        MfaVerifyRequest: {
            /** @description From the challenge. */
            challenge_id: string;
            /**
             * @description Which factor `code` is.
             * @enum {string}
             */
            method: "totp" | "recovery_code";
            /** @description TOTP code or recovery code. */
            code: string;
        };
        /** @description The signed-in browser session. The session ID itself is only in the cookie. */
        Session: {
            /**
             * @description Discriminator.
             * @constant
             */
            status: "authenticated";
            user: components["schemas"]["User"];
            /** @description Send as `X-CSRF-Token` on non-GET requests; keep in memory only. */
            csrf_token: string;
            mfa_verified_at?: components["schemas"]["Timestamp"];
            created_at: components["schemas"]["Timestamp"];
            idle_expires_at: components["schemas"]["Timestamp"];
            expires_at: components["schemas"]["Timestamp"];
        };
        /** @description Whether first-time setup is still possible. */
        SetupStatus: {
            /** @description An administrator exists; setup is closed. */
            initialized: boolean;
            /** @description SHA-256 fingerprint of a self-signed certificate, for comparison with the installer output. */
            tls_fingerprint?: string;
        };
        /** @description First administrator. */
        SetupRequest: {
            /** @description The one-time token from the installer output. */
            setup_token: string;
            username: components["schemas"]["Username"];
            password: components["schemas"]["Password"];
            /** @description Display name. */
            display_name?: string;
        };
        /** @description A pending TOTP secret; shown once, for the QR code and for manual entry. */
        TotpEnrollment: {
            /** @description Base32 secret without padding. */
            secret: string;
            /** @description `otpauth://totp/...` URL for the QR code. */
            otpauth_url: string;
            expires_at: components["schemas"]["Timestamp"];
        };
        /** @description A second-factor code. */
        TotpCodeRequest: {
            /** @description TOTP code */
            code: string;
        };
        /** @description The second factor is on. */
        TotpConfirmResult: {
            /** @description One-time recovery codes; shown only in this response. */
            recovery_codes: string[];
            user: components["schemas"]["User"];
            session: components["schemas"]["Session"];
        };
        /** @description Change of the caller's own password. */
        PasswordChangeRequest: {
            /** @description The current password. */
            current_password: string;
            new_password: components["schemas"]["Password"];
        };
        /** @description Redemption of an enrollment link. */
        EnrollmentRedeemRequest: {
            /** @description Token of the enrollment link. */
            token: string;
            password: components["schemas"]["Password"];
        };
        /** @description Exact producer and resource of a private handoff, without any private material. */
        PrivateExportPrepareRequest: {
            /** @description Current catalog action whose permission is required. */
            action: string;
            /** @description The verified producer plugin. */
            plugin_id: string;
            /** @description The producer instance. */
            instance_id: string;
            node_id: components["schemas"]["NodeId"];
            /**
             * @description Supported private handoff purpose.
             * @enum {string}
             */
            purpose: "ssh.private-key";
            /** @description Controlled account/user/keys resource identifier; never a path. */
            subject: string;
        };
        /** @description A temporary grant bound to the original live human session. */
        PrivateExportGrant: {
            /** @description Opaque export ID; never an internal secret reference. */
            export_id: string;
            /**
             * @description Generation has not yet started.
             * @enum {string}
             */
            status: "PREPARED";
            /**
             * Format: date-time
             * @description Absolute five-minute handoff expiry.
             */
            expires_at: string;
        };
        /** @description Probe result without internal detail. */
        HealthStatus: {
            /**
             * @description Always `ok` with a 200 response.
             * @enum {string}
             */
            status: "ok";
        };
        /**
         * @description Upper bound on what the token may do; always intersected with the owner's RBAC and plugin
         *     capabilities. Defaults follow ADR-0004 D6: reads run, `low` runs and notifies,
         *     `medium`/`high` need approval, destructive approvals need MFA.
         */
        DelegationPolicy: {
            /** @description Allowed action ID patterns; `*` matches one segment, e.g. `com.example.monitor/*`. Absent = all. */
            actions?: string[];
            /** @description Allowed nodes; absent = all the owner may access. */
            node_ids?: components["schemas"]["NodeId"][];
            /**
             * @description Highest effective risk that runs without approval. `medium` and `high` always need approval.
             * @default low
             * @enum {string}
             */
            auto_approve_max_risk: "none" | "low";
            /**
             * @description `queue`: create the operation in `AWAITING_APPROVAL`; `fail`: return `403 APPROVAL_REQUIRED` instead.
             * @default queue
             * @enum {string}
             */
            on_approval_required: "queue" | "fail";
            /**
             * Format: int32
             * @description Rate limit of the token.
             * @default 60
             */
            requests_per_minute: number;
        };
        /** @description A delegation of a user's authority to an AI operator. */
        Delegation: {
            delegation_id: components["schemas"]["ResourceId"];
            /** @description Shown in the actor name, e.g. "Claude desktop". */
            label: string;
            /** @description User whose authority is delegated. */
            owner_id: string;
            policy: components["schemas"]["DelegationPolicy"];
            /**
             * @description Revoked delegations are deleted.
             * @enum {string}
             */
            status: "active" | "suspended" | "expired";
            /** @description First characters of the token, for recognition. */
            token_prefix?: string;
            last_used_at?: components["schemas"]["Timestamp"];
            created_at: components["schemas"]["Timestamp"];
            expires_at: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /** @description The new delegation and, once, its token. */
        DelegationCreated: components["schemas"]["Delegation"] & {
            /** @description Bearer token `qwq_dlg_...`; absent in idempotent replays. */
            token?: string;
        };
        /** @description A page of delegations. */
        DelegationList: components["schemas"]["ListMeta"] & {
            /** @description Delegations. */
            items: components["schemas"]["Delegation"][];
        };
        /** @description New delegation. */
        DelegationCreateRequest: {
            /** @description Name of the AI client. */
            label: string;
            policy?: components["schemas"]["DelegationPolicy"];
            /**
             * Format: int32
             * @description Lifetime; default 30 days.
             * @default 2592000
             */
            ttl_seconds: number;
        };
        /** @description Members to change; absent members are unchanged. A policy can only be narrowed or replaced. */
        DelegationUpdateRequest: {
            expected_revision: components["schemas"]["Revision"];
            /**
             * @description Suspend or resume.
             * @enum {string}
             */
            status?: "active" | "suspended";
            policy?: components["schemas"]["DelegationPolicy"];
        };
        /**
         * @description Event envelope; mirrors proto `Event` (ARCH §4.2). All fields except `type`, `schema_version`,
         *     `subject` and `payload` are assigned by the host. Plugin event types are prefixed with the
         *     plugin ID (`<plugin_id>.<type>`), and their `subject` and `payload` are untrusted.
         */
        Event: {
            /** @description Unique ID; deduplicate on it. */
            event_id: string;
            sequence: components["schemas"]["Sequence"];
            /** @description Event type, e.g. `resource.changed`. */
            type: string;
            /** @description Version of the payload schema for this type. */
            schema_version: string;
            subject: components["schemas"]["Subject"];
            occurred_at: components["schemas"]["Timestamp"];
            actor?: components["schemas"]["Actor"];
            node_id?: components["schemas"]["NodeId"];
            /** @description Trace correlation ID. */
            trace_id?: string;
            /** @description Operation that caused the event. */
            operation_id?: string;
            /**
             * @description From the host topic policy.
             * @enum {string}
             */
            delivery_class: "lossy_realtime" | "reliable";
            /** @description Type-specific payload; see `ResourceChangedPayload`, `OperationUpdatedPayload` and the `AgentSessionUpdatedPayload` / `AgentSessionAttentionPayload` pair. Untrusted for plugin event types. */
            payload: Record<string, unknown>;
        };
        /**
         * @description `agent.session.updated` (gap 6): a committed status change of one agent session. The event
         *     is delivered to the session's owner alone, and the payload never carries the title, message
         *     content or tool arguments — the session event stream (`GET /api/v1/agent-sessions/{id}/events`)
         *     is the channel for those. `revision` is the session revision the change committed.
         */
        AgentSessionUpdatedPayload: {
            session_id: components["schemas"]["ResourceId"];
            status: components["schemas"]["AgentSessionStatus"];
            previous_status?: components["schemas"]["AgentSessionStatus"];
            /**
             * Format: int32
             * @description Tool calls waiting for a human decision at commit time.
             */
            pending_approvals: number;
            /**
             * Format: int64
             * @description Highest session sequence at commit time.
             */
            last_seq: number;
            last_message_at?: components["schemas"]["Timestamp"];
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description `agent.session.attention` (gap 6): the session needs its owner (`waiting_approval` or
         *     `failed`). Delivered to the owner alone, right after the `agent.session.updated` of the
         *     same commit, which shares its `revision`.
         */
        AgentSessionAttentionPayload: {
            session_id: components["schemas"]["ResourceId"];
            /**
             * @description Why the owner is needed.
             * @enum {string}
             */
            status: "waiting_approval" | "failed";
            approval_id?: components["schemas"]["ResourceId"];
            operation_id?: components["schemas"]["ResourceId"];
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description `resource.changed` (ADR-0004 D3), written in the same transaction as the change.
         *     `changed_pointers` lists the JSON Pointers that changed (empty for create and delete), so
         *     clients refetch exactly those with `fields`.
         */
        ResourceChangedPayload: {
            subject: components["schemas"]["Subject"];
            revision: components["schemas"]["Revision"];
            /**
             * @description What happened to the subject.
             * @enum {string}
             */
            kind: "create" | "update" | "delete";
            actor: components["schemas"]["Actor"];
            /** @description Operation that made the change. */
            operation_id?: string;
            /** @description Changed members. */
            changed_pointers: components["schemas"]["JsonPointer"][];
            /** @description More members changed than listed; refetch the whole subject. */
            changed_pointers_truncated?: boolean;
        };
        /**
         * @description `operation.updated`: status or progress change. Carries what follow mode and the task drawer
         *     need; fetch the operation for `result`.
         */
        OperationUpdatedPayload: {
            operation_id: components["schemas"]["ResourceId"];
            action: components["schemas"]["ActionId"];
            status: components["schemas"]["OperationStatus"];
            previous_status?: components["schemas"]["OperationStatus"];
            /**
             * Format: int32
             * @description Execution attempt.
             */
            attempt: number;
            actor: components["schemas"]["Actor"];
            target?: components["schemas"]["Target"];
            effective_risk?: components["schemas"]["RiskLevel"];
            approval_id?: components["schemas"]["ResourceId"];
            progress?: components["schemas"]["OperationProgress"];
            /** @description Shell route of the action, for follow mode. */
            ui_route?: string;
            error?: components["schemas"]["Problem"];
            revision: components["schemas"]["Revision"];
        };
        /** @description Envelope of a `resource.changed` event. */
        ResourceChangedEvent: components["schemas"]["Event"] & {
            /**
             * @description Event type.
             * @constant
             */
            type?: "resource.changed";
            payload?: components["schemas"]["ResourceChangedPayload"];
        };
        /** @description Envelope of an `operation.updated` event. */
        OperationUpdatedEvent: components["schemas"]["Event"] & {
            /**
             * @description Event type.
             * @constant
             */
            type?: "operation.updated";
            payload?: components["schemas"]["OperationUpdatedPayload"];
        };
        /** @description Envelope of an `agent.session.updated` event; delivered to the session's owner only. */
        AgentSessionUpdatedEvent: components["schemas"]["Event"] & {
            /**
             * @description Event type.
             * @constant
             */
            type?: "agent.session.updated";
            payload?: components["schemas"]["AgentSessionUpdatedPayload"];
        };
        /** @description Envelope of an `agent.session.attention` event; delivered to the session's owner only. */
        AgentSessionAttentionEvent: components["schemas"]["Event"] & {
            /**
             * @description Event type.
             * @constant
             */
            type?: "agent.session.attention";
            payload?: components["schemas"]["AgentSessionAttentionPayload"];
        };
        /** @description `event: ready` data. */
        StreamReady: {
            head_sequence: components["schemas"]["Sequence"];
            /**
             * Format: int32
             * @description Heartbeat interval.
             */
            heartbeat_seconds: number;
        };
        /** @description `event: heartbeat` data. */
        StreamHeartbeat: {
            head_sequence: components["schemas"]["Sequence"];
            server_time: components["schemas"]["Timestamp"];
        };
        /** @description `event: resync` data: reload snapshots, then continue after `head_sequence`. */
        StreamResync: {
            /**
             * @description Why events were lost.
             * @enum {string}
             */
            reason: "retention_exceeded" | "buffer_overflow" | "server_restart";
            head_sequence: components["schemas"]["Sequence"];
            /** @description Affected topics; absent = all subscribed. */
            topics?: string[];
        };
        /**
         * @description One SSE frame. On the wire each member is a field line (`event:`, `id:`, `retry:`, `data:`);
         *     `data` is a single line of JSON. Domain events have no `event` and carry `id`; control frames
         *     (`ready`, `heartbeat`, `resync`) have `event` and no `id`, so they never move `Last-Event-ID`.
         */
        StreamFrame: {
            /**
             * @description Control frame name; absent for domain events.
             * @enum {string}
             */
            event?: "ready" | "heartbeat" | "resync";
            id?: components["schemas"]["Sequence"];
            /**
             * Format: int32
             * @description Reconnect delay in milliseconds.
             */
            retry?: number;
            /** @description JSON data of the frame. */
            data: components["schemas"]["ResourceChangedEvent"] | components["schemas"]["OperationUpdatedEvent"] | components["schemas"]["AgentSessionUpdatedEvent"] | components["schemas"]["AgentSessionAttentionEvent"] | components["schemas"]["Event"] | components["schemas"]["StreamReady"] | components["schemas"]["StreamHeartbeat"] | components["schemas"]["StreamResync"];
        };
        /** @description Parameters of the `find_actions` tool. */
        FindActionsRequest: {
            /** @description Keywords, e.g. "enable firewall". */
            query: string;
            /** @description Optional filters. */
            scope?: {
                plugin_id?: components["schemas"]["PluginId"];
                node_id?: components["schemas"]["NodeId"];
                effect?: components["schemas"]["Effect"];
            };
            /**
             * Format: int32
             * @description Maximum entries.
             * @default 8
             */
            limit: number;
        };
        /** @description Search result. */
        FindActionsResponse: {
            /** @description Best matches first. */
            actions: components["schemas"]["ActionSummary"][];
            /** @description More matches exist; refine the query or raise `limit`. */
            truncated: boolean;
        };
        /** @description Parameters of the `describe_action` tool. */
        DescribeActionRequest: {
            id: components["schemas"]["ActionId"];
            /**
             * @description Include the plugin's bundled docs.
             * @default false
             */
            include_docs: boolean;
            /**
             * @description Include `result_schema`. Off by default: host result schemas embed Operation and Problem
             *     (about 11 KB versus 0.6-1.2 KB for `args_schema`), and a caller rarely needs them before
             *     the call.
             * @default false
             */
            include_result_schema: boolean;
        };
        /**
         * @description Everything needed to call an action. `args_schema` and `result_schema` are JSON Schema
         *     2020-12; for plugin actions they come from the package and are untrusted data. `args_schema`
         *     is the plain argument schema: `x-qwq-*` extension members are not kept in it. `target`
         *     says which `Target` members `plan`/`execute` need. MCP hints follow from `effect` and
         *     `idempotent` (`read` → readOnlyHint, `destructive` → destructiveHint).
         */
        ActionDescription: {
            action: components["schemas"]["ActionMeta"];
            /** @description Required target members. */
            target: {
                /** @description `target.node_id` is required. */
                node_id?: boolean;
                /** @description `target.plugin_id` is required. */
                plugin_id?: boolean;
                /** @description `target.instance_id` is required. */
                instance_id?: boolean;
                /** @description `target.subject` is required. */
                subject?: boolean;
            };
            /** @description JSON Schema of `args`. */
            args_schema: Record<string, unknown>;
            /** @description JSON Schema of `result`; returned only when `include_result_schema=true`. */
            result_schema?: Record<string, unknown>;
            /** @description Example argument objects. */
            examples?: Record<string, unknown>[];
            /** @description Bundled Markdown docs, possibly truncated. */
            docs?: string;
            /** @description `docs` was cut at the size limit. */
            docs_truncated?: boolean;
        };
        /** @description Parameters of the `read` tool. */
        ReadRequest: {
            subject: components["schemas"]["Subject"];
            /** @description JSON Pointers to return; absent = everything. */
            fields?: components["schemas"]["JsonPointer"][];
            since_revision?: components["schemas"]["Revision"];
            cursor?: components["schemas"]["Cursor"];
            /**
             * Format: int32
             * @description Collection page size.
             * @default 20
             */
            limit: number;
        };
        /**
         * @description Exactly one of `values` (single resource) or `items` (collection) is present, unless
         *     `unchanged=true`. All string content that originates from plugins or nodes is untrusted.
         */
        ReadResponse: {
            subject: components["schemas"]["Subject"];
            revision: components["schemas"]["Revision"];
            /** @description The resource still has `since_revision`; nothing else is returned. */
            unchanged?: boolean;
            /** @description Single resource. Keys are the requested JSON Pointers (`""` = whole resource). */
            values?: {
                [key: string]: unknown;
            };
            /** @description Requested pointers that do not exist. */
            missing?: components["schemas"]["JsonPointer"][];
            /** @description Collection members, projected by `fields`. */
            items?: Record<string, unknown>[];
            /** @description Collections only; see `ListMeta.delta`. */
            delta?: boolean;
            /** @description Collections with `delta=true`. */
            deleted_ids?: string[];
            next_cursor?: components["schemas"]["Cursor"];
            /** @description Present when a limit cut the response. */
            truncated?: {
                /**
                 * @description Which limit was hit.
                 * @enum {string}
                 */
                reason: "max_items" | "max_bytes";
                /**
                 * Format: int32
                 * @description Items or bytes returned.
                 */
                returned?: number;
                /** @description Host-written advice, e.g. "pass next_cursor or narrow fields". */
                hint?: string;
            };
        };
        /**
         * @description Parameters of the `execute` tool: either `plan_id`, or `action` + `args` (+ `target`,
         *     `expected_revision`). Not a `oneOf`, because function-calling APIs need a plain object schema;
         *     the host enforces the rule and answers `400 VALIDATION_FAILED`.
         */
        ExecuteRequest: {
            plan_id?: components["schemas"]["ResourceId"];
            action?: components["schemas"]["ActionId"];
            /** @description Action arguments. */
            args?: Record<string, unknown>;
            target?: components["schemas"]["TargetInput"];
            expected_revision?: components["schemas"]["Revision"];
        };
        /** @description Parameters of the `wait` tool. */
        WaitRequest: {
            operation_id: components["schemas"]["ResourceId"];
            /**
             * Format: int32
             * @description Maximum wait.
             * @default 25
             */
            timeout_seconds: number;
        };
        /** @description Parameters of the `cancel` tool. */
        AgentCancelRequest: {
            operation_id: components["schemas"]["ResourceId"];
            /** @description Recorded in the audit log. */
            reason?: string;
        };
    };
    responses: {
        /**
         * @description Finished synchronously. `status` is `SUCCEEDED`; `operation_id` is empty only for `effect=read`, `mode=invoke`
         *     plugin actions, which do not create operation records.
         */
        OperationDone: {
            headers: {
                "Idempotency-Replayed": components["headers"]["IdempotencyReplayed"];
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["OperationOutcome"];
            };
        };
        /** @description Accepted; the operation is pending, running or awaiting approval. Follow `Location` or events. */
        OperationAccepted: {
            headers: {
                Location: components["headers"]["Location"];
                "Idempotency-Replayed": components["headers"]["IdempotencyReplayed"];
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Operation"];
            };
        };
        /** @description `VALIDATION_FAILED`: malformed JSON, schema or business validation failure, with `violations`. */
        BadRequest: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `UNAUTHENTICATED`: missing, expired or revoked credentials, or failed login. */
        Unauthenticated: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `PERMISSION_DENIED`, `CSRF_FAILED`, `MFA_REQUIRED` or `APPROVAL_REQUIRED`. */
        Forbidden: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `NOT_FOUND`: no such resource, or the caller may not see it. */
        NotFound: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /**
         * @description `REVISION_CONFLICT` (with `current_revision`), `PRECONDITION_FAILED` (with
         *     `failed_preconditions`), `PLAN_EXPIRED`, `STATE_CONFLICT` or `IDEMPOTENCY_IN_PROGRESS`.
         */
        Conflict: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `PAYLOAD_TOO_LARGE`: body larger than the route limit, or JSON nested deeper than allowed. */
        PayloadTooLarge: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `IDEMPOTENCY_KEY_REUSED`, or `PLUGIN_ERROR` for a plugin-reported failure without a host mapping. */
        Unprocessable: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `RATE_LIMITED`: per-principal, per-IP or per-delegation limit, or idempotency key quota. */
        RateLimited: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `UNAVAILABLE`, `NODE_OFFLINE` or `PLUGIN_UNAVAILABLE`; retryable. */
        Unavailable: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `INSUFFICIENT_STORAGE`: the staging filesystem lacks room for another package; retryable. */
        InsufficientStorage: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description `TIMEOUT`: the plugin or node did not answer within the operation deadline. */
        Timeout: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
        /** @description Any other error (`405`, `415`, `500`, ...). Always a Problem. */
        Error: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
    };
    parameters: {
        /**
         * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
         *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
         *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
         *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
         *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
         *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
         *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
         *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
         *       (retryable, with `retry_after`).
         *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
         *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
         *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
         */
        IdempotencyKey: components["schemas"]["IdempotencyKeyValue"];
        /**
         * @description Same semantics as the required form. Required unless the target action has `effect=read` and `mode=invoke`;
         *     the gateway checks this against the action catalog. Keys sent with synchronous read invokes are ignored
         *     and not stored.
         */
        IdempotencyKeyConditional: components["schemas"]["IdempotencyKeyValue"];
        /**
         * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
         *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
         *     The result keeps the original nesting and contains only the selected members plus the
         *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
         *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
         *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
         */
        Fields: components["schemas"]["JsonPointer"][];
        /**
         * @description Increment: the `revision` watermark of an earlier list response. The response then has
         *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
         *     watermark is older than the change retention, the server returns a full snapshot with
         *     `delta=false`; the client must then replace its cache.
         */
        SinceRevision: components["schemas"]["Revision"];
        /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
        Cursor: components["schemas"]["Cursor"];
        /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
        Limit: number;
        /** @description The revision the caller last read; a mismatch returns `409 REVISION_CONFLICT`. */
        ExpectedRevisionQuery: components["schemas"]["Revision"];
        /** @description User identifier. */
        UserIdPath: components["schemas"]["ResourceId"];
        /** @description Delegation identifier. */
        DelegationIdPath: components["schemas"]["ResourceId"];
        /** @description Node identifier; `local` in a standalone installation. */
        NodeIdPath: components["schemas"]["NodeId"];
        /** @description Plugin identifier from its manifest. */
        PluginIdPath: components["schemas"]["PluginId"];
        /** @description Opaque upload handle returned by `POST /api/v1/plugin-packages`. */
        PluginUploadIdPath: string;
        /** @description Trusted publisher Ed25519 key identifier (`ed25519:<64 lower-case hex>`). */
        PluginTrustKeyIdPath: string;
        /** @description Optional TOTP or recovery code satisfying second-factor checks for sensitive host mutations when the current session is not freshly MFA-verified. */
        MfaCodeHeader: string;
        /** @description Plugin instance identifier. */
        InstanceIdPath: components["schemas"]["InstanceId"];
        /** @description Operation name from the plugin manifest. */
        OperationNamePath: components["schemas"]["OperationName"];
        /** @description Operation identifier. */
        OperationIdPath: components["schemas"]["ResourceId"];
        /** @description Plan identifier. */
        PlanIdPath: components["schemas"]["ResourceId"];
        /** @description Approval identifier. */
        ApprovalIdPath: components["schemas"]["ResourceId"];
        /** @description Agent session identifier. */
        AgentSessionIdPath: components["schemas"]["ResourceId"];
        /** @description AI provider identifier. */
        ProviderIdPath: components["schemas"]["ResourceId"];
    };
    requestBodies: never;
    headers: {
        /** @description URL of the created or accepted resource. */
        Location: string;
        /** @description Seconds to wait before retrying (RFC 9110). Also given as `retry_after` in the body. */
        RetryAfter: number;
        /** @description `true` when this response is the stored result of an earlier request with the same key. */
        IdempotencyReplayed: boolean;
        /** @description `__Secure-qwq_session=<id>; HttpOnly; Secure; SameSite=Lax; Path=/api/` */
        SetSessionCookie: string;
        /** @description Expires the session cookie. */
        ClearSessionCookie: string;
    };
    pathItems: never;
};
export type $defs = Record<string, never>;
export interface operations {
    getHealth: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The process is alive. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getReadiness: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The host is ready. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getSetupStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Setup status. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SetupStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    completeSetup: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Setup token and the first administrator. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["SetupRequest"];
            };
        };
        responses: {
            /** @description Administrator created and logged in. */
            201: {
                headers: {
                    "Set-Cookie": components["headers"]["SetSessionCookie"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createSession: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Username and password. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["LoginRequest"];
            };
        };
        responses: {
            /** @description A second factor is required. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MfaChallenge"];
                };
            };
            /** @description Logged in. */
            201: {
                headers: {
                    "Set-Cookie": components["headers"]["SetSessionCookie"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    verifySessionMfa: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Challenge ID and second-factor code. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["MfaVerifyRequest"];
            };
        };
        responses: {
            /** @description Logged in. */
            201: {
                headers: {
                    "Set-Cookie": components["headers"]["SetSessionCookie"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getCurrentSession: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The current session. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteCurrentSession: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Logged out. */
            204: {
                headers: {
                    "Set-Cookie": components["headers"]["ClearSessionCookie"];
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    beginTotpEnrollment: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The pending secret, shown only here. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TotpEnrollment"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    confirmTotpEnrollment: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description A code of the pending secret. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["TotpCodeRequest"];
            };
        };
        responses: {
            /** @description Second factor on; the recovery codes are shown only here. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TotpConfirmResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    disableTotp: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description The current second factor. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["TotpCodeRequest"];
            };
        };
        responses: {
            /** @description The user with `mfa_enabled` false. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["User"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateProfile: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description The new display name, with the expected revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileUpdateRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    changePassword: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Current and new password. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordChangeRequest"];
            };
        };
        responses: {
            /** @description Password changed. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    redeemEnrollment: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Enrollment token and the first password. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnrollmentRedeemRequest"];
            };
        };
        responses: {
            /** @description Password set and logged in. */
            201: {
                headers: {
                    "Set-Cookie": components["headers"]["SetSessionCookie"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    preparePrivateExport: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description The exact authorized producer and target resource. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PrivateExportPrepareRequest"];
            };
        };
        responses: {
            /** @description A grant bound to this human session. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PrivateExportGrant"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    consumePrivateExport: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description ID of the private export prepared by this same human session. */
                export_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The selected private material; Cache-Control is no-store. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/octet-stream": string;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    cancelPrivateExport: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description ID of a grant prepared by this same human session. */
                export_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Private handoff canceled. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listUsers: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of users. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createUser: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description The new user. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserCreateRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getUser: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The user. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["User"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteUser: {
        parameters: {
            query: {
                /** @description The revision the caller last read; a mismatch returns `409 REVISION_CONFLICT`. */
                expected_revision: components["parameters"]["ExpectedRevisionQuery"];
            };
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateUser: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        /** @description Members to change, with the expected revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserUpdateRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    issueEnrollmentToken: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description User identifier. */
                user_id: components["parameters"]["UserIdPath"];
            };
            cookie?: never;
        };
        /** @description The second factor, unless the session passed one recently. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnrollmentTokenRequest"];
            };
        };
        responses: {
            /** @description The link token, shown only here. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentToken"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listServiceAccounts: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Service account list */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createServiceAccount: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Service account creation payload. */
        requestBody: {
            content: {
                "application/json": {
                    name: string;
                    /** @enum {string} */
                    role: "admin" | "operator" | "viewer";
                    scope?: Record<string, unknown>;
                };
            };
        };
        responses: {
            /** @description Created service account with one-time bearer token */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteServiceAccount: {
        parameters: {
            query: {
                /** @description The revision the caller last read; a mismatch returns `409 REVISION_CONFLICT`. */
                expected_revision: components["parameters"]["ExpectedRevisionQuery"];
            };
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Identifier of the service account to revoke. */
                service_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Service account revoked */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    bootstrapRenewalServiceAccount: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description The confirmed private policy and its current revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["RenewalServiceBootstrapRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listDelegations: {
        parameters: {
            query?: {
                /** @description `me` (default) or `all` (administrators only). */
                owner?: "me" | "all";
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of delegations. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DelegationList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createDelegation: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Label, policy and lifetime of the delegation. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["DelegationCreateRequest"];
            };
        };
        responses: {
            /** @description Delegation created. `token` is shown only here. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DelegationCreated"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getDelegation: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Delegation identifier. */
                delegation_id: components["parameters"]["DelegationIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The delegation. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Delegation"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteDelegation: {
        parameters: {
            query: {
                /** @description The revision the caller last read; a mismatch returns `409 REVISION_CONFLICT`. */
                expected_revision: components["parameters"]["ExpectedRevisionQuery"];
            };
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Delegation identifier. */
                delegation_id: components["parameters"]["DelegationIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Revoked. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateDelegation: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Delegation identifier. */
                delegation_id: components["parameters"]["DelegationIdPath"];
            };
            cookie?: never;
        };
        /** @description Members to change, with the expected revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["DelegationUpdateRequest"];
            };
        };
        responses: {
            /** @description The updated delegation. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Delegation"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listNodes: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of nodes. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NodeList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createNodeEnrollmentToken: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Node enrollment token parameters. */
        requestBody: {
            content: {
                "application/json": {
                    preset_name: string;
                    /** @enum {string} */
                    mode?: "full" | "probe_512m";
                    /** Format: int32 */
                    ttl_seconds?: number;
                };
            };
        };
        responses: {
            /** @description One-time enrollment token */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getNode: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Node identifier; `local` in a standalone installation. */
                node_id: components["parameters"]["NodeIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The node. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Node"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    revokeNode: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Node identifier; `local` in a standalone installation. */
                node_id: components["parameters"]["NodeIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Node revoked */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listPlugins: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of installed plugins. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    installPlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description The staged package, the accepted capabilities and an optional concurrency guard. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginInstallRequest"];
            };
        };
        responses: {
            /** @description The installed version. */
            201: {
                headers: {
                    /** @description The installed plugin. */
                    Location?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginVersion"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    uploadPluginPackage: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description One signed plugin package. */
        requestBody: {
            content: {
                "multipart/form-data": components["schemas"]["PluginPackageUploadRequest"];
            };
        };
        responses: {
            /** @description The staged package. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginPackageUpload"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            507: components["responses"]["InsufficientStorage"];
            default: components["responses"]["Error"];
        };
    };
    fetchPluginPackage: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Remote HTTPS package URL and optional SHA-256 digest guard. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginPackageFetchRequest"];
            };
        };
        responses: {
            /** @description The staged package downloaded from the remote HTTPS URL. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginPackageUpload"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            507: components["responses"]["InsufficientStorage"];
            default: components["responses"]["Error"];
        };
    };
    getPluginCatalog: {
        parameters: {
            query?: {
                /** @description Set to `1` or `true` to bypass the 5-minute catalog cache and fetch fresh metadata. */
                refresh?: "0" | "1" | "true" | "false";
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The official plugin catalog matched to this host's architecture and installed state. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginCatalogResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listPluginTrustKeys: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The active official and custom trusted publisher keys. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginTrustKeyList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    addPluginTrustKey: {
        parameters: {
            query?: never;
            header?: {
                /** @description Optional TOTP or recovery code satisfying second-factor checks for sensitive host mutations when the current session is not freshly MFA-verified. */
                "X-QWQ-MFA-Code"?: components["parameters"]["MfaCodeHeader"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Human label and Ed25519 PKIX public key PEM to trust. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginTrustKeyCreateRequest"];
            };
        };
        responses: {
            /** @description The newly trusted custom publisher key. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginTrustKey"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    deletePluginTrustKey: {
        parameters: {
            query?: never;
            header?: {
                /** @description Optional TOTP or recovery code satisfying second-factor checks for sensitive host mutations when the current session is not freshly MFA-verified. */
                "X-QWQ-MFA-Code"?: components["parameters"]["MfaCodeHeader"];
            };
            path: {
                /** @description Trusted publisher Ed25519 key identifier (`ed25519:<64 lower-case hex>`). */
                key_id: components["parameters"]["PluginTrustKeyIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Custom trusted publisher key removed. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    inspectPluginPackage: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque upload handle returned by `POST /api/v1/plugin-packages`. */
                upload_id: components["parameters"]["PluginUploadIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The verification and preflight result. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginPackageInspection"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    deletePluginPackage: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque upload handle returned by `POST /api/v1/plugin-packages`. */
                upload_id: components["parameters"]["PluginUploadIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The staged package was discarded. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getPlugin: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The installed plugin. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plugin"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    uninstallPlugin: {
        parameters: {
            query: {
                /** @description The revision the caller last read; a mismatch returns `409 REVISION_CONFLICT`. */
                expected_revision: components["parameters"]["ExpectedRevisionQuery"];
                /** @description Also delete the retained configuration and the plugin token; needs a fresh second factor. */
                purge_data?: boolean;
            };
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    updatePlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /** @description The staged package, the accepted capabilities and an optional concurrency guard. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginUpdateRequest"];
            };
        };
        responses: {
            /** @description The committed update saga. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginUpdateResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    rollbackPlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /** @description Optional concurrency guard. */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["PluginRollbackRequest"];
            };
        };
        responses: {
            /** @description The committed rollback saga. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginUpdateResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    restartPlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /** @description Optional reason for the audit log. */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["PluginRestartRequest"];
            };
        };
        responses: {
            /** @description The restarted plugin. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plugin"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    enablePlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    disablePlugin: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getPluginLogs: {
        parameters: {
            query?: {
                /** @description Only this output stream. */
                stream?: "stdout" | "stderr";
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size, at most 100 lines. */
                limit?: number;
            };
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of journal lines. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginLogPage"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    putPluginResources: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /** @description Desired plugin resource limits or reset flag. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginResourcesOverrideRequest"];
            };
        };
        responses: {
            /** @description Updated plugin view with effective resource limits. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plugin"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getPluginConfig: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The active configuration revision. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginConfig"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    putPluginConfig: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        /** @description The configuration object and an optional concurrency guard. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginConfigRequest"];
            };
        };
        responses: {
            /** @description The applied configuration revision, with sensitive values redacted. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginConfig"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getPluginConfigSchema: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The configuration schema of the active version. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginConfigSchema"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    invokeControllerPluginOperation: {
        parameters: {
            query?: never;
            header?: {
                /**
                 * @description Same semantics as the required form. Required unless the target action has `effect=read` and `mode=invoke`;
                 *     the gateway checks this against the action catalog. Keys sent with synchronous read invokes are ignored
                 *     and not stored.
                 */
                "Idempotency-Key"?: components["parameters"]["IdempotencyKeyConditional"];
            };
            path: {
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
                /** @description Operation name from the plugin manifest. */
                operation: components["parameters"]["OperationNamePath"];
            };
            cookie?: never;
        };
        /** @description Operation payload and optional concurrency guard or plan binding. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginInvokeRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    invokeNodePluginOperation: {
        parameters: {
            query?: never;
            header?: {
                /**
                 * @description Same semantics as the required form. Required unless the target action has `effect=read` and `mode=invoke`;
                 *     the gateway checks this against the action catalog. Keys sent with synchronous read invokes are ignored
                 *     and not stored.
                 */
                "Idempotency-Key"?: components["parameters"]["IdempotencyKeyConditional"];
            };
            path: {
                /** @description Node identifier; `local` in a standalone installation. */
                node_id: components["parameters"]["NodeIdPath"];
                /** @description Plugin identifier from its manifest. */
                plugin_id: components["parameters"]["PluginIdPath"];
                /** @description Plugin instance identifier. */
                instance_id: components["parameters"]["InstanceIdPath"];
                /** @description Operation name from the plugin manifest. */
                operation: components["parameters"]["OperationNamePath"];
            };
            cookie?: never;
        };
        /** @description Operation payload and optional concurrency guard or plan binding. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PluginInvokeRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    listOperations: {
        parameters: {
            query?: {
                /** @description Comma-separated statuses, e.g. `RUNNING,AWAITING_APPROVAL`. */
                status?: components["schemas"]["OperationStatus"][];
                /** @description Only operations started by this kind of actor. */
                actor_kind?: components["schemas"]["ActorKind"];
                /** @description Only operations targeting this node. */
                node_id?: components["schemas"]["NodeId"];
                /** @description Only operations targeting this plugin. */
                plugin_id?: components["schemas"]["PluginId"];
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of operations. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getOperation: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Operation identifier. */
                operation_id: components["parameters"]["OperationIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The operation. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    cancelOperation: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Operation identifier. */
                operation_id: components["parameters"]["OperationIdPath"];
            };
            cookie?: never;
        };
        /** @description Optional reason for the audit log. */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["CancelRequest"];
            };
        };
        responses: {
            /** @description Canceled. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            /** @description Cancellation requested; the operation is still running. */
            202: {
                headers: {
                    Location: components["headers"]["Location"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createPlan: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Action, arguments and target to preview. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PlanRequest"];
            };
        };
        responses: {
            /** @description Plan created. */
            201: {
                headers: {
                    Location: components["headers"]["Location"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plan"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    getPlan: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Plan identifier. */
                plan_id: components["parameters"]["PlanIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The plan. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plan"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    executePlan: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Plan identifier. */
                plan_id: components["parameters"]["PlanIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    listApprovals: {
        parameters: {
            query?: {
                /** @description Only approvals in this status. Default `PENDING`. */
                status?: components["schemas"]["ApprovalStatus"];
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of approvals. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ApprovalList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getApproval: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Approval identifier. */
                approval_id: components["parameters"]["ApprovalIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The approval. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Approval"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    decideApproval: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description Approval identifier. */
                approval_id: components["parameters"]["ApprovalIdPath"];
            };
            cookie?: never;
        };
        /** @description Approve or reject, with MFA code when required. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["ApprovalDecisionRequest"];
            };
        };
        responses: {
            /** @description Decision recorded. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Approval"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listActions: {
        parameters: {
            query?: {
                /** @description Search terms; empty enumerates the catalog. */
                q?: string;
                /** @description Only actions of this plugin. */
                plugin_id?: components["schemas"]["PluginId"];
                /** @description Only actions with this effect. */
                effect?: components["schemas"]["Effect"];
                /** @description Page size. */
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Matching actions, best first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActionList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getAction: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Catalog identifier, percent-encoded (`/` becomes `%2F`). */
                action_id: components["schemas"]["ActionId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The action. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActionDetail"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAudit: {
        parameters: {
            query?: {
                /** @description Only events caused by this actor ID. */
                actor?: components["schemas"]["ResourceId"];
                /** @description Only this action name, e.g. `host.users.create` or `auth.login`. */
                action?: string;
                /** @description Only events about this resource subject. */
                subject?: string;
                /** @description Only events with this outcome. */
                outcome?: components["schemas"]["AuditOutcome"];
                /** @description Only events of this operation. */
                operation_id?: components["schemas"]["ResourceId"];
                /** @description Inclusive lower bound on the event time. */
                from?: string;
                /** @description Inclusive upper bound on the event time. */
                to?: string;
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of audit entries. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditPage"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getSystem: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The installation overview. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemInfo"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getSystemMetrics: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current host resource metrics snapshot. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemHostMetrics"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getSecurityTakeover: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current takeover status of manageable coexistence services. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecurityTakeoverStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    postSecurityTakeover: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Target manager to back up and take over. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["SecurityTakeoverRequest"];
            };
        };
        responses: {
            /** @description Updated coexistence takeover status. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecurityTakeoverStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    postSecurityRestore: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Target manager to restore from backup. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["SecurityTakeoverRequest"];
            };
        };
        responses: {
            /** @description Updated coexistence takeover status after restoration. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecurityTakeoverStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    getSystemAccess: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current panel access and disguise configuration. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PanelAccessSettings"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    putSystemAccess: {
        parameters: {
            query?: never;
            header?: {
                /** @description Optional TOTP or recovery code satisfying second-factor checks for sensitive host mutations when the current session is not freshly MFA-verified. */
                "X-QWQ-MFA-Code"?: components["parameters"]["MfaCodeHeader"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Desired panel access, secret entry path, disguise, and reverse-proxy domain settings. */
        requestBody: {
            content: {
                "application/json": {
                    /** @description Bind listen host (e.g. 127.0.0.1, 0.0.0.0, ::1, :: or a specific unicast IP). */
                    listen_host?: string;
                    /**
                     * Format: int32
                     * @description TCP port the panel listens on.
                     */
                    port?: number;
                    /** @description Secret entry path segment without slashes; empty disables the entry gate. */
                    entry_path?: string;
                    /** @description Generate a new cryptographically random secret entry path. */
                    generate_random_entry_path?: boolean;
                    /**
                     * @description Stealth response mode when the entry path is missing or wrong.
                     * @enum {string}
                     */
                    disguise?: "drop" | "nginx_404" | "nginx_403" | "blank_404" | "custom_html";
                    /** @description Custom disguise HTML used when disguise is custom_html. */
                    disguise_html?: string;
                    /** @description Reverse-proxy domain for direct access; automatically disables entry path and disguise when auto_disable_on_domain is true. */
                    panel_domain?: string;
                    /** @description Automatically disable the secret entry path and disguise once a reverse-proxy domain is configured. */
                    auto_disable_on_domain?: boolean;
                    /**
                     * Format: int64
                     * @description Optimistic concurrency revision from the previous GET /api/v1/system/access response.
                     */
                    expected_revision?: number;
                };
            };
        };
        responses: {
            /** @description Updated panel access and disguise configuration. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PanelAccessSettings"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listSystemBackups: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Available system backup archives ordered newest first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemBackupList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createSystemBackup: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Metadata of the newly created backup archive. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemBackupEntry"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    downloadSystemBackup: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Exact backup archive filename matching qwq-<timestamp>.tar.gz. */
                filename: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The backup tar.gz archive; Cache-Control is no-store. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/gzip": string;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createSystemSupportBundle: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The redacted support bundle tar.gz stream; Cache-Control is no-store. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/gzip": string;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getNetworkFacts: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Live host network facts. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getNetworkPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Node network policy. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    putNetworkPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Desired dual-stack network policy configuration. */
        requestBody: {
            content: {
                "application/json": {
                    inbound_family_mode?: string;
                    inbound_candidates?: Record<string, unknown>[];
                    outbound_family_mode?: string;
                    outbound_bind_ipv4?: string;
                    outbound_bind_ipv6?: string;
                    outbound_overrides?: Record<string, unknown>[];
                    expected_revision?: components["schemas"]["Revision"];
                    skip_facts_guard?: boolean;
                };
            };
        };
        responses: {
            /** @description Updated node network policy. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getRoutingProfile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Routing profile. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    putRoutingProfile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Desired China split routing profile and custom rules. */
        requestBody: {
            content: {
                "application/json": {
                    name?: string;
                    mode?: string;
                    block_ads?: boolean;
                    dns_anti_poison?: boolean;
                    custom_rules?: Record<string, unknown>[];
                    expected_revision?: components["schemas"]["Revision"];
                };
            };
        };
        responses: {
            /** @description Updated routing profile. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateRoutingBundle: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Routing rule bundle payload and optional expected SHA-256 digest. */
        requestBody: {
            content: {
                "application/json": {
                    version: string;
                    bundle_text: string;
                    expected_sha256?: string;
                };
            };
        };
        responses: {
            /** @description Activated bundle digest and rule count. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    previewRoutingTwoHop: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Target hostname or URL to evaluate. */
        requestBody: {
            content: {
                "application/json": {
                    target: string;
                };
            };
        };
        responses: {
            /** @description Two-hop routing preview. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, unknown>;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentSessions: {
        parameters: {
            query?: {
                /** @description Only sessions in this state, or `attention` for waiting_approval and failed. */
                status?: components["schemas"]["AgentSessionStatus"];
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
                /**
                 * @description Increment: the `revision` watermark of an earlier list response. The response then has
                 *     `delta=true` and contains only items created or changed since, plus `deleted_ids`. If the
                 *     watermark is older than the change retention, the server returns a full snapshot with
                 *     `delta=false`; the client must then replace its cache.
                 */
                since_revision?: components["parameters"]["SinceRevision"];
                /** @description Opaque `next_cursor` from the previous page. Keep the other query parameters unchanged. */
                cursor?: components["parameters"]["Cursor"];
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of sessions. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSessionList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createAgentSession: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Session settings. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentSessionCreateRequest"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    Location: components["headers"]["Location"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSession"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getAgentSession: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The session, its messages and its pending approvals. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSessionDetail"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteAgentSession: {
        parameters: {
            query?: {
                /** @description Optional concurrency guard; a mismatch returns REVISION_CONFLICT. */
                expected_revision?: components["schemas"]["Revision"];
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateAgentSession: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /** @description The members to change, with the expected revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentSessionUpdateRequest"];
            };
        };
        responses: {
            /** @description The updated session. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSession"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    exportAgentSession: {
        parameters: {
            query?: {
                /** @description Export file format (markdown or json). */
                format?: "markdown" | "md" | "json";
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Downloadable transcript attachment. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/markdown": string;
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentMessages: {
        parameters: {
            query?: {
                /** @description Return only messages with a session sequence lower than this one. */
                before_seq?: number;
                /** @description Page size; default `list_limit_default`, at most `list_limit_max`. */
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of messages, oldest first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSessionMessageList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    sendAgentMessage: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /** @description The user message. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentSendMessageRequest"];
            };
        };
        responses: {
            /** @description The message was stored and the turn was started. */
            201: {
                headers: {
                    Location: components["headers"]["Location"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSendMessageResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            default: components["responses"]["Error"];
        };
    };
    setAgentSessionAPIKey: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /** @description The API key to store for this session. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentSessionAPIKeyRequest"];
            };
        };
        responses: {
            /** @description The session after the change. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSession"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    clearAgentSessionAPIKey: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The session after the change. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSession"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    cancelAgentSession: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        /** @description Optional reason for the transcript. */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["AgentSessionCancelRequest"];
            };
        };
        responses: {
            /** @description The session after the cancel request. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSession"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    streamAgentSession: {
        parameters: {
            query?: {
                /** @description The same position, for a page reload that reopens the stream. */
                last_event_id?: string;
            };
            header?: {
                /** @description Sequence of the last event received; EventSource sends it on reconnect. */
                "Last-Event-ID"?: string;
            };
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The stream. Each frame's `data` is one AgentSessionEvent. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/event-stream": components["schemas"]["AgentSessionEvent"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentSessionApprovals: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Agent session identifier. */
                session_id: components["parameters"]["AgentSessionIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The pending approvals. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentSessionApprovalList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentCores: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The cores. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentCoreList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentCoreAuth: {
        parameters: {
            query?: {
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description External CLI core authentication statuses. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentCoreAuthList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    startAgentCoreLogin: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description External CLI core identifier (codex, claude-code or opencode). */
                core: "codex" | "claude-code" | "opencode";
            };
            cookie?: never;
        };
        /** @description Login mode (device or token) and optional write-only token payload. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentCoreLoginRequest"];
            };
        };
        responses: {
            /** @description Updated core authentication and login progress state. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentCoreAuthStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    logoutAgentCore: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description External CLI core identifier (codex, claude-code or opencode). */
                core: "codex" | "claude-code" | "opencode";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Updated core authentication state after logout. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentCoreAuthStatus"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentExchangeEntries: {
        parameters: {
            query?: {
                /** @description Relative subfolder path inside the exchange folder (empty for root). */
                path?: string;
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Listed exchange directory entries. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangeListResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    mkdirAgentExchange: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Subfolder path to create. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentExchangeMkdirRequest"];
            };
        };
        responses: {
            /** @description Created folder metadata. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangeEntry"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    uploadAgentExchange: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Multipart upload containing target dir and files parts. */
        requestBody: {
            content: {
                "multipart/form-data": {
                    /** @description Optional target subfolder path. */
                    dir?: string;
                    /** @description One or more files to upload. */
                    files?: string[];
                };
            };
        };
        responses: {
            /** @description Uploaded file entries. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangeUploadResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    downloadAgentExchange: {
        parameters: {
            query?: {
                /** @description Relative file or folder path (empty downloads the entire exchange folder as a zip). */
                path?: string;
                /** @description Set to 1 to render safe image files inline. */
                inline?: "0" | "1";
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description File or zip archive stream. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/octet-stream": string;
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    previewAgentExchange: {
        parameters: {
            query: {
                /** @description Relative file path inside the exchange folder. */
                path: string;
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description File preview content and metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangePreview"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    putAgentExchangeFile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Target relative path and UTF-8 content. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentExchangeWriteRequest"];
            };
        };
        responses: {
            /** @description Saved file metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangeEntry"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    renameAgentExchange: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Source and destination relative paths. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentExchangeRenameRequest"];
            };
        };
        responses: {
            /** @description Renamed entry metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentExchangeEntry"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteAgentExchangeEntry: {
        parameters: {
            query: {
                /** @description Relative file or subfolder path to delete. */
                path: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted successfully. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAgentWorkspaceFiles: {
        parameters: {
            query: {
                /** @description Separated workspace area (mcp, skills, or prompts). */
                area: "mcp" | "skills" | "prompts";
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Listed workspace files and canonical per-core prompt targets. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentWorkspaceListResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    getAgentWorkspaceFile: {
        parameters: {
            query: {
                /** @description Separated workspace area (mcp, skills, or prompts). */
                area: "mcp" | "skills" | "prompts";
                /** @description Relative file path within the workspace area. */
                path: string;
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description File content and metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentWorkspaceFileContent"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    putAgentWorkspaceFile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Target area, relative path, and UTF-8 or base64 content. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentWorkspaceWriteRequest"];
            };
        };
        responses: {
            /** @description Saved workspace file metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentWorkspaceFileEntry"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteAgentWorkspaceFile: {
        parameters: {
            query: {
                /** @description Separated workspace area (mcp, skills, or prompts). */
                area: "mcp" | "skills" | "prompts";
                /** @description Relative file path (or skill slug directory) within the area. */
                path: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted successfully. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    searchAgentRegistry: {
        parameters: {
            query?: {
                /** @description Filter by item type (all, skill, or mcp). */
                kind?: "all" | "skill" | "mcp";
                /** @description Filter by official repository source identifier. */
                source?: string;
                /** @description Case-insensitive search query. */
                q?: string;
                /** @description Set to 1 to refresh live GitHub repository indexes (cached 10 minutes). */
                refresh?: "0" | "1" | "false" | "true";
                /**
                 * @description Field projection: comma-separated RFC 6901 JSON Pointers relative to the resource (for lists:
                 *     relative to each item), at most `fields_max`. Example: `fields=/name,/status/state`.
                 *     The result keeps the original nesting and contains only the selected members plus the
                 *     identifier and `revision`. Pointers traverse objects only: selecting an array returns it
                 *     whole, and index segments are rejected. Commas inside keys are not supported here (use the
                 *     agent `read` tool). An unknown pointer returns `400 VALIDATION_FAILED` at `/fields`.
                 */
                fields?: components["parameters"]["Fields"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Official repository metadata and matching installable items. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentRegistrySearchResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    installAgentRegistryItem: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Official registry item identifier to install. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentRegistryInstallRequest"];
            };
        };
        responses: {
            /** @description Installation result and target workspace path. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentRegistryInstallResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    fetchAIProviderModels: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Existing provider_id or unsaved base_url/kind/api_key parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AiProviderFetchModelsRequest"];
            };
        };
        responses: {
            /** @description Discovered model list or sanitized failure category. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AiProviderFetchModelsResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    listAIProviders: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description All providers. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AiProviderList"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    createAIProvider: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description The provider to add. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AiProviderCreateRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    deleteAIProvider: {
        parameters: {
            query: {
                /** @description The revision the client last saw; a mismatch returns REVISION_CONFLICT. */
                expected_revision: components["schemas"]["Revision"];
            };
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    updateAIProvider: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        /** @description Members to change, with the expected revision. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AiProviderUpdateRequest"];
            };
        };
        responses: {
            200: components["responses"]["OperationDone"];
            202: components["responses"]["OperationAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    setAIProviderAPIKey: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        /** @description The API key to store for this provider. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AiProviderKeyRequest"];
            };
        };
        responses: {
            /** @description The key is stored; the answer never contains it. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    clearAIProviderAPIKey: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The key is removed (or was not there). */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    testAIProvider: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description AI provider identifier. */
                provider_id: components["parameters"]["ProviderIdPath"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The probe outcome. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AiProviderTestResult"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    streamEvents: {
        parameters: {
            query?: {
                /**
                 * @description Comma-separated event types or prefixes ending in `.*`, at most `sse_topics_max`.
                 *     Default `resource.changed,operation.updated`.
                 */
                topics?: string[];
                /** @description Resume after this sequence. Ignored when the `Last-Event-ID` header is present. */
                last_event_id?: components["schemas"]["Sequence"];
            };
            header?: {
                /** @description Standard SSE resume header; the sequence of the last domain event received. */
                "Last-Event-ID"?: components["schemas"]["Sequence"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The event stream. Each frame's `data` is JSON. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/event-stream": components["schemas"]["StreamFrame"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    agentFindActions: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["FindActionsRequest"];
            };
        };
        responses: {
            /** @description Matching actions, best first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindActionsResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    agentDescribeAction: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["DescribeActionRequest"];
            };
        };
        responses: {
            /** @description The action description. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActionDescription"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    agentRead: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReadRequest"];
            };
        };
        responses: {
            /** @description The projected state. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    agentPlan: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["PlanRequest"];
            };
        };
        responses: {
            /** @description The plan. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Plan"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    agentExecute: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["ExecuteRequest"];
            };
        };
        responses: {
            /** @description The operation outcome so far. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationOutcome"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            503: components["responses"]["Unavailable"];
            504: components["responses"]["Timeout"];
            default: components["responses"]["Error"];
        };
    };
    agentWait: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["WaitRequest"];
            };
        };
        responses: {
            /** @description The operation outcome when the wait ended. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationOutcome"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            413: components["responses"]["PayloadTooLarge"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
    agentCancel: {
        parameters: {
            query?: never;
            header: {
                /**
                 * @description Client-generated unique key (a UUID or ULID is fine), sent as a bare token without quotes.
                 *     Scope: authenticated principal (user, delegation or service account) + HTTP method + concrete
                 *     path. TTL 24 h from first use; at most `idempotency_keys_per_principal` live keys, beyond which
                 *     new keys get `429 RATE_LIMITED` (old keys are never evicted early).
                 *     - Same key, same request fingerprint (SHA-256 of the RFC 8785 canonical JSON body and the
                 *       sorted query string): the stored response is returned with `Idempotency-Replayed: true`.
                 *     - Same key, different fingerprint: `422 IDEMPOTENCY_KEY_REUSED`.
                 *     - Same key while the first request is still being processed: `409 IDEMPOTENCY_IN_PROGRESS`
                 *       (retryable, with `retry_after`).
                 *     Only responses produced after the key was bound are stored (2xx and 4xx from the handler).
                 *     Authentication failures, `429` and `5xx` release the key so the retry is processed afresh.
                 *     A missing key returns `400 VALIDATION_FAILED` with a violation at `/Idempotency-Key`.
                 */
                "Idempotency-Key": components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        /** @description Tool parameters. */
        requestBody: {
            content: {
                "application/json": components["schemas"]["AgentCancelRequest"];
            };
        };
        responses: {
            /** @description The operation outcome after the cancel request. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationOutcome"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthenticated"];
            403: components["responses"]["Forbidden"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            422: components["responses"]["Unprocessable"];
            429: components["responses"]["RateLimited"];
            default: components["responses"]["Error"];
        };
    };
}
