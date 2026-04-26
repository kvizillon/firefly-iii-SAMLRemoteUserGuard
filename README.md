# SAML Remote User Guard for Firefly III

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-^8.1-blue.svg)](https://www.php.net/)

This package provides **SAML 2.0 authentication** for [Firefly III](https://www.firefly-iii.org/) using the [`scaler-tech/laravel-saml2`](https://github.com/scaler-tech/laravel-saml2) package. It replaces the default `RemoteUserGuard` with a SAML‑aware guard that allows you to use external Identity Providers (including Authentik, Keycloak, SimpleSAMLphp, Azure AD, etc.) for passwordless authentication, passkeys, MFA, and any other auth methods your IdP supports.

> **Tested with** – [SimpleSAMLphp](https://github.com/simplesamlphp/simplesamlphp) as the Identity Provider.

---

## Table of Contents

- [Features](#features)
- [SAML Guard](#saml-guard)
- [Installation](#installation)
  - [Manual Installation](#manual-installation)
- [Configuration](#configuration)
  - [Core Settings](#core-settings)
  - [Authentication](#authentication)
  - [Additional Options](#additional-options)
- [Deployment](#deployment)
- [Security Recommendations](#security-recommendations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **SAML 2.0 support** – based on `scaler-tech/laravel-saml2`.
- **Seamless user provisioning** – automatically creates local users from SAML attributes (can be disabled).
- **Prevent user auto-creation** - restrict access to only pre-existing accounts
- **Domain restriction** – limit authentication to specific email domains (whitelist). Users with non‑allowed domains are blocked.

---

## SAML Guard

This guard extends the native `RemoteUserGuard` and activates when `AUTHENTICATION_GUARD_TYPE=saml` is set in your `.env` file. Once enabled, all unauthenticated web requests are redirected to your IdP’s SSO URL. After successful authentication, the `SignedIn` event is handled by `SamlSignedInListener`, which:

1. Extracts user data using the configured attribute mapping.
2. Finds or creates the local Firefly III user (auto‑creation can be disabled).
3. Enforces domain whitelisting (if configured).
4. Logs the user in via the `remote_user_guard`.
5. Restores the originally requested URL.

---

## Installation

### Manual Installation

Follow these steps to integrate the SAML Remote User Guard into your Firefly III installation.

#### 1. Install `scaler-tech/laravel-saml2`

    composer require scaler-tech/laravel-saml2

This command also creates the `saml2_tenants` table migration.

#### 2. Publish the SAML2 configuration

    php artisan vendor:publish --provider="Slides\Saml2\ServiceProvider"

This creates `config/saml2.php`.

#### 3. Run migrations

    php artisan migrate

This creates/updates the `saml2_tenants` table.

#### 4. Copy the guard files

Copy the following files into your Firefly III project:

- `config/saml-guard.php` → `config/saml-guard.php`
- `app/Support/Authentication/SamlRemoteUserGuard.php` → `app/Support/Authentication/SamlRemoteUserGuard.php`
- `app/Listeners/Security/User/SamlSignInListener.php` → `app/Listeners/Security/User/SamlSignInListener.php`

> You can download these files from the [GitHub repository](https://github.com/kvizillon/firefly-iii-SAMLRemoteUserGuard).

#### 5. Update `config/auth.php`

Add the `guard_type` line after the existing `guard_email` setting:
    'guard_email'      => env('AUTHENTICATION_GUARD_EMAIL'),
    
    //ADD:
    'guard_type'       => envDefaultWhenEmpty(env('AUTHENTICATION_GUARD_TYPE'), 'remote_user'),

Then replace the `remote_user_guard` definition:

    // FROM:
    'remote_user_guard' => [
        'driver'   => 'remote_user_guard',
        'provider' => 'remote_user_provider',
    ],

    // TO:
    'remote_user_guard' => [
        'driver'   => 'saml_remote_user_guard',
        'provider' => 'users',
    ],

#### 6. Register the guard in `app/Providers/AuthServiceProvider.php`

Add the `use` statement and the `Auth::extend()` call inside the `boot()` method:

    use FireflyIII\Support\Authentication\SamlRemoteUserGuard;

    // Inside boot() method
    Auth::extend(
        'saml_remote_user_guard',
        static fn ($app, string $name, array $config): SamlRemoteUserGuard => new SamlRemoteUserGuard(
            Auth::createUserProvider($config['provider']),
            $app
        )
    );

#### 7. Configure your `.env` file

Add or modify the following variables:

    AUTHENTICATION_GUARD=remote_user_guard

    # ==============================================
    # SAML guard setting
    # - 'saml' turns on SAML authentication
    # - any other value falls back to the base remote_user method  
    # ==============================================
    AUTHENTICATION_GUARD_TYPE=saml

    # Whether to automatically create users if they don't exist
    SAML_AUTO_CREATE_USERS=false

#### 8. Modify `config/saml2.php`

Add the `'routesMiddleware'` key (if not already present) and set it to `['web']`:

    'routesMiddleware' => ['web'],

#### 9. Create a SAML tenant

Run the artisan command to create your IdP tenant. Example for a generic IdP:

    php artisan saml2:create-tenant \
        --key="default" \
        --nameIdFormat="emailAddress" \
        --entityId="https://your-idp.com/saml2/idp/metadata.php" \
        --loginUrl="https://your-idp.com/saml2/idp/SSOService.php" \
        --logoutUrl="https://your-idp.com/saml2/idp/SingleLogoutService.php" \
        --x509cert="YOUR_X509_CERTIFICATE_HERE"

> Replace the URLs and certificate with those provided by your Identity Provider.

You can add multiple tenants, but SAMLRemoteUserGuard will use only one. By default, it uses the tenant with key name 'default' (if there's only one tenant, the key name doesn't matter).

To use a tenant with a key other than 'default', set the active tenant in config/saml2.php by adding 'active_tenant' => 'your_tenant_key'.

**Example:**
php 'active_tenant' => 'my_custom_tenant',

#### 10. Exclude SAML routes from CSRF protection

Edit `app/Http/Middleware/VerifyCsrfToken.php` and add `'saml2/*'` to the `$except` array:

    protected $except = [
        'oauth/token',
        'saml2/*',
    ];

#### 11. Clear the cache

Run the following commands or visit `https://your-domain.com/flush` (if available):

    php artisan cache:clear
    php artisan config:clear
    php artisan view:clear

    # For a full cache reset:
    php artisan optimize:clear

---

## Configuration

### Core Settings

The `config/saml-guard.php` file contains the main settings for the SAML guard.

    return [
        'auto_create_users' => env('SAML_AUTO_CREATE_USERS', false),

        'attribute_mapping' => [
            'email' => ['email', 'Email', 'mail', 'Mail', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
            'name'  => 'name',
        ],

        'allowed_domains' => env('SAML_ALLOWED_DOMAINS') 
            ? array_map('trim', explode(',', env('SAML_ALLOWED_DOMAINS'))) 
            : [],
    ];

| Key | Description |
|-----|-------------|
| `auto_create_users` | If `true`, creates a local user when a SAML‑authenticated user does not exist. If `false`, only pre‑existing users can log in. |
| `attribute_mapping` | Maps SAML attributes to Firefly III user fields. The key is the user field, the value is a single attribute name or an array of possible names (tried in order). |
| `allowed_domains` | Restricts authentication to specific email domains. Users with an email from a non‑listed domain are denied access. Leave empty to allow all domains. |

### Authentication

The guard triggers only when `AUTHENTICATION_GUARD_TYPE=saml` is set. Otherwise, it falls back to the original `RemoteUserGuard` behaviour.

### Additional Options

- **Session security** – The guard stores an HMAC‑signed token in the session instead of the plain user ID. This prevents session tampering. Check APP_KEY setting in .env
- **API routes** – Requests to `/api/*`, requests with an `Accept: application/json` header (excluding browser AJAX), or requests containing an `Authorization` header (Bearer/Basic) **skip** SAML redirection. This allows API tokens to work normally.
- **Intended URL** – The guard saves the original URL before redirecting to the IdP and restores it after successful login.

---

## Deployment

1. **Ensure HTTPS** – SAML requires secure cookies and endpoints. Always use HTTPS in production.
2. **Set proper session configuration** in `.env`:

       SESSION_SECURE_COOKIE=true
       SESSION_SAME_SITE=lax
       SESSION_LIFETIME=120

3. **Verify the IdP certificate** – The `x509cert` used in the tenant must be the **public certificate** of your IdP (without `-----BEGIN CERTIFICATE-----` line breaks). Usually it’s a single line string.
4. **Test the flow** – After deployment, try accessing a protected page (e.g., `//profile`). You should be redirected to your IdP, then back to the original page after login.

---

## Security Recommendations

1. **Keep `APP_DEBUG=false` in production** – Debug logs can expose sensitive SAML attributes.
2. **Validate SAML responses** – In `config/saml2.php`, set `'wantMessageSigned' => true` and `'wantAssertionsSigned' => true` to prevent tampering.
3. **Use strong session encryption** – Laravel’s `APP_KEY` must be unique and kept secret.
4. **Restrict auto‑creation** – Enable `auto_create_users` only if you fully trust your IdP. Otherwise, pre‑create user accounts manually.
5. **Domain whitelisting** – Use `allowed_domains` to limit who can log in, especially if auto‑creation is enabled.
6. **Logout handling** – The guard attempts global logout via IdP’s `SingleLogoutService`. If your IdP does not support SLO, you may want to remove the redirect in `logout()` to avoid errors.
7. **CSRF exclusions** – Only exclude `saml2/*` routes. Do not add other paths unless necessary.

---

## Troubleshooting

| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| Redirect loop (endless redirect to IdP) | Missing or invalid tenant configuration, or session issues. | Check that `saml2:create-tenant` was successful. Verify `saml2.php` `routesMiddleware` includes `'web'`. Clear cache. |
| `No tenant found` error | Tenant not created or database not migrated. | Run `php artisan migrate` and create a tenant with the artisan command. |
| User not logged in after IdP redirect | Session token validation fails (signature mismatch or expiry). | Check `storage/logs/laravel.log` for `Invalid token signature` or `Token expired`. Ensure `APP_KEY` is set and consistent. |
| API calls redirected to IdP | API detection failed. | Make sure your API requests either use the `/api/` path, send `Accept: application/json` (and are not AJAX), or include an `Authorization` header. |
| `email` attribute not found | Attribute name mismatch between IdP and `attribute_mapping`. | Check the IdP’s SAML response (look at logs) and adjust `attribute_mapping.email` accordingly. |
| `Blocked user` exception | User account is marked as blocked in Firefly III. | Unblock the user via admin panel or set `blocked = 0` in the `users` table. |
| "Authentication failed due to server error" | Generic exception during listener. | Inspect the full exception log entry. Common issues: missing `CreatesGroupMemberships` class (old Firefly III version) or database connection problems. |

If the issue persists, enable debug logging temporarily (`APP_DEBUG=true` and `LOG_LEVEL=debug`) and reproduce the problem. **Do not leave debug mode enabled in production.**

---

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

The original Firefly III is licensed under the [AGPL-3.0](https://github.com/firefly-iii/firefly-iii/blob/main/LICENSE).

---

**Built with ❤️ for the Firefly III community**
