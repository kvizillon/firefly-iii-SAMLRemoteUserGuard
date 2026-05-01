<?php

/**
 * SAML Remote User Guard for Firefly III
 *
 * This guard extends the default RemoteUserGuard to provide SAML-based authentication
 * using the scaler-tech/laravel-saml2 package. It supports automatic user creation,
 * attribute mapping, session token signing, and API route skipping.
 *
 * @link https://github.com/kvizillon/firefly-iii-SAMLRemoteUserGuard
 *
 * @package FireflyIII\Support\Authentication
 */

namespace FireflyIII\Support\Authentication;

use FireflyIII\Support\Authentication\RemoteUserGuard;
use FireflyIII\User;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Slides\Saml2\Models\Tenant;

class SamlRemoteUserGuard extends RemoteUserGuard
{
    /**
     * Cached SAML route prefix.
     */
    private ?string $cachedPrefix = null;

    /**
     * Cached tenant instance to avoid repeated database queries.
     */
    private ?Tenant $cachedTenant = null;

    /**
     * Flag indicating whether an authentication attempt has been made.
     */
    protected $tried = false;

    /**
     * The current HTTP request instance.
     */
    protected $request;

    /**
     * Create a new SAML Remote User Guard instance.
     *
     * @param UserProvider $provider
     * @param Application $app
     */
    public function __construct(UserProvider $provider, Application $app)
    {
        parent::__construct($provider, $app);
        $this->request = $app['request'];
        Log::debug('SamlRemoteUserGuard constructed');
    }

    /**
     * Get the session key used to store the user token.
     *
     * @return string
     */
    protected function getName(): string
    {
        return 'login_' . sha1(static::class);
    }

    /**
     * Attempt to authenticate the current request.
     *
     * @return void
     * @throws AccessDeniedHttpException
     */
    public function authenticate(): void
    {
        $guardType = config('auth.guard_type', 'remote_user');
        Log::debug('Current guard', [
            'name' => 'remote_user_guard',
            'type' => $guardType
        ]);

        $this->tried = true;

        if ($guardType === 'saml') {
            $path = $this->request->path();

            if ($this->shouldSkipAuthentication($path)) {
                return;
            }

            if ($this->handleInvalidUserFlag()) {
                return;
            }

            Log::debug(sprintf('SAML mode: Now at %s', __METHOD__));

            if ($this->user instanceof User) {
                Log::debug(sprintf('SAML mode: User already authenticated: user_id=%d, "%s".', $this->user->id, $this->user->email));
                return;
            }

            $sessionKey = $this->getName();
            try {
                $userToken = $this->request->session()->get($sessionKey);
            } catch (\Exception $e) {
                Log::debug('SAML mode: Session not available', ['error' => $e->getMessage()]);
                return;
            }

            Log::debug('SAML mode: Checking user in session', [
                'session_key' => $sessionKey,
                'has_token' => !empty($userToken)
            ]);

            if ($userToken) {
                // Validate the signed token
                $userId = $this->validateUserToken($userToken);
                if ($userId === null) {
                    Log::debug('SAML mode: Invalid or expired token, clearing session');
                    $this->clearSession();
                    return;
                }

                Log::debug('SAML mode: Valid token found in session', ['user_id' => $userId]);
                $userId = filter_var($userId, FILTER_VALIDATE_INT);
                $user = (is_numeric($userId) && $userId > 0) ? User::find($userId) : null;

                if ($user instanceof User) {
                    if ($user->blocked) {
                        Log::warning('SAML mode: Blocked user attempted to login', [
                            'user_id' => $user->id,
                            'email' => $user->email,
                            'blocked_code' => $user->blocked_code
                        ]);

                        $this->clearSession();

                        throw new AccessDeniedHttpException(
                            'Your account has been blocked. Please contact the administrator.'
                        );
                    }

                    $this->setUser($user);
                    Log::debug('SAML mode: Existing user found by user_id', ['user_id' => $this->user->id]);
                    return;
                } else {
                    Log::debug('SAML mode: Wrong user_id in session, clear session', [
                        'session_key' => $sessionKey,
                        'user_id' => $userId
                    ]);
                    $this->clearSession();
                }
            }

            $tenant = $this->getTenant();
            if (!$tenant) {
                Log::error('SAML mode: No tenant available, cannot proceed');
                throw new \Exception('SAML configuration error: No tenant found');
            }

            Log::debug('SAML mode: no user, redirecting to IdP', [
                'tenant_uuid' => $tenant->uuid,
                'tenant_key' => $tenant->key
            ]);

            $returnPath = $this->request->path();
            $fullUrl = $this->request->fullUrl();

            try {
                if ($this->request->hasSession()) {
                    $this->request->session()->put('saml_intended_url', $fullUrl);
                    Log::debug('SAML mode: Stored intended URL', ['url' => $fullUrl]);
                }
            } catch (\Exception $e) {
                Log::debug('SAML mode: Could not store intended URL', ['error' => $e->getMessage()]);
            }

            $redirectUrl = saml_url($returnPath, $tenant->uuid);

            Log::debug('SAML redirect URL', ['url' => $redirectUrl]);
            header('Location: ' . $redirectUrl);
            exit;
        }

        parent::authenticate();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return User|null
     */
    public function user(): ?User
    {
        if (false === $this->tried) {
            Log::debug('SAML mode: Have not tried authentication, do it now.');
            $this->authenticate();
        }

        $user = $this->user;

        if (!$user instanceof User) {
            Log::debug('SAML mode: User is NULL');
            return null;
        }

        return $user;
    }

    /**
     * Log a user into the application.
     *
     * @param User $user
     * @return void
     */
    public function login(User $user): void
    {
        Log::debug('SamlRemoteUserGuard::login() called', ['user_id' => $user->id]);

        $this->setUser($user);

        $sessionKey = $this->getName();

        try {
            if ($this->request->hasSession()) {
                // Regenerate session ID to prevent fixation attacks
                $this->request->session()->regenerate(true);

                // Store a signed token instead of the plain user ID
                $userToken = $this->generateUserToken($user);
                $this->request->session()->put($sessionKey, $userToken);

                Log::debug('SAML mode: Session regenerated and user logged in', [
                    'session_key' => $sessionKey,
                    'user_id' => $user->id,
                    'session_id' => $this->request->session()->getId()
                ]);
            } else {
                Log::debug('SAML mode: No session available, user will be logged in on next request');
            }
        } catch (\Exception $e) {
            Log::debug('SAML mode: Could not create session', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Log the user out of the application and optionally redirect to IdP for global logout.
     *
     * @return void
     * @throws AccessDeniedHttpException
     */
    public function logout(): void
    {
        Log::debug('SAML mode: SamlRemoteUserGuard::logout() called');

        $this->clearSession();
        $this->user = null;

        $tenant = $this->getTenant();

        if ($tenant && $tenant->idp_logout_url) {
            Log::debug('SAML mode: Redirecting to IdP for global logout', [
                'logout_url' => $tenant->idp_logout_url
            ]);

            try {
                $logoutUrl = route('saml.logout', ['uuid' => $tenant->uuid]);
                header('Location: ' . $logoutUrl);
                exit;
            } catch (\Exception $e) {
                Log::debug('SAML mode: Failed to initiate IdP logout', ['error' => $e->getMessage()]);
            }
        } else {
            Log::debug('SAML mode: No idp_logout_url found, skipping IdP notification');
        }

        throw new AccessDeniedHttpException('You have been logged out locally, but the global session could not be terminated automatically.');
    }

    /**
     * Get the SAML tenant to use for authentication.
     *
     * @return Tenant|null
     */
    protected function getTenant(): ?Tenant
    {
        // Return cached tenant if available
        if ($this->cachedTenant !== null) {
            return $this->cachedTenant;
        }

        // Try to get tenant from configuration first
        $tenantKey = config('saml2.active_tenant', 'default');

        if ($tenantKey && $tenantKey !== 'default') {
            $tenant = Tenant::where('key', $tenantKey)->first();
            if ($tenant) {
                $this->cachedTenant = $tenant;
                Log::debug('SAML mode: Tenant loaded by key', ['key' => $tenantKey]);
                return $tenant;
            }
        }

        // Fallback to first available tenant
        $tenants = Tenant::all();

        if ($tenants->isEmpty()) {
            Log::error('SAML mode: No tenants found in database');
            return null;
        }

        if ($tenants->count() > 1) {
            Log::warning('SAML mode: Multiple tenants found, using first one. Consider setting saml2.active_tenant config.', [
                'total' => $tenants->count(),
                'selected_uuid' => $tenants->first()->uuid
            ]);
        }

        $this->cachedTenant = $tenants->first();
        return $this->cachedTenant;
    }

    /**
     * Clear the session data related to this guard.
     *
     * @return void
     */
    private function clearSession(): void
    {
        $sessionKey = $this->getName();

        if (!$this->request->hasSession()) {
            Log::debug('SAML mode: No session to clear');
            return;
        }

        try {
            $this->request->session()->forget($sessionKey);
            $this->request->session()->invalidate();
            $this->request->session()->regenerateToken();

            Log::debug('SAML mode: Full session invalidated');
        } catch (\Exception $e) {
            Log::debug('SAML mode: Could not clear session', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Determine if authentication should be skipped for the current request.
     *
     * @param string $path
     * @return bool
     */
    private function shouldSkipAuthentication(string $path): bool
    {
        if (App::runningInConsole()) {
            Log::debug('SAML mode: Running in console, will not authenticate.');
            return true;
        }

        if ($this->isSamlRoute($path)) {
            Log::debug('SAML mode: On SAML route, skipping authentication', [
                'path' => $path,
                'prefix' => $this->getSamlRoutePrefix()
            ]);
            return true;
        }

        // API routes - always skip, let API token authentication handle it
        if ($this->isApiRoute()) {
            Log::debug('SAML mode: On API route, skipping SAML authentication', [
                'path' => $path,
                'accept_header' => $this->request->header('Accept'),
                'has_auth_header' => $this->request->hasHeader('Authorization')
            ]);
            return true;
        }

        return false;
    }

    /**
     * Generate a signed token for the user session to prevent ID tampering.
     *
     * @param User $user
     * @return string
     */
    private function generateUserToken(User $user): string
    {
        $payload = json_encode([
            'id' => $user->id,
            'email' => $user->email,
            'expires' => now()->addMinutes(config('session.lifetime', 120))->timestamp
        ]);

        $signature = hash_hmac('sha256', $payload, config('app.key'));

        return base64_encode($payload . '||' . $signature);
    }

    /**
     * Validate a signed user token and extract the user ID.
     *
     * @param string $token
     * @return int|null
     */
    private function validateUserToken(string $token): ?int
    {
        try {
            $decoded = base64_decode($token);

            if (!$decoded || !str_contains($decoded, '||')) {
                Log::debug('SAML mode: Invalid token format');
                return null;
            }

            [$payload, $signature] = explode('||', $decoded, 2);

            // Verify signature
            $expectedSignature = hash_hmac('sha256', $payload, config('app.key'));

            if (!hash_equals($expectedSignature, $signature)) {
                Log::debug('SAML mode: Invalid token signature');
                return null;
            }

            $data = json_decode($payload, true);

            if (!$data || !isset($data['id'], $data['expires'])) {
                Log::debug('SAML mode: Invalid token payload');
                return null;
            }

            // Check expiration
            if ($data['expires'] < time()) {
                Log::debug('SAML mode: Token expired');
                return null;
            }

            return (int)$data['id'];
        } catch (\Exception $e) {
            Log::debug('SAML mode: Token validation error', ['error' => $e->getMessage()]);
            return null;
        }
    }

    /**
     * Get the configured SAML route prefix.
     *
     * @return string
     */
    private function getSamlRoutePrefix(): string
    {
        if ($this->cachedPrefix === null) {
            $prefix = config('saml2.routesPrefix', '/saml2');
            $this->cachedPrefix = $prefix;
        }
        return $this->cachedPrefix;
    }

    /**
     * Check if the current request path belongs to a SAML route.
     *
     * @param string $path
     * @return bool
     */
    private function isSamlRoute(string $path): bool
    {
        $prefix = $this->getSamlRoutePrefix();

        $prefixWithoutSlash = ltrim($prefix, '/');

        if (strpos($path, $prefixWithoutSlash . '/') === 0) {
            return true;
        }

        if ($this->request->is(trim($prefix, '/') . '/*')) {
            return true;
        }

        return false;
    }

    /**
     * Detect if the current request is an API request that should not trigger SAML redirection.
     *
     * API requests are identified by:
     * - Path starting with "api/"
     * - Accept header containing "application/json" (excluding browser AJAX)
     * - Presence of Authorization header with Bearer or Basic token
     *
     * @return bool
     */
    private function isApiRoute(): bool
    {
        $path = $this->request->path();

        // Check by URL path (Firefly III standard)
        if (str_starts_with($path, 'api/')) {
            return true;
        }

        // Check by Accept header (typical for API clients)
        $acceptHeader = $this->request->header('Accept');
        if ($acceptHeader && str_contains($acceptHeader, 'application/json')) {
            // But don't treat browser AJAX requests as API
            $isAjax = $this->request->ajax();
            $isJsonApi = !$isAjax && str_contains($acceptHeader, 'application/json');

            if ($isJsonApi) {
                return true;
            }
        }

        // Check for API token in Authorization header (Bearer token or Basic auth)
        if ($this->request->hasHeader('Authorization')) {
            $authHeader = $this->request->header('Authorization');
            if (str_starts_with($authHeader, 'Bearer ') || str_starts_with($authHeader, 'Basic ')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if there's an invalid user flag in session and perform logout if needed.
     *
     * @return bool True if invalid user was detected and logout was triggered
     */
    private function handleInvalidUserFlag(): bool
    {
        if (!session()->has('saml_invalid_user')) {
            return false;
        }
        
        $invalidUser = session()->get('saml_invalid_user');
        
        // Clear the flag to prevent loops
        session()->forget('saml_invalid_user');
        
        Log::info('SAML mode: Invalid user detected, initiating IdP logout', [
            'email' => $invalidUser['email'] ?? 'unknown',
            'timestamp' => $invalidUser['timestamp'] ?? 'unknown'
        ]);
        
        // Perform IdP logout
        $this->logout();
        
        return true; // logout() will exit, so this line is never reached
    }
}
