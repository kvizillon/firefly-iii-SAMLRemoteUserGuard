<?php

/**
 * SAML SignedIn Event Listener for Firefly III
 *
 * This listener handles the SignedIn event dispatched by the scaler-tech/laravel-saml2 package.
 * It extracts user data from the SAML response, creates or updates the local user account,
 * assigns appropriate roles, and logs the user into the application using the SAMLRemoteUserGuard.
 *
 * @link https://github.com/kvizillon/firefly-iii-SAMLRemoteUserGuard
 *
 * @package FireflyIII\Listeners\Security\User
 */

namespace FireflyIII\Listeners\Security\User;

use Slides\Saml2\Events\SignedIn;
use FireflyIII\User;
use FireflyIII\Models\Role;
use FireflyIII\Console\Commands\Correction\CreatesGroupMemberships;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class SamlSignedInListener
{
    /**
     * Handle the SignedIn event.
     *
     * @param SignedIn $event
     * @return void
     * @throws AccessDeniedHttpException
     */
    public function handle(SignedIn $event): void
    {
        Log::debug('SamlSignedInListener: SignedIn event fired');

        try {
            // Get SAML user data
            $samlUser = $event->getSaml2User();

            // Extract email and name using attribute mapping from config
            $email = $this->getSamlAttributeValue($samlUser, 'email');
            $name  = $this->getSamlAttributeValue($samlUser, 'name');

            Log::debug('SamlSignedInListener: SAML user data', [
                'email'      => $email ?? 'not found',
                'name'       => $name ?? 'not found',
                'attributes' => array_keys($samlUser->getAttributes()),
                'userId'     => $samlUser->getUserId()
            ]);

            if (!$email) {
                Log::error('SamlSignedInListener: No email provided in SAML response');
                throw new AccessDeniedHttpException('SAML response did not contain email address.');
            }

            // Validate email domain if restrictions are configured
            $this->validateEmailDomain($email);

            $autoCreateUsers = config('saml-guard.auto_create_users', true);

            // Try to find existing user by email
            $user = User::where('email', $email)->first();

            if ($user && $user->blocked) {
                Log::warning('SamlSignedInListener: Blocked user attempted to login', [
                    'user_id' => $user->id,
                    'email'   => $user->email
                ]);
                throw new AccessDeniedHttpException(
                    'Your account has been blocked. Please contact the administrator.'
                );
            }

            // Handle case when user doesn't exist
            if (!$user) {
                if ($autoCreateUsers) {
                    // Auto-creation is enabled - create new user
                    Log::info('SamlSignedInListener: User not found, auto-creating new user', [
                        'email' => $email
                    ]);

                    // Generate name from available data if not provided by SAML
                    if (empty($name)) {
                        $name = explode('@', $email)[0];
                    }

                    // Create user (same as RemoteUserProvider)
                    $user = User::create([
                        'email'        => $email,
                        'name'         => $name,
                        'password'     => bcrypt(Str::random(32)),
                        'blocked'      => false,
                        'blocked_code' => null,
                    ]);

                    // If this is the first user, grant them owner role
                    if (User::count() === 1) {
                        $roleObject = Role::where('name', 'owner')->first();
                        if ($roleObject) {
                            $user->roles()->attach($roleObject);
                            Log::info('SamlSignedInListener: First user granted owner role', [
                                'user_id' => $user->id
                            ]);
                        }
                    }

                    Log::info('SamlSignedInListener: User auto-created successfully', [
                        'user_id' => $user->id,
                        'email'   => $user->email
                    ]);
                } else {
                    // Auto-creation is disabled - throw AccessDeniedHttpException
                    Log::warning('SamlSignedInListener: User not found and auto-create is disabled', [
                        'email' => $email
                    ]);

                    throw new AccessDeniedHttpException(
                        'User with email ' . $email . ' not found in the system. Please contact your administrator.'
                    );
                }
            } else {
                Log::debug('SamlSignedInListener: Existing user found', [
                    'user_id' => $user->id,
                    'email'   => $user->email
                ]);
            }

            // Create/verify user group (exactly as RemoteUserProvider does)
            CreatesGroupMemberships::createGroupMembership($user);

            Log::debug('SamlSignedInListener: User group created/verified');

            // Log the user in using the correct guard
            Auth::guard('remote_user_guard')->login($user);
            Log::debug('SamlSignedInListener: User logged in successfully', [
                'user_id' => $user->id,
                'guard'   => 'SamlRemoteUserGuard'
            ]);

            // Restore originally requested URL
            $this->restoreIntendedUrl();
        } catch (AccessDeniedHttpException $e) {
            throw $e;
        } catch (\Exception $e) {
            Log::error('SamlSignedInListener: Exception occurred', [
                'message' => $e->getMessage(),
                'file'    => $e->getFile(),
                'line'    => $e->getLine()
            ]);

            throw new AccessDeniedHttpException(
                'Authentication failed due to server error. Please contact administrator.'
            );
        }
    }

    /**
     * Get SAML attribute value based on mapping configuration.
     *
     * The configuration key 'saml-guard.attribute_mapping' defines which SAML attributes
     * correspond to user model fields. This method supports both single attribute names
     * and arrays of possible names (tried in order).
     *
     * @param mixed  $samlUser  The SAML user object.
     * @param string $fieldName The user model field name ('email', 'name', etc.).
     * @return string|null The attribute value or null if not found.
     */
    private function getSamlAttributeValue($samlUser, string $fieldName): ?string
    {
        $mapping = config('saml-guard.attribute_mapping', []);

        if (!isset($mapping[$fieldName])) {
            return null;
        }

        $attributeNames = $mapping[$fieldName];

        // Convert single string to array for uniform processing
        if (is_string($attributeNames)) {
            $attributeNames = [$attributeNames];
        }

        // Try each possible attribute name in order
        foreach ($attributeNames as $attributeName) {
            $value = $samlUser->getAttribute($attributeName);

            if (!empty($value[0])) {
                $value = trim($value[0]);

                // Special validation for email field
                if ($fieldName === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    Log::debug('SamlSignedInListener: Invalid email format', [
                        'attribute' => $attributeName,
                        'value'     => $value
                    ]);
                    continue;
                }

                Log::debug('SamlSignedInListener: Extracted attribute value', [
                    'field'     => $fieldName,
                    'attribute' => $attributeName,
                    'value'     => $value
                ]);

                return $value;
            }
        }

        // Fallback for email: try NameID if no email attribute found
        if ($fieldName === 'email') {
            $nameId = $samlUser->getUserId();
            if ($nameId && filter_var($nameId, FILTER_VALIDATE_EMAIL)) {
                Log::debug('SamlSignedInListener: Using NameID as email fallback', ['email' => $nameId]);
                return $nameId;
            }
        }

        Log::debug('SamlSignedInListener: No value found for field', ['field' => $fieldName]);
        return null;
    }

    /**
     * Validate that the email domain is allowed.
     *
     * If the configuration 'saml-guard.allowed_domains' is not empty, the email's domain
     * must be present in that list. Otherwise, any domain is permitted.
     *
     * @param string $email The email address to validate.
     * @return void
     * @throws AccessDeniedHttpException If the domain is not allowed.
     */
    private function validateEmailDomain(string $email): void
    {
        $allowedDomains = config('saml-guard.allowed_domains', []);

        if (empty($allowedDomains)) {
            return;
        }

        $domain = substr(strrchr($email, "@"), 1);

        if (!in_array($domain, $allowedDomains)) {
            Log::warning('SamlSignedInListener: User from disallowed domain attempted login', [
                'email'          => $email,
                'domain'         => $domain,
                'allowed_domains' => $allowedDomains
            ]);

            throw new AccessDeniedHttpException(
                "Login from domain '{$domain}' is not allowed. Please use an approved email domain."
            );
        }

        Log::debug('SamlSignedInListener: Email domain validated', ['domain' => $domain]);
    }

    /**
     * Restore the originally requested URL after successful login.
     *
     * The URL stored in the session before redirecting to the IdP is restored
     * as the intended destination. SAML routes are excluded to avoid redirect loops.
     *
     * @return void
     */
    private function restoreIntendedUrl(): void
    {
        try {
            if (session()->has('saml_intended_url')) {
                $intendedUrl = session('saml_intended_url');
                session()->forget('saml_intended_url');

                // Don't restore SAML routes to avoid redirect loops
                if ($intendedUrl && !str_contains($intendedUrl, '/saml2')) {
                    session(['url.intended' => $intendedUrl]);
                    Log::debug('SamlSignedInListener: Restored intended URL', ['url' => $intendedUrl]);
                }
            }
        } catch (\Exception $e) {
            Log::debug('SamlSignedInListener: Could not restore intended URL', ['error' => $e->getMessage()]);
        }
    }
}
