<?php

/**
 * SAML Guard Configuration for Firefly III
 *
 * This configuration file controls the behavior of the SAML authentication guard.
 * It defines user auto-creation, attribute mapping between SAML responses and local user fields,
 * and optional domain restrictions.
 *
 * @link https://github.com/kvizillon/firefly-iii-SAMLRemoteUserGuard
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Auto-create users
    |--------------------------------------------------------------------------
    |
    | Automatically create a local user account when a user successfully
    | authenticates via SAML but does not yet exist in the database.
    | When set to false, users must be pre-created by an administrator.
    |
    */
    'auto_create_users' => env('SAML_AUTO_CREATE_USERS', false),

    /*
    |--------------------------------------------------------------------------
    | SAML attribute mapping
    |--------------------------------------------------------------------------
    |
    | Map SAML attributes to fields in the users table.
    | The key is the user model field, the value is the SAML attribute name
    | or an array of possible attribute names (tried in order).
    | The first matching attribute that contains a non-empty value will be used.
    |
    */
    'attribute_mapping' => [
        'email' => [
            'email',
            'Email',
            'mail',
            'Mail',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        ],
        'name' => 'name',
    ],

    /*
    |--------------------------------------------------------------------------
    | Allowed email domains
    |--------------------------------------------------------------------------
    |
    | Restrict authentication to users from specific email domains.
    | Example: ['company.com', 'example.org']
    | Leave the array empty to allow all domains.
    |
    */
    'allowed_domains' => env('SAML_ALLOWED_DOMAINS')
        ? array_map('trim', explode(',', env('SAML_ALLOWED_DOMAINS')))
        : [],
    
    /*
    |--------------------------------------------------------------------------
    | Active Tenant
    |--------------------------------------------------------------------------
    |
    | Specify which tenant to use when multiple tenants exist.
    | Set to the key of the desired tenant.
    |
    */
    'active_tenant' => env('SAML_ACTIVE_TENANT', 'default'),
];
