#!/bin/sh

echo "Starting Nextjs [${API_URL}]"
echo "AUTH_TYPE: ${AUTH_TYPE}"
echo "DEBUG AUTH: ${AUTH_DEBUG}"
echo "SENTRY_DISABLED: ${SENTRY_DISABLED}"

if [ -n "${NEXTAUTH_SECRET}" ]; then
    echo "NEXTAUTH_SECRET is set"
else
    echo "‼️ WARNING: NEXTAUTH_SECRET is not set, setting default value (INSECURE)"
    export NEXTAUTH_SECRET=secret
    echo "NEXTAUTH_SECRET: ${NEXTAUTH_SECRET}"
fi

# Check Azure AD environment variables if AUTH_TYPE is "azuread"
if [ "${AUTH_TYPE}" = "azuread" ] || [ "${AUTH_TYPE}" = "AZUREAD" ]; then
    echo "Checking Azure AD configuration..."

    # Simple direct checks with first 4 chars display
    if [ -n "$KEEP_AZUREAD_CLIENT_ID" ]; then
        echo "✓ KEEP_AZUREAD_CLIENT_ID: $(printf "%.4s" "$KEEP_AZUREAD_CLIENT_ID")****"
    else
        echo "⚠️ WARNING: KEEP_AZUREAD_CLIENT_ID is not set"
    fi

    if [ -n "$KEEP_AZUREAD_CLIENT_SECRET" ]; then
        echo "✓ KEEP_AZUREAD_CLIENT_SECRET: $(printf "%.4s" "$KEEP_AZUREAD_CLIENT_SECRET")****"
    else
        echo "⚠️ WARNING: KEEP_AZUREAD_CLIENT_SECRET is not set"
    fi

    if [ -n "$KEEP_AZUREAD_TENANT_ID" ]; then
        echo "✓ KEEP_AZUREAD_TENANT_ID: $(printf "%.4s" "$KEEP_AZUREAD_TENANT_ID")****"
    else
        echo "⚠️ WARNING: KEEP_AZUREAD_TENANT_ID is not set"
    fi
fi

# Check OAuth environment variables if AUTH_TYPE is "oauth"
if [ "${AUTH_TYPE}" = "oauth" ] || [ "${AUTH_TYPE}" = "OAUTH" ]; then
    echo "Checking OAuth configuration..."

    if [ -n "$KEEP_OAUTH_PROVIDER" ]; then
        echo "✓ KEEP_OAUTH_PROVIDER: ${KEEP_OAUTH_PROVIDER}"
        
        # Check provider-specific environment variables
        if [ "${KEEP_OAUTH_PROVIDER}" = "github" ]; then
            echo "Checking GitHub OAuth configuration..."
            if [ -n "$KEEP_OAUTH_GITHUB_CLIENT_ID" ]; then
                echo "✓ KEEP_OAUTH_GITHUB_CLIENT_ID: $(printf "%.4s" "$KEEP_OAUTH_GITHUB_CLIENT_ID")****"
            else
                echo "⚠️ WARNING: KEEP_OAUTH_GITHUB_CLIENT_ID is not set"
            fi
            if [ -n "$KEEP_OAUTH_GITHUB_CLIENT_SECRET" ]; then
                echo "✓ KEEP_OAUTH_GITHUB_CLIENT_SECRET: $(printf "%.4s" "$KEEP_OAUTH_GITHUB_CLIENT_SECRET")****"
            else
                echo "⚠️ WARNING: KEEP_OAUTH_GITHUB_CLIENT_SECRET is not set"
            fi
        elif [ "${KEEP_OAUTH_PROVIDER}" = "azuread" ]; then
            echo "Checking Azure AD OAuth configuration..."
            if [ -n "$KEEP_OAUTH_AZUREAD_CLIENT_ID" ]; then
                echo "✓ KEEP_OAUTH_AZUREAD_CLIENT_ID: $(printf "%.4s" "$KEEP_OAUTH_AZUREAD_CLIENT_ID")****"
            else
                echo "⚠️ WARNING: KEEP_OAUTH_AZUREAD_CLIENT_ID is not set"
            fi
            if [ -n "$KEEP_OAUTH_AZUREAD_CLIENT_SECRET" ]; then
                echo "✓ KEEP_OAUTH_AZUREAD_CLIENT_SECRET: $(printf "%.4s" "$KEEP_OAUTH_AZUREAD_CLIENT_SECRET")****"
            else
                echo "⚠️ WARNING: KEEP_OAUTH_AZUREAD_CLIENT_SECRET is not set"
            fi
            if [ -n "$KEEP_OAUTH_AZUREAD_TENANT_ID" ]; then
                echo "✓ KEEP_OAUTH_AZUREAD_TENANT_ID: $(printf "%.4s" "$KEEP_OAUTH_AZUREAD_TENANT_ID")****"
            else
                echo "⚠️ WARNING: KEEP_OAUTH_AZUREAD_TENANT_ID is not set"
            fi
        else
            echo "⚠️ WARNING: Unknown OAuth provider: ${KEEP_OAUTH_PROVIDER}"
        fi
    else
        echo "⚠️ WARNING: KEEP_OAUTH_PROVIDER is not set"
    fi
fi

exec node server.js
