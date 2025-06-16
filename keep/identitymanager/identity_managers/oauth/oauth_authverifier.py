import hashlib
import logging
import os

import requests
from fastapi import Depends, HTTPException

from keep.api.core.db import (
    create_user,
    update_user_last_sign_in,
    update_user_role,
    user_exists,
)
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase, oauth2_scheme
from keep.identitymanager.rbac import get_role_by_role_name
from keep.identitymanager.role_mapper import RoleMapper

logger = logging.getLogger(__name__)


def get_user_info(provider: str, access_token: str) -> dict:
    """Fetch user information from OAuth provider using access token"""

    try:
        if provider.lower() == "azure-ad":
            # Microsoft Graph API to get user info
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            if response.status_code != 200:
                logger.error(
                    f"Microsoft Graph API error: {response.status_code} - {response.text}"
                )
                raise HTTPException(
                    status_code=401, detail="Failed to fetch user info from Azure AD"
                )

            user_data = response.json()

            email = user_data.get("mail") or user_data.get("userPrincipalName")
            if not email:
                raise HTTPException(
                    status_code=401, detail="Could not retrieve email from Azure AD"
                )

            return {
                "email": email,
                "name": user_data.get("displayName"),
                "username": user_data.get("userPrincipalName"),
                "provider": "azure-ad",
            }

        elif provider.lower() == "github":
            # GitHub API to get user info
            response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Keep-OAuth-Client",
                },
                timeout=10,
            )

            if response.status_code != 200:
                logger.error(
                    f"GitHub API error: {response.status_code} - {response.text}"
                )
                raise HTTPException(
                    status_code=401, detail="Failed to fetch user info from GitHub"
                )

            user_data = response.json()

            # Get primary email if not public
            email = user_data.get("email")
            if not email:
                # Fetch user emails
                email_response = requests.get(
                    "https://api.github.com/user/emails",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "Keep-Auth-Client",
                    },
                    timeout=10,
                )

                if email_response.status_code == 200:
                    emails = email_response.json()
                    # Find primary email
                    for email_info in emails:
                        if email_info.get("primary", False):
                            email = email_info.get("email")
                            break

                    # Fallback to first verified email
                    if not email:
                        for email_info in emails:
                            if email_info.get("verified", False):
                                email = email_info.get("email")
                                break

            if not email:
                raise HTTPException(
                    status_code=401, detail="Could not retrieve email from GitHub"
                )

            return {
                "email": email,
                "name": user_data.get("name") or user_data.get("login"),
                "username": user_data.get("login"),
                "provider": "github",
            }

        else:
            raise HTTPException(
                status_code=400, detail=f"Unsupported OAuth provider: {provider}"
            )

    except requests.RequestException as e:
        logger.error(f"Network error fetching user info from {provider}: {e}")
        raise HTTPException(
            status_code=500, detail="Network error fetching user information"
        )
    except Exception as e:
        logger.error(f"Error fetching user info from {provider}: {e}")
        raise HTTPException(status_code=500, detail="Error fetching user information")


class OAuthVerifier(AuthVerifierBase):
    """Handles authentication and authorization for OAuth providers"""

    def __init__(self, scopes: list[str] = []) -> None:
        super().__init__(scopes)
        self.role_mapper = RoleMapper()
        # Keep track of hashed tokens so we won't update the user on the same token
        self.saw_tokens = set()

    def _verify_bearer_token(
        self, token: str = Depends(oauth2_scheme)
    ) -> AuthenticatedEntity:
        try:
            # Determine provider from environment variable
            auth_provider = os.environ.get("AUTH_PROVIDER", "").lower()
            if not auth_provider:
                raise HTTPException(
                    status_code=500,
                    detail="OAuth provider not configured. Please set AUTH_PROVIDER environment variable (e.g., 'github', 'microsoft-entra-id').",
                )

            # Fetch user info from OAuth provider
            user_info = get_user_info(auth_provider, token)

            # Extract user information
            tenant_id = "keep"  # Default tenant
            email = user_info["email"]

            if not email:
                raise HTTPException(
                    status_code=401, detail="No email provided by OAuth provider"
                )

            # Clean up email if needed
            if "#" in email:
                email = email.split("#")[1]

            # Map email to role
            role_name = self.role_mapper.get_role_from_email(email)
            if not role_name:
                self.logger.warning(
                    f"User {email} could not be mapped to any authorized role for Keep",
                    extra={
                        "tenant_id": tenant_id,
                        "email": email,
                    },
                )
                raise HTTPException(
                    status_code=403,
                    detail="User could not be mapped to any authorized role for Keep",
                )

            # Validate role scopes
            role = get_role_by_role_name(role_name)
            if not role.has_scopes(self.scopes):
                self.logger.warning(
                    f"Role {role_name} does not have required permissions",
                    extra={
                        "tenant_id": tenant_id,
                        "role": role_name,
                    },
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Role {role_name} does not have required permissions",
                )

            # Auto-provisioning logic
            hashed_token = hashlib.sha256(token.encode()).hexdigest()
            if hashed_token not in self.saw_tokens:
                if not user_exists(tenant_id, email):
                    create_user(
                        tenant_id=tenant_id, username=email, role=role_name, password=""
                    )
                else:
                    update_user_role(tenant_id, email, role_name)

                update_user_last_sign_in(tenant_id, email)
            self.saw_tokens.add(hashed_token)

            return AuthenticatedEntity(tenant_id, email, None, role_name)

        except HTTPException:
            # Re-raise known HTTP errors
            self.logger.exception("Token validation failed (HTTPException)")
            raise
        except Exception:
            self.logger.exception("Token validation failed")
            raise HTTPException(status_code=401, detail="Invalid token")

    def _authorize(self, authenticated_entity: AuthenticatedEntity) -> None:
        """
        Authorize the authenticated entity against required scopes
        """
        if not authenticated_entity.role:
            raise HTTPException(status_code=403, detail="No role assigned")

        role = get_role_by_role_name(authenticated_entity.role)
        if not role.has_scopes(self.scopes):
            raise HTTPException(
                status_code=403,
                detail="You don't have the required permissions to access this resource",
            )
