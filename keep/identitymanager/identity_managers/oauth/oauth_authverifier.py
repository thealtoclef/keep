import hashlib
import logging
import os

import jwt
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
            # Get the KEEP_JWT_SECRET from environment
            keep_jwt_secret = os.environ.get("KEEP_JWT_SECRET")
            if not keep_jwt_secret:
                raise HTTPException(
                    status_code=500,
                    detail="KEEP_JWT_SECRET must be configured for OAuth authentication.",
                )

            try:
                # Verify and decode the JWT token signed by NextAuth
                payload = jwt.decode(token, keep_jwt_secret, algorithms=["HS256"])

                # Extract email from the verified payload
                email = payload.get("email")
                if not email:
                    raise HTTPException(
                        status_code=401, detail="No email found in token payload"
                    )

                self.logger.info(f"Successfully verified JWT token for user: {email}")

            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token has expired")
            except jwt.InvalidTokenError as e:
                self.logger.warning(f"Invalid JWT token: {e}")
                raise HTTPException(status_code=401, detail="Invalid token")

            # Extract user information
            tenant_id = "keep"  # Default tenant

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
