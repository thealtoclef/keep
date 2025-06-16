from keep.api.models.user import User
from keep.contextmanager.contextmanager import ContextManager
from keep.identitymanager.identity_managers.db.db_identitymanager import (
    DbIdentityManager,
)
from keep.identitymanager.identity_managers.oauth.oauth_authverifier import (
    OAuthVerifier,
)
from keep.identitymanager.identitymanager import BaseIdentityManager


class OAuthIdentityManager(BaseIdentityManager):
    def __init__(self, tenant_id, context_manager: ContextManager, **kwargs) -> None:
        super().__init__(tenant_id, context_manager, **kwargs)
        self.db_identity_manager = DbIdentityManager(
            tenant_id, context_manager, **kwargs
        )

    def get_users(self) -> list[User]:
        return self.db_identity_manager.get_users(self.tenant_id)

    def get_auth_verifier(self, scopes) -> OAuthVerifier:
        return OAuthVerifier(scopes)

    # No need to create users for OAuth - they are auto-provisioned
    def create_user(self, **kwargs) -> None:
        return None

    # Not implemented - OAuth users are managed externally
    def update_user(self, user_email: str, update_data: dict) -> None:
        raise NotImplementedError("OAuthIdentityManager.update_user")

    # Not implemented - OAuth users are managed externally
    def delete_user(self, user_email=None, **kwargs) -> None:
        raise NotImplementedError("OAuthIdentityManager.delete_user")
