import fnmatch
import logging
import os

import yaml

from keep.api.core.config import config

logger = logging.getLogger(__name__)


class RoleMapper:
    """Maps users to Keep roles via email-based mapping (reusable across auth types)"""

    def __init__(self) -> None:
        self.role_mapping_file = config("KEEP_ROLE_MAPPING_FILE", default=None)
        self.default_role = config("KEEP_ROLE_MAPPING_DEFAULT_ROLE", default="noc")
        self.role_mappings = {}  # role -> list of users/patterns
        self.user_to_role_cache = {}  # cached email -> role mapping for performance
        self.mappings_loaded = False

        # Load role mappings once at startup
        self._load_role_mappings()

    def _load_role_mappings(self) -> None:
        """Load role mappings from YAML file at startup"""
        if not self.role_mapping_file or not os.path.exists(self.role_mapping_file):
            logger.warning(
                f"Role mapping file not found: {self.role_mapping_file}. Using default role: {self.default_role}"
            )
            self.mappings_loaded = True
            return

        try:
            with open(self.role_mapping_file, "r") as f:
                config_data = yaml.safe_load(f) or {}
                self.role_mappings = config_data.get("role_mappings", {})
                self.mappings_loaded = True

            # Count total users across all roles
            total_users = sum(
                len(users) if isinstance(users, list) else 0
                for users in self.role_mappings.values()
            )
            logger.info(
                f"Loaded {len(self.role_mappings)} roles with {total_users} user mappings from {self.role_mapping_file}"
            )

        except Exception as e:
            logger.error(
                f"Failed to load role mappings from {self.role_mapping_file}: {e}"
            )
            self.role_mappings = {}
            self.mappings_loaded = True

    def get_role_from_email(self, email: str) -> str:
        """
        Determine Keep role based on user email
        Returns role name or default role if no match found
        """
        email_lower = email.lower()

        # First pass: exact matches (highest priority)
        for role, users in self.role_mappings.items():
            if not isinstance(users, list):
                logger.warning(f"Role {role} has invalid user list format, skipping")
                continue

            for user in users:
                if isinstance(user, str) and user.lower() == email_lower:
                    logger.debug(f"Found exact match for {email} in role {role}")
                    return role

        # Second pass: pattern matches
        for role, users in self.role_mappings.items():
            if not isinstance(users, list):
                continue

            for user_pattern in users:
                if isinstance(user_pattern, str) and "*" in user_pattern:
                    if fnmatch.fnmatch(email_lower, user_pattern.lower()):
                        logger.debug(
                            f"Found pattern match for {email} with pattern {user_pattern} in role {role}"
                        )
                        return role

        # No matches found, use default
        logger.debug(
            f"No role mapping found for {email}, using default role: {self.default_role}"
        )
        return self.default_role
