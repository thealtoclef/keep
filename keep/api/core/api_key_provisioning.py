import hashlib
import logging
import os

from sqlmodel import Session, select

from keep.api.core.db_utils import create_db_engine
from keep.api.models.db.tenant import TenantApiKey
from keep.contextmanager.contextmanager import ContextManager
from keep.secretmanager.secretmanagerfactory import SecretManagerFactory

logger = logging.getLogger(__name__)

engine = create_db_engine()


def provision_api_keys(api_keys: dict, tenant_id: str) -> None:
    """
    Provision API keys from a dictionary configuration.

    Args:
        api_keys (dict): Dictionary of API key configurations {key_hash: {name: str, role: str, secret: str}}
        tenant_id (str): The tenant ID
    """
    try:
        with Session(engine) as session:
            # Get existing system API keys
            existing_api_keys = session.exec(
                select(TenantApiKey).where(
                    TenantApiKey.tenant_id == tenant_id,
                    TenantApiKey.is_system == True,
                    TenantApiKey.created_by == "system",
                )
            ).all()
            existing_keys_map = {
                api_key.key_hash: api_key for api_key in existing_api_keys
            }

            # Set operations for efficient reconciliation
            desired_keys_set = set(api_keys.keys())
            existing_keys_set = set(existing_keys_map.keys())

            keys_to_create = desired_keys_set - existing_keys_set
            keys_to_update = desired_keys_set & existing_keys_set
            keys_to_delete = existing_keys_set - desired_keys_set

            context_manager = ContextManager(tenant_id=tenant_id)
            secret_manager = SecretManagerFactory.get_secret_manager(context_manager)

            # CREATE new API keys
            for key_hash in keys_to_create:
                api_key = api_keys[key_hash]
                api_key_name = api_key["name"]
                api_key_role = api_key["role"]
                api_key_secret = api_key["secret"]
                logger.info(f"Provisioning api key {api_key_name}")

                new_installation_api_key = TenantApiKey(
                    tenant_id=tenant_id,
                    reference_id=api_key_name,
                    key_hash=key_hash,
                    is_system=True,
                    created_by="system",
                    role=api_key_role,
                )
                session.add(new_installation_api_key)
                # write to the secret manager
                try:
                    secret_manager.write_secret(
                        secret_name=f"{tenant_id}-{api_key_name}",
                        secret_value=api_key_secret,
                    )
                except Exception:
                    logger.exception(
                        f"Failed to write secret for api key {api_key_name}"
                    )
                logger.info(f"Api key {api_key_name} provisioned")

            # UPDATE existing API keys
            for key_hash in keys_to_update:
                api_key = api_keys[key_hash]
                api_key_name = api_key["name"]
                api_key_role = api_key["role"]
                api_key_secret = api_key["secret"]

                existing_key = existing_keys_map[key_hash]
                existing_api_key_name = existing_key.reference_id
                existing_api_key_role = existing_key.role

                needs_update = (
                    existing_api_key_name != api_key_name
                    or existing_api_key_role != api_key_role
                    or existing_key.is_deleted
                )
                if needs_update:
                    logger.info(f"Updating api key {api_key_name}")

                    # If the name is changing, clean up the old secret first
                    if existing_api_key_name != api_key_name:
                        logger.info(
                            f"API key name changing from {existing_api_key_name} to {api_key_name}"
                        )
                        try:
                            secret_manager.delete_secret(
                                secret_name=f"{tenant_id}-{existing_api_key_name}",
                            )
                            logger.info(
                                f"Deleted old secret for api key {existing_api_key_name}"
                            )
                        except Exception as e:
                            # Check if it's a 404 error (secret doesn't exist) - this is acceptable
                            error_msg = str(e).lower()
                            if "404" in error_msg or "not found" in error_msg:
                                logger.info(
                                    f"Old secret for api key {existing_api_key_name} already doesn't exist - this is fine"
                                )
                            else:
                                logger.exception(
                                    f"Failed to delete old secret for api key {existing_api_key_name}"
                                )

                    # Update fields
                    existing_key.reference_id = api_key_name
                    existing_key.role = api_key_role
                    existing_key.is_deleted = False

                    # write to the secret manager with new name
                    try:
                        secret_manager.write_secret(
                            secret_name=f"{tenant_id}-{api_key_name}",
                            secret_value=api_key_secret,
                        )
                    except Exception:
                        logger.exception(
                            f"Failed to write secret for api key {api_key_name}"
                        )
                    logger.info(f"Api key {api_key_name} updated")
                else:
                    logger.info(
                        f"Api key {api_key_name} already exists and is up to date"
                    )

            # DELETE removed API keys
            for key_hash in keys_to_delete:
                existing_key = existing_keys_map[key_hash]
                existing_api_key_name = existing_key.reference_id
                if not existing_key.is_deleted:
                    logger.info(f"Marking api key {existing_api_key_name} as deleted")
                    existing_key.is_deleted = True
                    # Remove from secret manager for true reconciliation
                    try:
                        secret_manager.delete_secret(
                            secret_name=f"{tenant_id}-{existing_api_key_name}",
                        )
                        logger.info(
                            f"Deleted secret for api key {existing_api_key_name}"
                        )
                    except Exception as e:
                        # Check if it's a 404 error (secret doesn't exist) - this is acceptable
                        error_msg = str(e).lower()
                        if "404" in error_msg or "not found" in error_msg:
                            logger.info(
                                f"Secret for api key {existing_api_key_name} already doesn't exist - this is fine"
                            )
                        else:
                            logger.exception(
                                f"Failed to delete secret for api key {existing_api_key_name}"
                            )

            session.commit()

            if not api_keys:
                logger.info(
                    "No API keys to provision - cleaned up existing system keys"
                )
            else:
                logger.info(f"Successfully provisioned {len(api_keys)} API keys")

    except Exception as e:
        logger.exception(f"Failed to provision API keys for tenant {tenant_id}: {e}")
        raise


def provision_api_keys_from_env(tenant_id: str) -> None:
    """
    Provision API keys from KEEP_DEFAULT_API_KEYS environment variable.

    Args:
        tenant_id (str): The tenant ID
    """
    env_api_keys = os.environ.get("KEEP_DEFAULT_API_KEYS", "")
    if not env_api_keys.strip():
        logger.info("No KEEP_DEFAULT_API_KEYS environment variable found")
        # Still call provision_api_keys with empty dict to handle deletion of existing keys
        provision_api_keys({}, tenant_id)
        return

    # First, validate ALL entries before making any changes (atomic validation)
    api_keys_list = []
    for api_key_str in env_api_keys.split(","):
        api_key_str = api_key_str.strip()
        if not api_key_str:  # Skip empty entries
            continue

        parts = api_key_str.split(":")
        if len(parts) != 3:
            logger.error(
                "Invalid format for KEEP_DEFAULT_API_KEYS entry. Expected format: name:role:secret"
            )
            logger.error(
                "Aborting API key provisioning due to format error - no changes made"
            )
            return

        api_key_name, api_key_role, api_key_secret = parts

        # Validate that none of the parts are empty
        if not api_key_name or not api_key_role or not api_key_secret:
            logger.error(
                "Invalid format for KEEP_DEFAULT_API_KEYS entry - empty name, role, or secret not allowed"
            )
            logger.error(
                "Aborting API key provisioning due to format error - no changes made"
            )
            return

        api_keys_list.append((api_key_name, api_key_role, api_key_secret))

    # All entries are valid, now process them
    api_keys_dict = {}
    seen_names = set()

    for api_key_name, api_key_role, api_key_secret in api_keys_list:
        # Check for duplicate names
        if api_key_name in seen_names:
            logger.error(
                f"Duplicate API key name detected in KEEP_DEFAULT_API_KEYS - name '{api_key_name}' used multiple times"
            )
            logger.error(
                "Aborting API key provisioning due to duplicate name - no changes made"
            )
            return
        seen_names.add(api_key_name)

        # Hash the secret to use as the key
        key_hash = hashlib.sha256(api_key_secret.encode("utf-8")).hexdigest()

        # Check for duplicate key hashes (same secret used multiple times)
        if key_hash in api_keys_dict:
            logger.error(
                "Duplicate secret detected in KEEP_DEFAULT_API_KEYS - same secret used for multiple API keys"
            )
            logger.error(
                "Aborting API key provisioning due to duplicate secret - no changes made"
            )
            return

        api_keys_dict[key_hash] = {
            "name": api_key_name,
            "role": api_key_role,
            "secret": api_key_secret,
        }

    logger.info(f"Provisioning {len(api_keys_dict)} API keys from environment variable")
    provision_api_keys(api_keys_dict, tenant_id)
