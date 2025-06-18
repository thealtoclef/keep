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
        api_keys (dict): Dictionary of API key configurations {name: {role: str, secret: str}}
        tenant_id (str): The tenant ID
    """
    if not api_keys:
        logger.info("No API keys to provision")
        return

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
            api_key.reference_id: api_key for api_key in existing_api_keys
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
        for api_key_name in keys_to_create:
            api_key_config = api_keys[api_key_name]
            logger.info(f"Provisioning api key {api_key_name}")
            hashed_api_key = hashlib.sha256(
                api_key_config["secret"].encode("utf-8")
            ).hexdigest()
            new_installation_api_key = TenantApiKey(
                tenant_id=tenant_id,
                reference_id=api_key_name,
                key_hash=hashed_api_key,
                is_system=True,
                created_by="system",
                role=api_key_config["role"],
            )
            session.add(new_installation_api_key)
            # write to the secret manager
            try:
                secret_manager.write_secret(
                    secret_name=f"{tenant_id}-{api_key_name}",
                    secret_value=api_key_config["secret"],
                )
            except Exception:
                logger.exception(f"Failed to write secret for api key {api_key_name}")
            logger.info(f"Api key {api_key_name} provisioned")

        # UPDATE existing API keys
        for api_key_name in keys_to_update:
            api_key_config = api_keys[api_key_name]
            existing_key = existing_keys_map[api_key_name]
            hashed_new_secret = hashlib.sha256(
                api_key_config["secret"].encode("utf-8")
            ).hexdigest()

            needs_update = (
                existing_key.role != api_key_config["role"]
                or existing_key.key_hash != hashed_new_secret
                or existing_key.is_deleted
            )
            if needs_update:
                logger.info(f"Updating api key {api_key_name}")
                existing_key.role = api_key_config["role"]
                existing_key.key_hash = hashed_new_secret
                existing_key.is_deleted = False
                # write to the secret manager
                try:
                    secret_manager.write_secret(
                        secret_name=f"{tenant_id}-{api_key_name}",
                        secret_value=api_key_config["secret"],
                    )
                except Exception:
                    logger.exception(
                        f"Failed to write secret for api key {api_key_name}"
                    )
                logger.info(f"Api key {api_key_name} updated")
            else:
                logger.info(f"Api key {api_key_name} already exists and is up to date")

        # DELETE removed API keys
        for api_key_name in keys_to_delete:
            existing_key = existing_keys_map[api_key_name]
            if not existing_key.is_deleted:
                logger.info(f"Marking api key {api_key_name} as deleted")
                existing_key.is_deleted = True
                # Remove from secret manager for true reconciliation
                try:
                    secret_manager.delete_secret(
                        secret_name=f"{tenant_id}-{api_key_name}",
                    )
                    logger.info(f"Deleted secret for api key {api_key_name}")
                except Exception:
                    logger.exception(
                        f"Failed to delete secret for api key {api_key_name}"
                    )

        session.commit()


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

    # Parse API keys from environment variable
    api_keys_dict = {}
    for api_key_str in env_api_keys.split(","):
        try:
            api_key_name, api_key_role, api_key_secret = api_key_str.strip().split(":")
            api_keys_dict[api_key_name] = {
                "role": api_key_role,
                "secret": api_key_secret,
            }
        except ValueError:
            logger.error(
                f"Invalid format for API key: {api_key_str}. Expected format: name:role:secret"
            )
            continue

    logger.info(f"Provisioning {len(api_keys_dict)} API keys from environment variable")
    provision_api_keys(api_keys_dict, tenant_id)
