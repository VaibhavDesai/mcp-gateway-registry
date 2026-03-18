"""Factory for creating authentication provider instances."""

import logging
import os

from .base import AuthProvider
from .cognito import CognitoProvider
from .entra import EntraIdProvider
from .keycloak import KeycloakProvider
from .webex import WebexProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)

logger = logging.getLogger(__name__)


def get_auth_provider(provider_type: str | None = None) -> AuthProvider:
    """Factory function to get the appropriate auth provider.

    Args:
        provider_type: Type of provider to create ('cognito', 'keycloak', or 'entra').
                      If None, uses AUTH_PROVIDER environment variable.

    Returns:
        AuthProvider instance configured for the specified provider

    Raises:
        ValueError: If provider type is unknown or required config is missing
    """
    provider_type = provider_type or os.environ.get("AUTH_PROVIDER", "cognito")

    logger.info(f"Creating authentication provider: {provider_type}")

    if provider_type == "keycloak":
        return _create_keycloak_provider()
    elif provider_type == "cognito":
        return _create_cognito_provider()
    elif provider_type == "entra":
        return _create_entra_provider()
    elif provider_type == "webex":
        return _create_webex_provider()
    else:
        raise ValueError(f"Unknown auth provider: {provider_type}")


def _create_keycloak_provider() -> KeycloakProvider:
    """Create and configure Keycloak provider."""
    # Required configuration
    keycloak_url = os.environ.get("KEYCLOAK_URL")
    keycloak_external_url = os.environ.get("KEYCLOAK_EXTERNAL_URL", keycloak_url)
    realm = os.environ.get("KEYCLOAK_REALM", "mcp-gateway")
    client_id = os.environ.get("KEYCLOAK_CLIENT_ID")
    client_secret = os.environ.get("KEYCLOAK_CLIENT_SECRET")

    # Optional M2M configuration
    m2m_client_id = os.environ.get("KEYCLOAK_M2M_CLIENT_ID")
    m2m_client_secret = os.environ.get("KEYCLOAK_M2M_CLIENT_SECRET")

    # Validate required configuration
    missing_vars = []
    if not keycloak_url:
        missing_vars.append("KEYCLOAK_URL")
    if not client_id:
        missing_vars.append("KEYCLOAK_CLIENT_ID")
    if not client_secret:
        missing_vars.append("KEYCLOAK_CLIENT_SECRET")

    if missing_vars:
        raise ValueError(
            f"Missing required Keycloak configuration: {', '.join(missing_vars)}. "
            "Please set these environment variables."
        )

    logger.info(
        f"Initializing Keycloak provider for realm '{realm}' at {keycloak_url} (external: {keycloak_external_url})"
    )

    return KeycloakProvider(
        keycloak_url=keycloak_url,
        keycloak_external_url=keycloak_external_url,
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
        m2m_client_id=m2m_client_id,
        m2m_client_secret=m2m_client_secret,
    )


def _create_cognito_provider() -> CognitoProvider:
    """Create and configure Cognito provider."""
    # Required configuration
    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID")
    client_id = os.environ.get("COGNITO_CLIENT_ID")
    client_secret = os.environ.get("COGNITO_CLIENT_SECRET")
    region = os.environ.get("AWS_REGION", "us-east-1")

    # Optional configuration
    domain = os.environ.get("COGNITO_DOMAIN")

    # Validate required configuration
    missing_vars = []
    if not user_pool_id:
        missing_vars.append("COGNITO_USER_POOL_ID")
    if not client_id:
        missing_vars.append("COGNITO_CLIENT_ID")
    if not client_secret:
        missing_vars.append("COGNITO_CLIENT_SECRET")

    if missing_vars:
        raise ValueError(
            f"Missing required Cognito configuration: {', '.join(missing_vars)}. "
            "Please set these environment variables."
        )

    logger.info(
        f"Initializing Cognito provider for user pool '{user_pool_id}' in region '{region}'"
    )

    return CognitoProvider(
        user_pool_id=user_pool_id,
        client_id=client_id,
        client_secret=client_secret,
        region=region,
        domain=domain,
    )


def _create_entra_provider() -> EntraIdProvider:
    """Create and configure Entra ID provider."""
    # Required configuration
    tenant_id = os.environ.get("ENTRA_TENANT_ID")
    client_id = os.environ.get("ENTRA_CLIENT_ID")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET")

    # Validate required configuration
    missing_vars = []
    if not tenant_id:
        missing_vars.append("ENTRA_TENANT_ID")
    if not client_id:
        missing_vars.append("ENTRA_CLIENT_ID")
    if not client_secret:
        missing_vars.append("ENTRA_CLIENT_SECRET")

    if missing_vars:
        raise ValueError(
            f"Missing required Entra ID configuration: {', '.join(missing_vars)}. "
            "Please set these environment variables."
        )

    logger.info(f"Initializing Entra ID provider for tenant '{tenant_id}'")

    return EntraIdProvider(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)


def _create_webex_provider() -> WebexProvider:
    """Create and configure Webex provider."""
    import json

    # Required configuration
    client_id = os.environ.get("WEBEX_CLIENT_ID")
    client_secret = os.environ.get("WEBEX_CLIENT_SECRET")

    # Optional configuration
    webex_api_base_url = os.environ.get("WEBEX_API_BASE_URL", "https://webexapis.com")
    webex_auth_base_url = os.environ.get("WEBEX_AUTH_BASE_URL", webex_api_base_url)
    webex_logout_url = os.environ.get(
        "WEBEX_LOGOUT_URL", "https://idbroker.webex.com/idb/oauth2/v1/logout"
    )

    # Validate required configuration
    missing_vars = []
    if not client_id:
        missing_vars.append("WEBEX_CLIENT_ID")
    if not client_secret:
        missing_vars.append("WEBEX_CLIENT_SECRET")

    if missing_vars:
        raise ValueError(
            f"Missing required Webex configuration: {', '.join(missing_vars)}. "
            "Please set these environment variables."
        )

    # Parse orgId -> groups mapping from JSON env var
    # Format: {"orgId1": ["group1", "group2"], "orgId2": ["group3"], "*": ["default-group"]}
    org_group_mappings = {}
    org_mappings_json = os.environ.get("WEBEX_ORG_GROUP_MAPPINGS", "")
    if org_mappings_json:
        try:
            org_group_mappings = json.loads(org_mappings_json)
            logger.info(f"Loaded {len(org_group_mappings)} Webex org->group mappings")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse WEBEX_ORG_GROUP_MAPPINGS: {e}")

    # Default groups for users whose orgId is not in the mapping
    default_groups_str = os.environ.get("WEBEX_DEFAULT_GROUPS", "")
    default_groups = [g.strip() for g in default_groups_str.split(",") if g.strip()]

    # OAuth scopes to request (must match what's registered on the Webex integration)
    scopes = os.environ.get("WEBEX_SCOPES", "spark:people_read")

    # Token URL override (BTS uses idbrokerbts.webex.com, prod uses webexapis.com)
    webex_token_url = os.environ.get("WEBEX_TOKEN_URL", "")

    logger.info(
        f"Initializing Webex provider with API base: {webex_api_base_url}, "
        f"auth base: {webex_auth_base_url}, scopes: {scopes}"
        + (f", token_url: {webex_token_url}" if webex_token_url else "")
    )

    return WebexProvider(
        client_id=client_id,
        client_secret=client_secret,
        webex_api_base_url=webex_api_base_url,
        webex_auth_base_url=webex_auth_base_url,
        webex_logout_url=webex_logout_url,
        webex_token_url=webex_token_url or None,
        org_group_mappings=org_group_mappings,
        default_groups=default_groups,
        scopes=scopes,
    )


def _get_provider_health_info() -> dict:
    """Get health information for the current provider."""
    try:
        provider = get_auth_provider()
        if hasattr(provider, "get_provider_info"):
            return provider.get_provider_info()
        else:
            return {
                "provider_type": os.environ.get("AUTH_PROVIDER", "cognito"),
                "status": "unknown",
            }
    except Exception as e:
        logger.error(f"Failed to get provider health info: {e}")
        return {
            "provider_type": os.environ.get("AUTH_PROVIDER", "cognito"),
            "status": "error",
            "error": str(e),
        }
