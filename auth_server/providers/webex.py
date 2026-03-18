"""Webex (Cisco) OAuth2 authentication provider implementation.

Validates Webex access tokens by calling the Webex People API (/v1/people/me).
Webex tokens are opaque (not JWT), so validation is done via API introspection.

Groups are derived from the Webex orgId: each unique orgId maps to a configurable
set of groups via the WEBEX_ORG_GROUP_MAPPINGS environment variable.
"""

import json
import logging
import os
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import requests

from .base import AuthProvider


class _BearerAuth(httpx.Auth):
    """httpx Auth that re-attaches the Bearer token on every request in a redirect chain."""

    def __init__(self, token: str):
        self.token = token

    def auth_flow(self, request: httpx.Request):
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request

# Constants for self-signed token validation (shared with other providers)
JWT_ISSUER = os.environ.get("JWT_ISSUER", "mcp-auth-server")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "mcp-registry")
SECRET_KEY = os.environ.get("SECRET_KEY", "development-secret-key")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)

logger = logging.getLogger(__name__)


class WebexProvider(AuthProvider):
    """Webex (Cisco) OAuth2 authentication provider.

    Webex tokens are opaque — validation is done by calling /v1/people/me.
    Groups are derived from the user's orgId using a configurable mapping.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        webex_api_base_url: str = "https://webexapis.com",
        webex_auth_base_url: str | None = None,
        webex_logout_url: str = "https://idbroker.webex.com/idb/oauth2/v1/logout",
        webex_token_url: str | None = None,
        org_group_mappings: dict[str, list[str]] | None = None,
        default_groups: list[str] | None = None,
        scopes: str = "spark:people_read",
    ):
        """Initialize Webex provider.

        Args:
            client_id: Webex OAuth2 Integration client ID
            client_secret: Webex OAuth2 Integration client secret
            webex_api_base_url: Base URL for Webex APIs (prod or integration)
            webex_auth_base_url: Base URL for auth endpoints (defaults to webex_api_base_url)
            webex_logout_url: IdP logout endpoint
            webex_token_url: Full token endpoint URL (overrides auto-derived URL from api_base_url)
            org_group_mappings: Dict mapping orgId -> list of group names
            default_groups: Default groups for users whose orgId is not in mappings
            scopes: Space-separated OAuth scopes to request (must match Webex integration registration)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.webex_api_base_url = webex_api_base_url.rstrip("/")
        self.webex_auth_base_url = (webex_auth_base_url or webex_api_base_url).rstrip("/")
        self.webex_logout_url = webex_logout_url

        # Endpoints
        self.auth_url = f"{self.webex_auth_base_url}/v1/authorize"
        self.token_url = webex_token_url or f"{self.webex_api_base_url}/v1/access_token"
        self.userinfo_url = f"{self.webex_api_base_url}/v1/people/me"
        self.logout_endpoint = webex_logout_url

        # OAuth scopes (must match what's registered on the Webex integration)
        self.scopes = scopes

        # orgId → groups mapping (Option A)
        self.org_group_mappings = org_group_mappings or {}
        self.default_groups = default_groups or []

        # Cache for user info to avoid repeated API calls within short windows
        self._user_cache: dict[str, tuple[dict, float]] = {}
        self._cache_ttl = 300  # 5 minutes

        logger.info(
            f"Initialized Webex provider with API base: {self.webex_api_base_url}, "
            f"auth base: {self.webex_auth_base_url}, "
            f"{len(self.org_group_mappings)} org->group mappings, "
            f"default groups: {self.default_groups}"
        )

    def validate_token(self, token: str, **kwargs: Any) -> dict[str, Any]:
        """Validate a Webex access token by calling /v1/people/me.

        Webex tokens are opaque, so we validate by making an API call.
        If the token is valid, Webex returns the user's profile.
        If invalid/expired, Webex returns 401.

        Also checks if the token is a self-signed JWT from our auth server.
        """
        try:
            # First check if this is a self-signed token from our auth server
            try:
                import jwt

                unverified_claims = jwt.decode(token, options={"verify_signature": False})
                if unverified_claims.get("iss") == JWT_ISSUER:
                    logger.debug("Token appears to be self-signed, validating...")
                    return self._validate_self_signed_token(token)
            except Exception:
                # Not a JWT at all (Webex tokens are opaque) — continue to Webex validation
                pass

            logger.debug("Validating Webex access token via /v1/people/me")

            # Call Webex People API to validate token and get user identity
            user_info = self._call_people_me(token)

            # Extract identity
            email = user_info.get("emails", [None])[0] if user_info.get("emails") else None
            username = email or user_info.get("displayName") or user_info.get("id")
            org_id = user_info.get("orgId", "")

            # Map orgId to groups
            groups = self._resolve_groups(org_id)

            logger.info(
                f"Webex token validated for user: {username}, orgId: {org_id}, groups: {groups}"
            )

            return {
                "valid": True,
                "username": username,
                "email": email,
                "groups": groups,
                "scopes": [],  # Scopes are derived from groups, not from Webex token
                "client_id": self.client_id,
                "method": "webex",
                "data": {
                    "id": user_info.get("id"),
                    "displayName": user_info.get("displayName"),
                    "emails": user_info.get("emails", []),
                    "orgId": org_id,
                    "avatar": user_info.get("avatar"),
                    "type": user_info.get("type"),
                },
            }

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.warning("Webex token validation failed: Token expired or invalid")
                raise ValueError("Webex token expired or invalid")
            logger.error(f"Webex API error during token validation: {e}")
            raise ValueError(f"Webex token validation failed: {e}")
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Webex token validation error: {e}")
            raise ValueError(f"Token validation failed: {e}")

    def _call_people_me(self, access_token: str) -> dict[str, Any]:
        """Call Webex /v1/people/me to get the authenticated user's profile.

        Uses a short-lived cache to avoid hammering the Webex API on rapid
        successive requests with the same token.
        """
        # Check cache (keyed on first 16 chars of token to avoid storing full token)
        cache_key = access_token[:16] if len(access_token) > 16 else access_token
        now = time.time()
        if cache_key in self._user_cache:
            cached_data, cached_time = self._user_cache[cache_key]
            if now - cached_time < self._cache_ttl:
                logger.debug("Using cached Webex user info")
                return cached_data

        # integration.webexapis.com 302-redirects to an internal API gateway
        # on a different host.  Both Python requests and httpx strip the
        # Authorization header on cross-domain redirects by default.
        # We disable auto-redirects and follow manually, re-attaching the
        # Bearer token on every hop — matching Node.js fetch behaviour
        # (used by camls-playground).
        auth_headers = {"Authorization": f"Bearer {access_token}"}
        url = self.userinfo_url
        with httpx.Client(timeout=10.0) as client:
            for _ in range(5):  # max redirects
                response = client.get(url, headers=auth_headers, follow_redirects=False)
                if response.status_code in (301, 302, 303, 307, 308):
                    redirect_url = response.headers.get("location", "")
                    logger.debug(f"Following Webex API redirect to: {redirect_url}")
                    url = redirect_url
                    continue
                break
        response.raise_for_status()
        user_data = response.json()

        # Cache the result
        self._user_cache[cache_key] = (user_data, now)

        # Evict stale cache entries
        stale_keys = [k for k, (_, t) in self._user_cache.items() if now - t > self._cache_ttl]
        for k in stale_keys:
            del self._user_cache[k]

        return user_data

    def _resolve_groups(self, org_id: str) -> list[str]:
        """Resolve Webex orgId to gateway groups.

        Uses org_group_mappings dict. Falls back to default_groups if orgId not mapped.
        A wildcard key '*' matches any orgId.
        """
        if org_id and org_id in self.org_group_mappings:
            return self.org_group_mappings[org_id]

        # Check wildcard mapping
        if "*" in self.org_group_mappings:
            return self.org_group_mappings["*"]

        return list(self.default_groups)

    def _validate_self_signed_token(self, token: str) -> dict[str, Any]:
        """Validate a self-signed JWT token generated by our auth server."""
        import jwt

        try:
            claims = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={"verify_exp": True, "verify_iat": True, "verify_aud": True},
            )

            token_use = claims.get("token_use")
            if token_use != "access":  # nosec B105
                raise ValueError(f"Invalid token_use: {token_use}")

            scopes = []
            if "scope" in claims:
                scope_value = claims["scope"]
                if isinstance(scope_value, str):
                    scopes = scope_value.split() if scope_value else []
                elif isinstance(scope_value, list):
                    scopes = scope_value

            groups = claims.get("groups", [])
            if isinstance(groups, str):
                groups = [groups]

            logger.info(
                f"Successfully validated self-signed token for user: {claims.get('sub')}, "
                f"groups: {groups}, scopes: {scopes}"
            )

            return {
                "valid": True,
                "method": "self_signed",
                "data": claims,
                "client_id": claims.get("client_id", "user-generated"),
                "username": claims.get("sub", ""),
                "email": claims.get("email", ""),
                "expires_at": claims.get("exp"),
                "scopes": scopes,
                "groups": groups,
                "token_type": "user_generated",
            }

        except Exception as e:
            logger.error(f"Self-signed token validation error: {e}")
            raise ValueError(f"Self-signed token validation failed: {e}")

    def get_jwks(self) -> dict[str, Any]:
        """Webex tokens are opaque — no JWKS available.

        Returns an empty key set. Token validation is done via API call.
        """
        logger.debug("Webex tokens are opaque — JWKS not applicable")
        return {"keys": []}

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange authorization code for Webex access token."""
        try:
            logger.debug("Exchanging Webex authorization code for token")

            data = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            response = requests.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            response.raise_for_status()

            token_data = response.json()
            logger.debug("Webex token exchange successful")

            return token_data

        except requests.RequestException as e:
            logger.error(f"Failed to exchange Webex code for token: {e}")
            raise ValueError(f"Webex token exchange failed: {e}")

    def get_user_info(self, access_token: str) -> dict[str, Any]:
        """Get user information from Webex /v1/people/me."""
        try:
            user_data = self._call_people_me(access_token)

            # Map to standard format
            email = user_data.get("emails", [None])[0] if user_data.get("emails") else None
            org_id = user_data.get("orgId", "")
            groups = self._resolve_groups(org_id)

            return {
                "username": email or user_data.get("displayName"),
                "email": email,
                "name": user_data.get("displayName"),
                "groups": groups,
                "orgId": org_id,
                "avatar": user_data.get("avatar"),
            }

        except requests.RequestException as e:
            logger.error(f"Failed to get Webex user info: {e}")
            raise ValueError(f"User info retrieval failed: {e}")

    def get_auth_url(self, redirect_uri: str, state: str, scope: str | None = None) -> str:
        """Get Webex authorization URL."""
        logger.debug(f"Generating Webex auth URL with redirect_uri: {redirect_uri}")

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope or "spark:people_read",
            "state": state,
        }

        auth_url = f"{self.auth_url}?{urlencode(params)}"
        logger.debug(f"Generated Webex auth URL: {auth_url}")

        return auth_url

    def get_logout_url(self, redirect_uri: str) -> str:
        """Get Webex/IDB logout URL."""
        logger.debug(f"Generating Webex logout URL with redirect_uri: {redirect_uri}")

        params = {"goto": redirect_uri}
        logout_url = f"{self.logout_endpoint}?{urlencode(params)}"
        logger.debug(f"Generated Webex logout URL: {logout_url}")

        return logout_url

    def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh a Webex access token using a refresh token."""
        try:
            logger.debug("Refreshing Webex access token")

            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": refresh_token,
            }

            response = requests.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            response.raise_for_status()

            token_data = response.json()
            logger.debug("Webex token refresh successful")

            return token_data

        except requests.RequestException as e:
            logger.error(f"Failed to refresh Webex token: {e}")
            raise ValueError(f"Webex token refresh failed: {e}")

    def validate_m2m_token(self, token: str) -> dict[str, Any]:
        """Validate a machine-to-machine token.

        Webex doesn't natively support M2M client credentials.
        Falls back to self-signed token validation or standard Webex validation.
        """
        return self.validate_token(token)

    def get_m2m_token(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Webex does not support client_credentials grant.

        M2M access should use self-signed tokens generated by this auth server.
        """
        raise ValueError(
            "Webex does not support client_credentials grant. "
            "Use the /internal/tokens endpoint to generate self-signed JWT tokens for M2M access."
        )

    def get_provider_info(self) -> dict[str, Any]:
        """Get provider-specific information."""
        return {
            "provider_type": "webex",
            "webex_api_base_url": self.webex_api_base_url,
            "client_id": self.client_id,
            "endpoints": {
                "auth": self.auth_url,
                "token": self.token_url,
                "userinfo": self.userinfo_url,
                "logout": self.logout_endpoint,
            },
            "scopes": self.scopes,
            "org_group_mappings_count": len(self.org_group_mappings),
            "default_groups": self.default_groups,
            "healthy": self._check_webex_health(),
        }

    def _check_webex_health(self) -> bool:
        """Check if Webex API is reachable."""
        try:
            # Simple connectivity check — don't send auth, just see if endpoint responds
            response = requests.get(
                f"{self.webex_api_base_url}/v1/people/me",
                headers={"Authorization": "Bearer invalid"},
                timeout=5,
            )
            # 401 means the API is reachable (just unauthorized)
            return response.status_code in (200, 401)
        except Exception:
            return False
