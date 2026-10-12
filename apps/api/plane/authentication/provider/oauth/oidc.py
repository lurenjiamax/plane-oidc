# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only

import os
import secrets
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import jwt
from django.conf import settings
import pytz
import requests

from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)


class OIDCOAuthProvider(OauthAdapter):
    provider = "oidc"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_DISCOVERY_URL) = get_configuration_value(
            [
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_DISCOVERY_URL",
                    "default": os.environ.get("OIDC_DISCOVERY_URL"),
                },
            ]
        )

        if not (OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_DISCOVERY_URL):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        # Fetch OIDC discovery document
        try:
            response = requests.get(OIDC_DISCOVERY_URL, timeout=15)
            response.raise_for_status()
            discovery = response.json()
            for key in ("issuer", "token_endpoint", "userinfo_endpoint", "authorization_endpoint", "jwks_uri"):
                endpoint = urlparse(discovery[key])
                if endpoint.scheme != "https" or not endpoint.netloc:
                    raise ValueError("Invalid OIDC endpoint")
        except (requests.RequestException, ValueError, KeyError, TypeError):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED: Failed to fetch discovery document",
            )

        self.token_url = discovery.get("token_endpoint")
        self.userinfo_url = discovery.get("userinfo_endpoint")
        auth_endpoint = discovery.get("authorization_endpoint")
        self.issuer = discovery["issuer"]
        self.jwks_uri = discovery["jwks_uri"]
        self.signing_algorithms = [
            algorithm for algorithm in discovery.get("id_token_signing_alg_values_supported", [])
            if algorithm in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
        ]
        self.nonce = request.session.get("oidc_nonce")
        if code is None:
            self.nonce = secrets.token_urlsafe(32)
            request.session["oidc_nonce"] = self.nonce

        callback_path = "/auth/spaces/oidc/callback/" if request.path.startswith("/auth/spaces/") else "/auth/oidc/callback/"
        redirect_uri = f"{settings.WEB_URL.rstrip('/')}{callback_path}"
        url_params = {
            "client_id": OIDC_CLIENT_ID,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "nonce": self.nonce,
        }
        auth_url = f"{auth_endpoint}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            OIDC_CLIENT_ID,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            OIDC_CLIENT_SECRET,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {"Accept": "application/json"}
        token_response = self.get_user_token(data=data, headers=headers)
        try:
            if not token_response.get("access_token") or not self.nonce or not self.signing_algorithms:
                raise ValueError("Incomplete OIDC token response")
            id_token = token_response["id_token"]
            key = jwt.PyJWKClient(
                self.jwks_uri, timeout=15, headers={"User-Agent": "Plane-OIDC/1.3.1"}
            ).get_signing_key_from_jwt(id_token)
            self.id_claims = jwt.decode(
                id_token, key.key, algorithms=self.signing_algorithms,
                audience=self.client_id, issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            if self.id_claims.get("nonce") != self.nonce:
                raise ValueError("OIDC nonce mismatch")
            if self.id_claims.get("azp", self.client_id) != self.client_id:
                raise ValueError("OIDC authorized party mismatch")
        except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
            self.logger.warning("OIDC ID token validation failed: %s", type(exc).__name__)
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR: Invalid ID token",
            )
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": None,
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        email = user_info_response.get("email")
        if not email or user_info_response.get("sub") != self.id_claims["sub"] or user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED: Invalid userinfo identity or email",
            )

        first_name = user_info_response.get("given_name", "")
        last_name = user_info_response.get("family_name", "")
        if not first_name:
            name = user_info_response.get("name", "")
            parts = name.split(" ", 1)
            first_name = parts[0] if parts else ""
            last_name = parts[1] if len(parts) > 1 else ""

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": user_info_response.get("sub"),
                    "email": email,
                    "avatar": user_info_response.get("picture", ""),
                    "first_name": first_name,
                    "last_name": last_name,
                    "is_password_autoset": True,
                },
            }
        )

    def authentication_error_code(self) -> str:
        return "OIDC_OAUTH_PROVIDER_ERROR"

    def get_user_token(self, data: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            response = requests.post(self.token_url, data=data, headers=headers, timeout=15)
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("Invalid token response")
            return result
        except (requests.RequestException, ValueError):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR: Token exchange failed",
            )

    def get_user_response(self) -> dict[str, Any]:
        try:
            response = requests.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {self.token_data['access_token']}"},
                timeout=15,
            )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("Invalid userinfo response")
            return result
        except (requests.RequestException, ValueError):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR: Userinfo request failed",
            )
