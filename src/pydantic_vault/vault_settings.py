from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import cast

from hvac import Client as HvacClient
from pydantic import SecretStr, TypeAdapter, ValidationError
from pydantic_settings import BaseSettings
from pydantic_settings.sources import EnvSettingsSource
from pydantic_settings.sources.utils import parse_env_vars

from pydantic_vault.entities import (Approle, AuthMethodParameters,
                                     HvacClientParameters, Kubernetes,
                                     SettingsConfigDict, VaultJwt)

logger = logging.getLogger("pydantic-vault")
logger.addHandler(logging.NullHandler())


class PydanticVaultException(BaseException): ...


class VaultParameterError(PydanticVaultException, ValueError): ...


def _format_vault_client_auth_log(
    vault_url: str,
    vault_auth_method: str,
    vault_namespace: str | None = None,
    additional_parameters: dict[str, str] | None = None,
) -> str:
    message = f"Connecting to Vault '{vault_url}'"

    if vault_namespace is not None:
        message += f" on namespace '{vault_namespace}'"

    message += f" with method '{vault_auth_method}'"

    if additional_parameters is not None:
        message += f" ({additional_parameters})"

    return message


def _get_authenticated_vault_client(config: SettingsConfigDict) -> HvacClient | None:  # noqa: C901
    hvac_parameters: HvacClientParameters = {}

    # URL
    _vault_url = config.get("vault_url")
    if _vault_url is not None:
        logger.debug(f"Found Vault Address '{_vault_url}' in model_config")
    if "VAULT_ADDR" in os.environ:
        _vault_url = os.environ["VAULT_ADDR"]
        logger.debug(f"Found Vault Address '{_vault_url}' in environment variables")
    if _vault_url is None:
        raise VaultParameterError("No URL provided to connect to Vault")

    # Namespace
    _vault_namespace = config.get("vault_namespace")
    if _vault_namespace is not None:
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(f"Found Vault Namespace '{_vault_namespace}' in model_config")
    if "VAULT_NAMESPACE" in os.environ:
        _vault_namespace = os.environ["VAULT_NAMESPACE"]
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(f"Found Vault Namespace '{_vault_namespace}' in environment variables")

    # Certificate verification
    _vault_certificate_verify = config.get("vault_certificate_verify")
    if _vault_certificate_verify is not None:
        logger.debug(f"Found Vault CA bundle '{_vault_certificate_verify}' in model_config")
    if "VAULT_CA_BUNDLE" in os.environ:
        try:
            _vault_certificate_verify = TypeAdapter(bool).validate_python(
                os.environ["VAULT_CA_BUNDLE"]
            )
        except ValidationError:
            _vault_certificate_verify = os.environ["VAULT_CA_BUNDLE"]
        logger.debug(
            f"Found Vault CA bundle '{_vault_certificate_verify}' in environment variables"
        )
    if _vault_certificate_verify is not None:
        hvac_parameters.update({"verify": _vault_certificate_verify})

    # Auth method parameters
    _vault_auth_method_parameters: AuthMethodParameters = {}
    _vault_auth_mount_point = config.get("vault_auth_mount_point")
    if _vault_auth_mount_point is not None:
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(f"Found Vault Auth mount point '{_vault_auth_mount_point}' in model_config")
    if "VAULT_AUTH_MOUNT_POINT" in os.environ:
        _vault_auth_mount_point = os.environ["VAULT_AUTH_MOUNT_POINT"]
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(
            f"Found Vault Auth mount point '{_vault_auth_mount_point}' in environment variables"
        )

    _vault_auth_path = config.get("vault_auth_path")
    if _vault_auth_path is not None:
        _vault_auth_method_parameters["path"] = _vault_auth_path
        logger.debug(f"Found Vault Auth path '{_vault_auth_path}' in model_config")
    if "VAULT_AUTH_PATH" in os.environ:
        _vault_auth_path = os.environ["VAULT_AUTH_PATH"]
        _vault_auth_method_parameters["path"] = _vault_auth_path
        logger.debug(f"Found Vault Auth path '{_vault_auth_path}' in environment variables")

    _vault_token = _extract_vault_token(config)
    if _vault_token is not None:
        hvac_parameters.update({"token": _vault_token.get_secret_value()})
        hvac_client = HvacClient(_vault_url, **hvac_parameters)
        logger.info(_format_vault_client_auth_log(_vault_url, "Vault Token", _vault_namespace))
        return hvac_client

    hvac_client = HvacClient(_vault_url, **hvac_parameters)

    _vault_kubernetes = _extract_kubernetes(config)
    if _vault_kubernetes is not None:
        hvac_client.auth.kubernetes.login(
            _vault_kubernetes.role,
            _vault_kubernetes.jwt_token.get_secret_value(),
            mount_point=_vault_auth_method_parameters.get("mount_point", "kubernetes"),
        )
        logger.info(
            _format_vault_client_auth_log(
                _vault_url,
                "Kubernetes",
                _vault_namespace,
                {"kubernetes_role": _vault_kubernetes.role},
            )
        )
        return hvac_client

    _vault_approle = _extract_approle(config)
    if _vault_approle is not None:
        hvac_client.auth.approle.login(
            role_id=_vault_approle.role_id,
            secret_id=_vault_approle.secret_id.get_secret_value(),
            mount_point=_vault_auth_method_parameters.get("mount_point", "approle"),
        )
        logger.info(
            _format_vault_client_auth_log(
                _vault_url,
                "Approle",
                _vault_namespace,
                {"role_id": _vault_approle.role_id},
            )
        )
        return hvac_client

    _vault_jwt = _extract_jwt_token(config)
    if _vault_jwt is not None:
        hvac_client.auth.jwt.jwt_login(
            _vault_jwt.role,
            _vault_jwt.token.get_secret_value(),
            path=_vault_auth_method_parameters.get("path"),
        )
        logger.info(
            _format_vault_client_auth_log(
                _vault_url,
                "JWT",
                _vault_namespace,
                {"role": _vault_jwt.role},
            )
        )
        return hvac_client

    # We couldn't find suitable information to authenticate against Vault
    return None


def _extract_approle(config: SettingsConfigDict) -> Approle | None:
    """Extract Approle information from environment or from BaseSettings.model_config"""
    # Load from BaseSettings.model_config
    _vault_role_id = config.get("vault_role_id")
    if _vault_role_id is not None:
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in model_config")

    _vault_secret_id = config.get("vault_secret_id")
    if config.get("vault_secret_id") is not None:
        logger.debug("Found Vault Secret ID in model_config")

    # Load (and eventually override) from environment
    if "VAULT_ROLE_ID" in os.environ:
        _vault_role_id = os.environ["VAULT_ROLE_ID"]
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in environment variables")
    if "VAULT_SECRET_ID" in os.environ:
        _vault_secret_id = os.environ["VAULT_SECRET_ID"]
        logger.debug("Found Vault Secret ID in environment variables")

    if _vault_role_id is not None and _vault_secret_id is not None:
        return Approle(
            role_id=_vault_role_id,
            secret_id=_vault_secret_id
            if isinstance(_vault_secret_id, SecretStr)
            else SecretStr(_vault_secret_id),
        )

    return None


def _extract_vault_token(config: SettingsConfigDict) -> SecretStr | None:
    """Extract Vault token from environment, from .vault-token file or from BaseSettings.model_config"""
    _vault_token: str | SecretStr | None = None
    if "VAULT_TOKEN" in os.environ:
        _vault_token = SecretStr(os.environ["VAULT_TOKEN"])
        logger.debug("Found Vault Token in environment variables")
        return _vault_token

    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = SecretStr(token_file.read().strip())
            logger.debug("Found Vault Token in file '~/.vault-token'")
            return _vault_token

    _vault_token = config.get("vault_token")
    if _vault_token is not None:
        if not isinstance(_vault_token, SecretStr):
            _vault_token = SecretStr(_vault_token)
        logger.debug("Found Vault Token in model_config")
        return _vault_token

    return None


def _extract_kubernetes(config: SettingsConfigDict) -> Kubernetes | None:
    """Extract Kubernetes token from default file, and role from environment or from BaseSettings.model_config"""
    _kubernetes_jwt: SecretStr
    with suppress(FileNotFoundError):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
            _kubernetes_jwt = SecretStr(token_file.read().strip())
            logger.debug(
                "Found Kubernetes JWT Token in file '/var/run/secrets/kubernetes.io/serviceaccount/token'"
            )

        # Kubernetes role
        kubernetes_role = config.get("vault_kubernetes_role")
        if kubernetes_role is not None:
            logger.debug(f"Found Kubernetes role '{kubernetes_role}' in model_config")
        if "VAULT_KUBERNETES_ROLE" in os.environ:
            kubernetes_role = os.environ["VAULT_KUBERNETES_ROLE"]
            logger.debug(f"Found Kubernetes role '{kubernetes_role}' in environment variables")

        if kubernetes_role is not None:
            return Kubernetes(role=kubernetes_role, jwt_token=_kubernetes_jwt)

    return None


def _extract_jwt_token(config: SettingsConfigDict) -> VaultJwt | None:
    """
    Extract jwt auth params from environment or from BaseSettings.model_config
    """
    # Load from BaseSettings.model_config
    _vault_jwt_role = config.get("vault_jwt_role")
    if _vault_jwt_role is not None:
        logger.debug(f"Found Vault JWT Role '{_vault_jwt_role}' in model_config")

    _vault_jwt_token = config.get("vault_jwt_token")
    if _vault_jwt_token is not None:
        if not isinstance(_vault_jwt_token, SecretStr):
            _vault_jwt_token = SecretStr(_vault_jwt_token)
        logger.debug("Found Vault JWT Token in model_config")

    # Load (and eventually override) from environment
    if "VAULT_JWT_ROLE" in os.environ:
        _vault_jwt_role = os.environ["VAULT_JWT_ROLE"]
        logger.debug(f"Found Vault JWT Role '{_vault_jwt_role}' in environment variables")
    if "VAULT_JWT_TOKEN" in os.environ:
        _vault_jwt_token = SecretStr(os.environ["VAULT_JWT_TOKEN"])
        logger.debug("Found Vault JWT Token in environment variables")

    vault_jwt: VaultJwt | None = None
    if _vault_jwt_role is not None and _vault_jwt_token is not None:
        vault_jwt = VaultJwt(role=_vault_jwt_role, token=_vault_jwt_token)

    return vault_jwt


class VaultSettingsSource(EnvSettingsSource):
    def __init__(
        self,
        settings_cls: type[BaseSettings],
        vault_secret_path: str | None = None,
        case_sensitive: bool | None = None,
        env_prefix: str | None = None,
        env_nested_delimiter: str | None = None,
        env_nested_max_split: int | None = None,
        env_ignore_empty: bool | None = None,
        env_parse_none_str: str | None = None,
        env_parse_enums: bool | None = None,
    ) -> None:
        self.vault_secret_path = vault_secret_path
        super().__init__(
            settings_cls,
            case_sensitive,
            env_prefix,
            env_nested_delimiter,
            env_nested_max_split,
            env_ignore_empty,
            env_parse_none_str,
            env_parse_enums,
        )

    def _load_env_vars(self) -> Mapping[str, str | None]:
        return self._read_vault_secret()
    
    def _read_vault_secret(self) -> Mapping[str, str | None]:
        model_config = cast(SettingsConfigDict, self.settings_cls.model_config)
        vault_client = _get_authenticated_vault_client(model_config)
        vault_secret_path = self.vault_secret_path or model_config.get("vault_secret_path")
        
        if not vault_client or not vault_secret_path:
            # If no vault client or secret path is provided, return an empty mapping
            return {}
        
        return self._static_read_vault_secret(
            vault_client,
            vault_secret_path=vault_secret_path,
            case_sensitive=self.case_sensitive,
            ignore_empty=self.env_ignore_empty,
            parse_none_str=self.env_parse_none_str,
        )

    @staticmethod
    def _static_read_vault_secret(
        vault_client: HvacClient,
        vault_secret_path: str | None = None,
        case_sensitive: bool = False,
        ignore_empty: bool = False,
        parse_none_str: str | None = None,
    ) -> Mapping[str, str | None]:
        vault_api_response: dict[str, str | None] = vault_client.read(vault_secret_path)
        vault_vars = vault_api_response["data"]["data"]
        return parse_env_vars(vault_vars, case_sensitive, ignore_empty, parse_none_str)
