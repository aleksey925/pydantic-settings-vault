import json.decoder
import logging
import os
import typing
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, Generic, Optional, Tuple, Type, TypeVar, Union, cast

from hvac import Client as HvacClient
from hvac.exceptions import VaultError
from pydantic import GetCoreSchemaHandler, SecretStr
from pydantic.fields import FieldInfo
from pydantic_core import CoreSchema, core_schema
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_settings.sources import SettingsError, _annotation_is_complex

from pydantic_vault.entities import (
    Approle,
    AuthMethodParameters,
    HvacClientParameters,
    Kubernetes,
)

logger = logging.getLogger("pydantic-vault")
logger.addHandler(logging.NullHandler())

T = TypeVar("T")


class PydanticVaultException(BaseException):
    ...


class VaultParameterError(PydanticVaultException, ValueError):
    ...


class _ContinueException(PydanticVaultException, Exception):
    ...


def _format_vault_client_auth_log(
    vault_url: str,
    vault_auth_method: str,
    vault_namespace: Optional[str] = None,
    additional_parameters: Optional[Dict[str, str]] = None,
) -> str:
    message = f"Connecting to Vault '{vault_url}'"

    if vault_namespace is not None:
        message += f" on namespace '{vault_namespace}'"

    message += f" with method '{vault_auth_method}'"

    if additional_parameters is not None:
        message += f" ({additional_parameters})"

    return message


def _get_authenticated_vault_client(
    settings: Type[BaseSettings],
) -> Optional[HvacClient]:
    hvac_parameters: HvacClientParameters = {}

    # URL
    _vault_url: Optional[str] = None
    if "VAULT_ADDR" in os.environ:
        _vault_url = os.environ["VAULT_ADDR"]
        logger.debug(f"Found Vault Address '{_vault_url}' in environment variables")
    if settings.model_config.get("vault_url") is not None:
        _vault_url = settings.model_config["vault_url"]  # type: ignore
        logger.debug(f"Found Vault Address '{_vault_url}' in model_config")
    if _vault_url is None:
        raise VaultParameterError("No URL provided to connect to Vault")

    # Namespace
    _vault_namespace: Optional[str] = None
    if "VAULT_NAMESPACE" in os.environ:
        _vault_namespace = os.environ["VAULT_NAMESPACE"]
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(
            f"Found Vault Namespace '{_vault_namespace}' in environment variables"
        )
    if settings.model_config.get("vault_namespace") is not None:
        _vault_namespace = cast(str, settings.model_config["vault_namespace"])  # type: ignore
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(f"Found Vault Namespace '{_vault_namespace}' in model_config")

    # Auth method parameters
    _vault_auth_method_parameters: AuthMethodParameters = {}
    if "VAULT_AUTH_MOUNT_POINT" in os.environ:
        _vault_auth_mount_point = os.environ["VAULT_AUTH_MOUNT_POINT"]
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(
            f"Found Vault Auth mount point '{_vault_auth_mount_point}' in environment variables"
        )
    if settings.model_config.get("vault_auth_mount_point") is not None:
        _vault_auth_mount_point: str = settings.model_config["vault_auth_mount_point"]  # type: ignore
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(
            f"Found Vault Auth mount point '{_vault_auth_mount_point}' in model_config"
        )

    _vault_token = _extract_vault_token(settings)
    if _vault_token is not None:
        hvac_parameters.update({"token": _vault_token.get_secret_value()})
        hvac_client = HvacClient(_vault_url, **hvac_parameters)
        logger.info(
            _format_vault_client_auth_log(_vault_url, "Vault Token", _vault_namespace)
        )
        return hvac_client

    hvac_client = HvacClient(_vault_url, **hvac_parameters)

    _vault_kubernetes = _extract_kubernetes(settings)
    if _vault_kubernetes is not None:
        hvac_client.auth.kubernetes.login(
            _vault_kubernetes.role,
            _vault_kubernetes.jwt_token.get_secret_value(),
            **_vault_auth_method_parameters,
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

    _vault_approle = _extract_approle(settings)
    if _vault_approle is not None:
        hvac_client.auth.approle.login(
            role_id=_vault_approle.role_id,
            secret_id=_vault_approle.secret_id.get_secret_value(),
            **_vault_auth_method_parameters,
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

    # We couldn't find suitable information to authenticate against Vault
    return None


def _extract_approle(settings: Type[BaseSettings]) -> Optional[Approle]:
    """Extract Approle information from environment or from BaseSettings.model_config"""
    _vault_role_id: Optional[str] = None
    _vault_secret_id: Optional[SecretStr] = None

    # Load from environment
    if "VAULT_ROLE_ID" in os.environ:
        _vault_role_id = os.environ["VAULT_ROLE_ID"]
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in environment variables")
    if "VAULT_SECRET_ID" in os.environ:
        _vault_secret_id = SecretStr(os.environ["VAULT_SECRET_ID"])
        logger.debug("Found Vault Secret ID in environment variables")

    # Load (and eventually override) from BaseSettings.model_config
    if settings.model_config.get("vault_role_id") is not None:
        _vault_role_id = settings.model_config["vault_role_id"]  # type: ignore
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in model_config")
    if settings.model_config.get("vault_secret_id") is not None:
        if isinstance(settings.model_config["vault_secret_id"], SecretStr):  # type: ignore
            _vault_secret_id = settings.model_config["vault_secret_id"]  # type: ignore
        else:
            _vault_secret_id = SecretStr(settings.model_config["vault_secret_id"])  # type: ignore
        logger.debug(f"Found Vault Secret ID in model_config")

    if _vault_role_id is not None and _vault_secret_id is not None:
        return Approle(role_id=_vault_role_id, secret_id=_vault_secret_id)

    return None


def _extract_vault_token(settings: Type[BaseSettings]) -> Optional[SecretStr]:
    """Extract Vault token from environment, from .vault-token file or from BaseSettings.model_config"""
    _vault_token: SecretStr
    if settings.model_config.get("vault_token") is not None:
        if isinstance(settings.model_config["vault_token"], SecretStr):  # type: ignore
            _vault_token = settings.model_config["vault_token"]  # type: ignore
        else:
            _vault_token = SecretStr(settings.model_config["vault_token"])  # type: ignore
        logger.debug("Found Vault Token in model_config")
        return _vault_token

    if "VAULT_TOKEN" in os.environ:
        _vault_token = SecretStr(os.environ["VAULT_TOKEN"])
        logger.debug("Found Vault Token in environment variables")
        return _vault_token

    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = SecretStr(token_file.read().strip())
            logger.debug("Found Vault Token in file '~/.vault-token'")
            return _vault_token

    return None


def _extract_kubernetes(settings: Type[BaseSettings]) -> Optional[Kubernetes]:
    """Extract Kubernetes token from default file, and role from environment or from BaseSettings.model_config"""
    _kubernetes_jwt: SecretStr
    with suppress(FileNotFoundError):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
            _kubernetes_jwt = SecretStr(token_file.read().strip())
            logger.debug(
                "Found Kubernetes JWT Token in file '/var/run/secrets/kubernetes.io/serviceaccount/token'"
            )

        # Kubernetes role
        kubernetes_role: Optional[str] = None
        if "VAULT_KUBERNETES_ROLE" in os.environ:
            kubernetes_role = os.environ["VAULT_KUBERNETES_ROLE"]
            logger.debug(
                f"Found Kubernetes role '{kubernetes_role}' in environment variables"
            )
        if settings.model_config.get("vault_kubernetes_role") is not None:
            kubernetes_role = settings.model_config["vault_kubernetes_role"]  # type: ignore
            logger.debug(f"Found Kubernetes role '{kubernetes_role}' in model_config")

        if kubernetes_role is not None:
            return Kubernetes(role=kubernetes_role, jwt_token=_kubernetes_jwt)

    return None


class VaultSettingsSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: Type[BaseSettings]) -> None:
        super().__init__(settings_cls)

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> Tuple[Any, str, bool]:
        raise NotImplemented

    def __call__(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        vault_client = _get_authenticated_vault_client(self.settings_cls)
        if vault_client is None:
            logger.warning("Could not find a suitable authentication method for Vault")
            return {}

        # Get secrets
        for field_name, field_info in self.settings_cls.model_fields.items():
            extra = self._get_field_extra(field_info)
            vault_secret_path: Optional[str] = extra.get("vault_secret_path")
            vault_secret_key: Optional[str] = extra.get("vault_secret_key")

            if vault_secret_path is None:
                logger.debug(f"Skipping field {field_name}")
                continue

            try:
                vault_val: Union[str, Dict[str, Any]] = self._get_vault_secret(
                    vault_client=vault_client,
                    vault_secret_path=vault_secret_path,
                    vault_secret_key=vault_secret_key,
                )
            except _ContinueException:
                continue

            vault_val = self._deserialize_complex_type(
                vault_val=vault_val,
                field_info=field_info,
                vault_secret_path=vault_secret_path,
                vault_secret_key=vault_secret_key,
            )
            data[field_info.alias or field_name] = vault_val

        return data

    def _get_vault_secret(
        self,
        vault_client: HvacClient,
        vault_secret_path: str,
        vault_secret_key: Optional[str],
    ) -> Union[str, Dict[str, Any]]:
        try:
            vault_api_response = vault_client.read(vault_secret_path)
            if vault_api_response is None:
                raise VaultError
            vault_api_response = vault_api_response["data"]
        except VaultError:
            logger.info(f'could not get secret "{vault_secret_path}"')
            raise _ContinueException

        if vault_secret_key is None:
            try:
                vault_val = vault_api_response["data"]
            except KeyError:
                vault_val = vault_api_response
        else:
            try:
                vault_val = vault_api_response["data"][vault_secret_key]
            except KeyError:
                try:
                    vault_val = vault_api_response[vault_secret_key]
                except KeyError:
                    logger.info(
                        f'could not get key "{vault_secret_key}" in secret "{vault_secret_path}"'
                    )
                    raise _ContinueException

        return vault_val

    def _deserialize_complex_type(
        self,
        vault_val: Union[str, Dict[str, Any]],
        field_info: FieldInfo,
        vault_secret_path: str,
        vault_secret_key: Optional[str],
    ) -> Union[str, Dict[str, Any]]:
        is_field_complex = _annotation_is_complex(
            field_info.annotation, field_info.metadata
        )
        if is_field_complex and not isinstance(vault_val, Dict):
            try:
                try:
                    vault_val = field_info.annotation.model_validate_json(vault_val)  # type: ignore
                except AttributeError:
                    try:
                        vault_val = json.loads(vault_val)  # type: ignore
                    except json.decoder.JSONDecodeError as exc:
                        raise ValueError from exc
            except ValueError as e:
                secret_full_path = vault_secret_path
                if vault_secret_key is not None:
                    secret_full_path += f":{vault_secret_key}"
                raise SettingsError(
                    f'error parsing JSON for "{secret_full_path}"'
                ) from e

        return vault_val

    def _get_field_extra(self, field_info: FieldInfo) -> Dict[str, Any]:
        extra = {}
        if isinstance(field_info.json_schema_extra, Dict):
            extra.update(field_info.json_schema_extra)
        elif callable(field_info.json_schema_extra):
            field_info.json_schema_extra(extra)
        return extra


class StoredSecret(Generic[T]):
    """
    Generic type of secrets that can be saved to disk. Should be used with DataSaver validator.

    Example:
        ```py
        from pathlib import Path
        from typing import Annotated

        from pydantic import BaseModel, AfterValidator
        from pydantic_vault import StoredSecret, DataSaver

        class Settings(BaseModel):
            google_ads_service_account: Annotated[
                StoredSecret[str],
                AfterValidator(DataSaver(Path('service-account.json'))),
            ]

        ```
    """

    def __init__(self, value: T) -> None:
        self.value: T = value
        self.path: Optional[Path] = None
        self.encoding: str = "utf-8"
        self.silent_mode: bool = False

    def get_value(self) -> T:
        return self.value

    def save_to_disk(self) -> None:
        if self.path is None:
            msg = "Cannot save secret to disk. Path is not set."
            logger.error(msg)
            if not self.silent_mode:
                raise ValueError(msg)
            return

        try:
            data = (
                json.dumps(self.value)
                if not isinstance(self.value, str)
                else self.value
            )
            self.path.write_text(data, encoding=self.encoding)
        except Exception:
            logger.error("Failed to save secret to disk: %s", self.path)
            if not self.silent_mode:
                raise

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        secret_type = next(iter(typing.get_args(source_type)))
        return core_schema.no_info_after_validator_function(cls, handler(secret_type))

    def __repr__(self) -> str:
        return f"StoredSecret({self.value!r}, path={self.path!r}, encoding={self.encoding!r})"

    def __str__(self) -> str:
        return f"StoredSecret({self.value!s}, path={self.path!s}, encoding={self.encoding!s})"


class DataSaver:
    """
    Validator that injects settings to the StoredSecret object and saves it to disk.
    """

    def __init__(
        self,
        path: Path,
        encoding: Optional[str] = None,
        silent_mode: Optional[bool] = None,
    ) -> None:
        self.path = path
        self.encoding = encoding
        self.silent_mode = silent_mode

    def __call__(self, local_secret: StoredSecret[T]) -> StoredSecret[T]:
        if not isinstance(local_secret, StoredSecret):
            raise ValueError(
                "DataSaver can be used only with object type of StoredSecret"
            )

        self._inject_settings(local_secret)
        local_secret.save_to_disk()
        return local_secret

    def _inject_settings(self, local_secret: StoredSecret[T]) -> None:
        local_secret.path = self.path
        if self.encoding is not None:
            local_secret.encoding = self.encoding
        if self.silent_mode is not None:
            local_secret.silent_mode = self.silent_mode
