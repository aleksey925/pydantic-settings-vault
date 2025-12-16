from typing import NamedTuple

from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict as _SettingsConfigDict
from typing_extensions import TypedDict


class SettingsConfigDict(_SettingsConfigDict, total=False):
    vault_url: str | None
    vault_token: str | SecretStr | None
    vault_namespace: str | None
    vault_certificate_verify: bool | str | None
    vault_auth_mount_point: str | None
    vault_role_id: str | None
    vault_secret_id: str | SecretStr | None
    vault_kubernetes_role: str | None
    vault_auth_path: str | None
    vault_jwt_role: str | None
    vault_jwt_token: str | SecretStr | None


class HvacClientParameters(TypedDict, total=False):
    namespace: str
    token: str
    verify: bool | str


class HvacReadSecretParameters(TypedDict, total=False):
    path: str
    mount_point: str


class AuthMethodParameters(TypedDict, total=False):
    mount_point: str
    path: str


class Approle(NamedTuple):
    role_id: str
    secret_id: SecretStr


class Kubernetes(NamedTuple):
    role: str
    jwt_token: SecretStr


class VaultJwt(NamedTuple):
    role: str
    token: SecretStr
