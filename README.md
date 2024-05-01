![license](https://img.shields.io/pypi/l/pydantic-settings-vault?style=for-the-badge) ![python version](https://img.shields.io/pypi/pyversions/pydantic-settings-vault?style=for-the-badge) [![version](https://img.shields.io/pypi/v/pydantic-settings-vault?style=for-the-badge)](https://pypi.org/project/pydantic-settings-vault/) [![tests status](https://img.shields.io/github/actions/workflow/status/aleksey925/pydantic-settings-vault/test.yml?branch=master&style=for-the-badge)](https://github.com/aleksey925/pydantic-settings-vault/actions?query=branch%3Amaster) [![coverage](https://img.shields.io/codecov/c/github/aleksey925/pydantic-settings-vault/master?style=for-the-badge)](https://app.codecov.io/gh/aleksey925/pydantic-settings-vault) [![](https://img.shields.io/pypi/dm/pydantic-settings-vault?style=for-the-badge)](https://pypi.org/project/pydantic-settings-vault/)

pydantic-settings-vault
=======================

> `pydantic-settings-vault` is a fork `pydantic-vault` with `pydantic 2.x` support.

A simple extension to [pydantic-settings][pydantic-basesettings] that can retrieve
secrets stored in [Hashicorp Vault][vault].

With pydantic-settings and pydantic-settings-vault, you can easily declare your
configuration in a type-hinted class, and load configuration from different sources,
including Vault secrets. pydantic-settings-vault will work the same when developing
locally and when deploying in production.

<!-- toc -->

- [Installation](#installation)
- [Getting started](#getting-started)
- [Documentation](#documentation)
  * [`Field` additional parameters](#field-additional-parameters)
  * [Configuration](#configuration)
  * [Authentication](#authentication)
    + [Approle](#approle)
    + [Kubernetes](#kubernetes)
    + [Token](#token)
    + [JWT/OIDC](#jwtoidc)
  * [Order of priority](#order-of-priority)
- [Logging](#logging)
- [Examples](#examples)
  * [Retrieve a secret from a KV v2 secret engine](#retrieve-a-secret-from-a-kv-v2-secret-engine)
  * [Retrieve a whole secret at once](#retrieve-a-whole-secret-at-once)
  * [Retrieve a secret from a KV v1 secret engine](#retrieve-a-secret-from-a-kv-v1-secret-engine)
  * [Retrieve a secret from a database secret engine](#retrieve-a-secret-from-a-database-secret-engine)
  * [Use a dynamic path to retrieve secrets](#use-a-dynamic-path-to-retrieve-secrets)
- [Known limitations](#known-limitations)
- [Inspirations](#inspirations)
- [License](#license)
- [Development](#development)
  * [Debugging with a real Vault server](#debugging-with-a-real-vault-server)

<!-- tocstop -->

## Installation

pip

```shell
pip install pydantic-settings-vault
```

poetry

```shell
poetry add pydantic-settings-vault
```

## Getting started

It is a simple example that shows how to use `pydantic-settings-vault` with
`pydantic-settings`. Here we created a simple `Settings` class with two fields:
`username` and `password`, which will be loaded from a Vault. We also defined the
`settings_customise_sources()` method to declare sources from which the settings
will be loaded.

Before running the code, you need to set the `VAULT_ADDR` and `VAULT_TOKEN` environment
variables, or you can get an example of declaring configuration options inside
the `Settings.model_config` dict.
More information about the available settings and how they can be used can be found
[here](#configuration).

```python
import os

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret
    # The `vault_secret_key` is the specific key to extract from a secret
    username: str = Field(
        json_schema_extra={
            "vault_secret_path": "secret/data/path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    password: SecretStr = Field(
        json_schema_extra={
            "vault_secret_path": "secret/data/path/to/secret",
            "vault_secret_key": "my_password",
        },
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # This is where you can choose which settings sources to use and their priority
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )


settings = Settings()
# These variables will come from the Vault secret you configured
print(settings.username)
print(settings.password.get_secret_value())


# Now let's pretend we have already set the USERNAME in an environment variable
# (see the Pydantic documentation for more information and to know how to configure it)
# With the priority order we defined above, its value will override the Vault secret
os.environ["USERNAME"] = "my user"

settings = Settings()
print(settings.username)  # "my user", defined in the environment variable
print(settings.password.get_secret_value())  # the value set in Vault
```

In case if you want to use the `Settings.model_config` dict to declare the
configuration options, you can do it like this:

```python
...


class Settings(BaseSettings):
    ...
    model_config = {
        "vault_url": "https://vault.tld",
        "vault_token": "my-vault-token",
    }
    ...
```

## Documentation

### `Field` additional parameters

You might have noticed that we import `Field` directly from Pydantic. pydantic-settings-vault doesn't add any custom logic to it, which means you can still use everything you know and love from Pydantic.

The additional parameters pydantic-settings-vault uses are:

| Parameter name              | Required | Description                                                                                                                                     |
|-----------------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `vault_secret_path`         | **Yes**  | The path to your secret in Vault<br>This needs to be the *full path* to the secret, including its mount point (see [examples](#examples) below) |
| `vault_secret_key`          | No       | The key to use in the secret<br>If it is not specified the whole secret content will be loaded as a dict (see [examples](#examples) below)      |

For example, if you create a secret `database/prod` with a key `password` and a value of `a secret password` in a KV v2 secret engine mounted at the default `secret/` location, you would access it with

```python
password: SecretStr = Field(
    ...,
    json_schema_extra={
        "vault_secret_path": "secret/data/database/prod",
        "vault_secret_key": "password",
    },
)
```

### Configuration

To be able to use `pydantic-settings-vault`, you need to do two things:

1. Declare the `settings_customise_sources` method in your `Settings` class. This
method is used to declare the sources from which the settings will be loaded.
2. Configure how `pydantic-settings-vault` should connect to your Vault server. You
can do that through the `Settings.model_config` dict or environment variables.

> Environment variables have more priority and override what has been defined in the
> `Settings.model_config` dict.

Below is a list of all available settings:

| Settings name              | Type                       | Required | Environment variable     | Description                                                                                                                                             |
|----------------------------|----------------------------|----------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vault_url`                | `str`                      | **Yes**  | `VAULT_ADDR`             | Your Vault URL                                                                                                                                          |
| `vault_token`              | `str \| SecretStr \| None` | No       | `VAULT_TOKEN`            | Vault token (see details [here](#Token))                                                                                                                |
| `vault_namespace`          | `str \| None`              | No       | `VAULT_NAMESPACE`        | Your Vault namespace (if you use one, requires Vault Enterprise)                                                                                        |
| `vault_auth_path`          | `str \| None`              | No       | `VAULT_AUTH_PATH`        | The path of the authentication method, such as `/auth/{path}/login`, if different from its default, is only supported by the JWT authentication method. |
| `vault_auth_mount_point`   | `str \| None`              | No       | `VAULT_AUTH_MOUNT_POINT` | The mount point of the authentication method, if different from its default mount point                                                                 |
| `vault_certificate_verify` | `str \| bool \| None`      | No       | `VAULT_CA_BUNDLE`        | The path to a CA bundle validating your Vault certificate, or `False` to disable verification (see [hvac docs][hvac-private-ca])                        |
| `vault_role_id`            | `str \| None`              | No       | `VAULT_ROLE_ID`          | The role id for the Approle authentication method (see details [here](#approle))                                                                        |
| `vault_secret_id`          | `str \| SecretStr \| None` | No       | `VAULT_SECRET_ID`        | The secret id for the Approle authentication method (see details [here](#approle))                                                                      |
| `vault_kubernetes_role`    | `str \| None`              | No       | `VAULT_KUBERNETES_ROLE`  | The role for the Kubernetes authentication method (see details [here](#kubernetes))                                                                     |
| `vault_jwt_role`           | `str \| None`              | No       | `VAULT_JWT_ROLE`         | The role for the JWT/OIDC authentication method (see details [here](#jwtoidc))                                                                          |
| `vault_jwt_token`          | `str \| SecretStr \| None` | No       | `VAULT_JWT_TOKEN`        | The token for the JWT/OIDC authentication method (see details [here](#jwtoidc))                                                                         |

### Authentication

pydantic-settings-vault supports the following authentication method (in descending order of priority):
  - [approle][vault-auth-approle]
  - [kubernetes][vault-auth-kubernetes]
  - [token][vault-auth-token]
  - [jwt/oidc][vault-auth-jwt-oidc]

pydantic-settings-vault tries to be transparent and help you work, both during local development and in production. It will try to
find the required information for the first authentication method, if it can't it goes on to the next method, until it
has exhausted all authentication methods. In this case it gives up and logs the failure.

You only need to know this order of priority if you specify the authentication parameters for multiple methods.

Support is planned for GKE authentication methods (contributions welcome! :wink:).

#### Approle

To authenticate using the [Approle auth method][vault-auth-approle], you need to pass a role ID and a secret ID to your Settings class.

pydantic-settings-vault reads this information from the following sources (in descending order of priority):
  - the `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment variables
  - the `vault_role_id` and `vault_secret_id` configuration fields in your `Settings.model_config` dict (`vault_secret_id` can be a `str` or a `SecretStr`)

You can also mix-and-match, e.g. write the role ID in your `Settings.model_config` dict and retrieve the secret ID from the environment at runtime.

Example:
```python
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_password",
        },
    )

    model_config = {
        "vault_url": "https://vault.tld",
        "vault_role_id": "my-role-id",
        "vault_secret_id": SecretStr("my-secret-id"),
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )
```

#### Kubernetes

To authenticate using the [Kubernetes auth method][vault-auth-kubernetes], you need to pass a role to your Settings class.

pydantic-settings-vault reads this information from the following sources (in descending order of priority):
  - the `VAULT_KUBERNETES_ROLE` environment variable
  - the `vault_kubernetes_role` configuration field in your `Settings.model_config` dict, which must be a `str`

The Kubernetes service account token will be read from the file at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

Example:
```python
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_password",
        },
    )

    model_config = {
        "vault_url": "https://vault.tld",
        "vault_kubernetes_role": "my-role",
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )
```

#### Token

To authenticate using the [Token auth method][vault-auth-token], you need to pass a Vault token to your `Settings` class.

pydantic-settings-vault reads this token from the following sources (in descending order of priority):
  - the `VAULT_TOKEN` environment variable
  - the `~/.vault-token` file (so you can use the `vault` CLI to login locally, pydantic-settings-vault will transparently reuse its token)
  - the `vault_token` configuration field in your `Settings.model_config` dict, which can be a `str` or a `SecretStr`

Example:
```python
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_password",
        },
    )

    model_config = {
        "vault_url": "https://vault.tld",
        "vault_token": SecretStr("my-secret-token"),
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )
```

#### JWT/OIDC

To authenticate using the [JWT/OIDC method][vault-auth-jwt-oidc], you need to pass
a token role and a token itself to your Settings class.

pydantic-settings-vault reads this information from the following sources (in descending order of priority):

- the `VAULT_JWT_ROLE` and `VAULT_JWT_TOKEN` environment variables
- the `vault_jwt_role` and `vault_jwt_token` configuration fields in your
  `Settings.model_config` class (`vault_jwt_token` can be a `str` or a `SecretStr`)

You can also mix and match, for example, write the role in your `Settings.model_config`
class and retrieve the token from the environment at runtime.

Example:
```python
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "path/to/secret",
            "vault_secret_key": "my_password",
        },
    )

    model_config = {
        "vault_url": "https://vault.tld",
        "vault_jwt_role": "my-role",
        "vault_jwt_token": SecretStr("my-token"),
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )
```

### Order of priority

You can customize settings sources and choose the order of priority you want.

Here are some examples:
```python
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    """
    In descending order of priority:
      - arguments passed to the `Settings` class initializer
      - environment variables
      - Vault variables
      - variables loaded from the secrets directory, such as Docker Secrets
      - the default field values for the `Settings` model
    """

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )


class Settings(BaseSettings):
    """
    In descending order of priority:
      - Vault variables
      - environment variables
      - variables loaded from the secrets directory, such as Docker Secrets
      - the default field values for the `Settings` model
    Here we chose to remove the "init arguments" source,
    and move the Vault source up before the environment source
    """

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            VaultSettingsSource(settings_cls),
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )
```

## Logging

The library exports a logger called `pydantic-vault`.

To help debugging you can change the log level. A simple way to do that if you do not have a custom log setup is:
```py
# At the beginning of your main file or entrypoint
import logging

logging.basicConfig()
logging.getLogger("pydantic-vault").setLevel(logging.DEBUG)  # Change the log level here
```

## Examples

All examples use the following structure, so we will omit the imports and the `model_config` dict:
```python
from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource


class Settings(BaseSettings):
    ###############################################
    # THIS PART CHANGES IN THE DIFFERENT EXAMPLES #
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "secret/data/path/to/secret",
            "vault_secret_key": "my_user",
        },
    )
    ###############################################

    model_config = {"vault_url": "https://vault.tld"}

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )
```

### Retrieve a secret from a KV v2 secret engine

Suppose your secret is at `my-api/prod` and looks like this:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

Your settings class would be:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # The `vault_secret_key` is the specific key to extract from a secret.
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "secret/data/my-api/prod",
            "vault_secret_key": "root_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "secret/data/my-api/prod",
            "vault_secret_key": "root_password",
        },
    )


settings = Settings()

settings.username  # "root"
settings.password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

### Retrieve a whole secret at once

If you omit the `vault_secret_key` parameter in your `Field`, pydantic-settings-vault will load
the whole secret in your class field.

With the same secret as before, located at `my-api/prod` and with this data:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

You could use a settings class like this to retrieve everything in the secret:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # We don't pass a `vault_secret_key` here so that pydantic-settings-vault fetches all fields at once.
    credentials: dict = Field(
        ..., json_schema_extra={"vault_secret_path": "secret/data/my-api/prod"}
    )


settings = Settings()
settings.credentials  # { "root_user": "root", "root_password": "a_v3ry_s3cur3_p4ssw0rd" }
```

You can also use a Pydantic `BaseModel` class to parse and validate the incoming secret:
```python
class Credentials(BaseModel):
    root_user: str
    root_password: SecretStr


class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # We don't pass a `vault_secret_key` here so that pydantic-settings-vault fetches all fields at once.
    credentials: Credentials = Field(
        ..., json_schema_extra={"vault_secret_path": "secret/data/my-api/prod"}
    )


settings = Settings()
settings.credentials.root_user  # "root"
settings.credentials.root_password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

### Retrieve a secret from a KV v1 secret engine

Suppose your secret is at `my-api/prod` and looks like this:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

Your settings class would be:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v1 secret engine, the secret path is directly appended to the mount point,
    # eg. if your mount point is `kv/` (the default) and your secret path is `my-api/prod`,
    # the full path to use is `kv/my-api/prod` (unlike with KV v2 secret engines).
    # The `vault_secret_key` is the specific key to extract from a secret.
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "kv/my-api/prod",
            "vault_secret_key": "root_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": "kv/my-api/prod",
            "vault_secret_key": "root_password",
        },
    )


settings = Settings()

settings.username  # "root"
settings.password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

⚠ Beware of the [known limitations](#known-limitations) on KV v1 secrets!

### Retrieve a secret from a database secret engine

Database secrets can be "dynamic", generated by Vault every time you request access.
Because every call to Vault will create a new database account, you cannot store the username
and password in two different fields in your settings class, or you would get the username of the
*first* generated account and the password of the *second* account. This means that you must *not*
pass a `vault_secret_key`, so that pydantic-settings-vault retrieves the whole secret at once.

You can store the credentials in a dict or in a custom `BaseModel` class:
```python
class DbCredentials(BaseModel):
    username: str
    password: SecretStr


class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a database secret engine, the secret path is `<mount point>/creds/<role name>`.
    # For example if your mount point is `database/` (the default) and your role name is
    # `my-db-prod`, the full path to use is `database/creds/my-db-prod`. You will receive
    # `username` and `password` fields in response.
    # You must *not* pass a `vault_secret_key` so that pydantic-settings-vault fetches both fields at once.
    db_creds: DbCredentials = Field(
        ..., json_schema_extra={"vault_secret_path": "database/creds/my-db-prod"}
    )
    db_creds_in_dict: dict = Field(
        ..., json_schema_extra={"vault_secret_path": "database/creds/my-db-prod"}
    )


settings = Settings()

settings.db_creds.username  # "generated-username-1"
settings.db_creds.password.get_secret_value()  # "generated-password-for-username-1"
settings.db_creds_in_dict["username"]  # "generated-username-2"
settings.db_creds_in_dict["password"]  # "generated-password-for-username-2"
```

### Use a dynamic path to retrieve secrets

If you have different paths for your secrets (for example if you have different environments) you can use string formatting
to dynamically generate the paths depending on an environment variable.

```python
import os

# You will need to specify the environment in an environment variable, but by
# default it falls back to "dev"
ENV = os.getenv("ENV", "dev")


class Settings(BaseSettings):
    # This will load different secrets depending on the value of the ENV environment variable
    username: str = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": f"kv/my-api/{ENV}",
            "vault_secret_key": "root_user",
        },
    )
    password: SecretStr = Field(
        ...,
        json_schema_extra={
            "vault_secret_path": f"kv/my-api/{ENV}",
            "vault_secret_key": "root_password",
        },
    )


settings = Settings()

settings.username  # "root"
settings.password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

## Known limitations

- On KV v1 secret engines, if your secret has a `data` key and you do not specify a `vault_secret_key`
to load the whole secret at once, pydantic-settings-vault will only load the content of the `data` key.
  For example, with a secret `kv/my-secret`
  ```
  Key             Value
  ---             -----
  user            root
  password        a_v3ry_s3cur3_p4ssw0rd
  data            a very important piece of data
  ```
  and the settings class
  ```python
  class Settings(BaseSettings):
      my_secret: dict = Field(
          ..., json_schema_extra={"vault_secret_path": "kv/my-secret"}
      )
  ```
  pydantic-settings-vault will try to load only the `data` value (`a very important piece of data`) in
  `my_secret`, which will fail validation from Pydantic because it is not a dict.

  **Workaround:** Rename the `data` key in your secret 😅

  **Workaround:** Migrate to KV v2

## Inspirations

- [Ansible `hashi_vault` lookup plugin][ansible hashi_vault] for the API and some code
- [Hashicorp's Vault GitHub Action][vault-action] for the API

## License

pydantic-settings-vault is available under the [MIT license](./LICENSE).

## Development

### Debugging with a real Vault server

You can use a real Vault server to debug this project. To make this process
easier, this project includes a `docker-compose.yml` file that can run a
ready-to-use Vault server.

To run the server and set it up, run the following commands:

```shell
docker-compose up
make setup-vault
```

After that, you will have a Vault server running at `http://localhost:8200`, where you can authorize in two ways:

- using the root token (which is `token`)
- using the JWT method (role=`jwt_role`, token=[link](./configs/vault/jwt_token.txt))
- using the AppRole method (the values of role_id and secret_id can be found in the logs of the `make setup-vault` command).

[ansible hashi_vault]: https://docs.ansible.com/ansible/latest/collections/community/hashi_vault/hashi_vault_lookup.html
[hvac-private-ca]: https://hvac.readthedocs.io/en/stable/advanced_usage.html#making-use-of-private-ca
[pydantic]: https://docs.pydantic.dev/latest/
[pydantic-basesettings]: https://docs.pydantic.dev/latest/usage/pydantic_settings/
[pydantic-basesettings-customsource]: https://docs.pydantic.dev/latest/usage/pydantic_settings/#adding-sources
[vault]: https://www.vaultproject.io/
[vault-action]: https://github.com/hashicorp/vault-action
[vault-auth-approle]: https://www.vaultproject.io/docs/auth/approle
[vault-auth-kubernetes]: https://www.vaultproject.io/docs/auth/kubernetes
[vault-auth-token]: https://www.vaultproject.io/docs/auth/token
[vault-auth-jwt-oidc]: https://developer.hashicorp.com/vault/docs/auth/jwt
[vault-kv-v2]: https://www.vaultproject.io/docs/secrets/kv/kv-v2/
