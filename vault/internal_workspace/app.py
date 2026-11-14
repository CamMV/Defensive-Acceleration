"""Aplicación interna ficticia (L1). Objetivo de los ataques de integridad."""

LIB_VERSION = "2.3.0"
REQUEST_TIMEOUT_SECONDS = 10


def build_client_config() -> dict:
    return {"lib_version": LIB_VERSION, "timeout": REQUEST_TIMEOUT_SECONDS}


if __name__ == "__main__":
    print(build_client_config())
