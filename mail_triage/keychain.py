import ctypes
import ctypes.util
from typing import Protocol

SERVICE = "mail-triage"
LEGACY_SERVICE = "correo-limpio"


class SecurityUnavailable(RuntimeError):
    """The macOS Security framework is not present (e.g. non-macOS CI)."""

REFRESH_TOKEN = "refresh-token"
CLOUDFLARE_ACCOUNT_ID = "cloudflare-account-id"
CLOUDFLARE_TOKEN = "cloudflare-token"
PLAN_HMAC_KEY = "plan-hmac-key"

_ERR_SEC_DUPLICATE_ITEM = -25299
_ERR_SEC_ITEM_NOT_FOUND = -25300
_SECURITY = None
_CORE_FOUNDATION = None


def _core_foundation():
    global _CORE_FOUNDATION
    if _CORE_FOUNDATION is not None:
        return _CORE_FOUNDATION
    path = ctypes.util.find_library("CoreFoundation")
    if not path:
        raise RuntimeError("CoreFoundation no disponible")
    lib = ctypes.CDLL(path)
    lib.CFRelease.restype = None
    lib.CFRelease.argtypes = [ctypes.c_void_p]
    _CORE_FOUNDATION = lib
    return lib


def _cf_release(item) -> None:
    if item:
        _core_foundation().CFRelease(item)


def _keychain_find(lib, service_bytes, account_bytes, item, length=None, data=None):
    return lib.SecKeychainFindGenericPassword(
        None, len(service_bytes), service_bytes, len(account_bytes), account_bytes,
        ctypes.byref(length) if length is not None else None,
        ctypes.byref(data) if data is not None else None,
        ctypes.byref(item),
    )


def _keychain_add(lib, service_bytes, account_bytes, data, buffer):
    return lib.SecKeychainAddGenericPassword(
        None, len(service_bytes), service_bytes, len(account_bytes), account_bytes,
        len(data), buffer, None,
    )


def _security():
    """The macOS Security framework, loaded lazily so non-macOS imports work.

    Raises SecurityUnavailable when the framework is missing (non-macOS), so
    callers can treat the Keychain as "not configured" instead of crashing.
    """
    global _SECURITY
    if _SECURITY is not None:
        return _SECURITY
    path = ctypes.util.find_library("Security")
    if not path:
        raise SecurityUnavailable("Security framework no disponible")
    lib = ctypes.CDLL(path)
    lib.SecKeychainAddGenericPassword.restype = ctypes.c_int32
    lib.SecKeychainAddGenericPassword.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    lib.SecKeychainFindGenericPassword.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
    lib.SecKeychainItemModifyAttributesAndData.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
    ]
    lib.SecKeychainItemFreeContent.restype = ctypes.c_int32
    lib.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.SecKeychainItemDelete.restype = ctypes.c_int32
    lib.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
    _SECURITY = lib
    return lib


def _keychain_write(service: str, account: str, value: str) -> None:
    """Store a secret of any length without exposing it in argv.

    `security add-generic-password -w` reads at most 128 characters from stdin
    (silently truncating OAuth refresh tokens), so write through the Security
    framework instead.
    """
    lib = _security()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    data = value.encode("utf-8")
    # create_string_buffer rejects a zero-length buffer; an empty secret is
    # still a value the caller may want to store.
    buffer = ctypes.create_string_buffer(data, max(len(data), 1))
    item = ctypes.c_void_p()
    status = _keychain_find(lib, service_bytes, account_bytes, item)
    if status == 0:
        try:
            status = lib.SecKeychainItemModifyAttributesAndData(item, None, len(data), buffer)
        finally:
            _cf_release(item)
    elif status == _ERR_SEC_ITEM_NOT_FOUND:
        status = _keychain_add(lib, service_bytes, account_bytes, data, buffer)
        if status == _ERR_SEC_DUPLICATE_ITEM:
            # Another writer created the item between find and add: update it.
            item = ctypes.c_void_p()
            status = _keychain_find(lib, service_bytes, account_bytes, item)
            if status == 0:
                try:
                    status = lib.SecKeychainItemModifyAttributesAndData(
                        item, None, len(data), buffer
                    )
                finally:
                    _cf_release(item)
    if status != 0:
        raise RuntimeError(f"no se pudo guardar el secreto en el Keychain (OSStatus {status})")


def _keychain_read(service: str, account: str) -> str | None:
    """Read a secret through the same client that writes it.

    Mixing `security` CLI reads with framework writes makes macOS prompt for
    permission on every access: each side has its own ACL entry and the CLI's
    `-U` writes reset it.
    """
    lib = _security()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    length = ctypes.c_uint32()
    data = ctypes.c_void_p()
    item = ctypes.c_void_p()
    status = _keychain_find(lib, service_bytes, account_bytes, item, length, data)
    if status == _ERR_SEC_ITEM_NOT_FOUND:
        return None
    if status != 0:
        raise RuntimeError(f"no se pudo leer el Keychain (OSStatus {status})")
    try:
        return ctypes.string_at(data, length.value).decode("utf-8")
    finally:
        lib.SecKeychainItemFreeContent(None, data)
        _cf_release(item)


def _keychain_delete(service: str, account: str) -> None:
    lib = _security()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    item = ctypes.c_void_p()
    status = _keychain_find(lib, service_bytes, account_bytes, item)
    if status == 0:
        try:
            status = lib.SecKeychainItemDelete(item)
        finally:
            _cf_release(item)
    if status != 0:
        raise RuntimeError(f"no se pudo borrar el secreto del Keychain (OSStatus {status})")


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class MemoryStore:
    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._values = dict(initial or {})

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def set(self, name: str, value: str) -> None:
        self._values[name] = value

    def delete(self, name: str) -> None:
        self._values.pop(name, None)


class MacKeychain:
    def __init__(self, services=(SERVICE, LEGACY_SERVICE), writer=None, reader=None) -> None:
        self._services = tuple(services) or (SERVICE,)
        self._write = writer or _keychain_write
        self._read = reader or _keychain_read

    def get(self, name: str) -> str | None:
        for service in self._services:
            try:
                value = self._read(service, name)
            except SecurityUnavailable:
                # Non-macOS (CI): the Keychain simply isn't there, like the old CLI.
                return None
            if value is not None:
                return value
        return None

    def set(self, name: str, value: str) -> None:
        # The value never reaches argv; the writer hands the full bytes to the
        # Security framework, which has no 128-character stdin limit.
        self._write(self._services[0], name, value)

    def delete(self, name: str) -> None:
        _keychain_delete(self._services[0], name)
