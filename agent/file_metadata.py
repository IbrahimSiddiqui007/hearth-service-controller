"""Native metadata-preserving replacement. Never ignore ACL merge failures."""
import ctypes
import os
import platform
import uuid
from pathlib import Path
from dataclasses import dataclass, field


@dataclass(frozen=True)
class WindowsSecurity:
    descriptor: bytes = field(compare=False)
    owner: bytes
    dacl: bytes
    protected: bool


class ReplacementUncertain(OSError):
    """Preserve candidate/recovery files after a native replacement may have begun."""


def windows_api():
    if os.name != 'nt':
        raise OSError('Windows security APIs are unavailable')
    from ctypes import wintypes as w
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    signatures = [
        (adv.GetFileSecurityW, [w.LPCWSTR, w.DWORD, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
        (adv.SetFileSecurityW, [w.LPCWSTR, w.DWORD, w.LPVOID], w.BOOL),
        (adv.GetSecurityDescriptorOwner, [w.LPVOID, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)], w.BOOL),
        (adv.GetSecurityDescriptorControl, [w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL),
        (adv.GetSecurityDescriptorDacl, [w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)], w.BOOL),
        (adv.GetLengthSid, [w.LPVOID], w.DWORD),
        (adv.OpenProcessToken, [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL),
        (adv.GetTokenInformation, [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
        (adv.EqualSid, [w.LPVOID, w.LPVOID], w.BOOL),
        (kernel.GetCurrentProcess, [], w.HANDLE),
        (kernel.CloseHandle, [w.HANDLE], w.BOOL),
        (kernel.ReplaceFileW, [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.LPVOID, w.LPVOID], w.BOOL),
    ]
    for function, args, result in signatures:
        function.argtypes, function.restype = args, result
    return adv, kernel


def windows_security(path, require_owner=True):
    from ctypes import wintypes as w
    adv, kernel = windows_api()
    size = w.DWORD()
    adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))  # OWNER | DACL
    if not 0 < size.value <= 65536:
        raise PermissionError('File security descriptor is unavailable')
    descriptor = ctypes.create_string_buffer(size.value)
    if not adv.GetFileSecurityW(str(path), 5, descriptor, size, ctypes.byref(size)):
        raise PermissionError('File security descriptor cannot be read')
    owner, defaulted = w.LPVOID(), w.BOOL()
    if not adv.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)) or not owner:
        raise PermissionError('File owner is unavailable')
    if require_owner:
        token = w.HANDLE()
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise PermissionError('Agent account identity is unavailable')
        try:
            needed = w.DWORD()
            adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
            if not 0 < needed.value <= 65536:
                raise PermissionError('Agent account identity is unavailable')
            user = ctypes.create_string_buffer(needed.value)
            if not adv.GetTokenInformation(token, 1, user, needed, ctypes.byref(needed)):
                raise PermissionError('Agent account identity cannot be read')
            sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
            if not adv.EqualSid(owner, sid):
                raise PermissionError('The agent account must own the file')
        finally:
            kernel.CloseHandle(token)
    present, dacl, defaulted, control, revision = w.BOOL(), w.LPVOID(), w.BOOL(), w.WORD(), w.DWORD()
    if not adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present or not dacl:
        raise PermissionError('An explicit file DACL is required')
    if not adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
        raise PermissionError('File ACL protection cannot be read')
    acl_size = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[1]
    sid_size = adv.GetLengthSid(owner)
    if not 8 <= acl_size <= 65536 or not 8 <= sid_size <= 1024:
        raise PermissionError('File security metadata is invalid')
    # Compare actual ownership, ordered ACE bytes and inheritance protection.
    # Self-relative layout and informational auto-inherit flags can change when
    # Windows merges the same ACL; they do not establish changed permissions.
    return WindowsSecurity(descriptor.raw[:size.value], ctypes.string_at(owner, sid_size), ctypes.string_at(dacl, acl_size), bool(control.value & 0x1000))


def mac_library():
    if platform.system() != 'Darwin':
        raise OSError('macOS metadata APIs are unavailable')
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.fcopyfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libc.fcopyfile.restype = ctypes.c_int
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.getxattr.restype = ctypes.c_ssize_t
    return libc


def mac_security(path):
    libc = mac_library()
    acl = libc.acl_get_file(os.fsencode(path), 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        raise PermissionError('macOS file ACL cannot be read')
    text = None
    try:
        length = ctypes.c_ssize_t()
        text = libc.acl_to_text(acl, ctypes.byref(length))
        if not text or not 0 <= length.value <= 65536:
            raise PermissionError('macOS file ACL cannot be verified')
        info = path.stat()
        attrs, total = {}, 0
        for key in os.listxattr(path, follow_symlinks=False):
            size = libc.getxattr(os.fsencode(path), os.fsencode(key), None, 0, 0, 1)
            if size < 0 or size > 262144 or total + size > 2_000_000:
                raise OSError('File extended attributes exceed the supported limit or cannot be read')
            value = os.getxattr(path, key, follow_symlinks=False)
            if len(value) != size:
                raise OSError('File extended attributes changed during verification')
            attrs[key], total = value, total + size
        return (info.st_uid, info.st_gid, info.st_mode & 0o7777, ctypes.string_at(text, length.value), attrs)
    finally:
        if text:
            libc.acl_free(text)
        libc.acl_free(acl)


def security(path, system):
    return windows_security(path) if system == 'Windows' else mac_security(path) if system == 'Darwin' else None


def copy_metadata(source, candidate, system, expected):
    if system == 'Windows':
        adv, _ = windows_api()
        descriptor = ctypes.create_string_buffer(expected.descriptor)
        from ctypes import wintypes as w
        control, revision = w.WORD(), w.DWORD()
        if not adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise PermissionError('Original ACL protection cannot be read')
        flags = 4 | (0x80000000 if control.value & 0x1000 else 0x20000000)
        if not adv.SetFileSecurityW(str(candidate), flags, descriptor):
            raise PermissionError('Candidate ACL could not be preserved')
    elif system == 'Darwin':
        libc = mac_library()
        with source.open('rb') as original, candidate.open('r+b') as replacement:
            if libc.fcopyfile(original.fileno(), replacement.fileno(), None, 7):  # ACL | STAT | XATTR; never DATA
                raise PermissionError('macOS metadata copy failed; original file was not replaced')
    if system in ('Windows', 'Darwin') and security(candidate, system) != expected:
        raise PermissionError('Candidate permissions differ; original file was not replaced')


def replace(candidate, target, system, expected):
    if system == 'Windows':
        _, kernel = windows_api()
        backup = target.parent / ('.psc-recovery-' + uuid.uuid4().hex)
        if backup.exists() or backup.is_symlink():
            raise OSError('Recovery path is occupied; original file was not replaced')
        # A backup name is supplied because ReplaceFileW can partially rename
        # files on error. Never ignore ACL or attribute merging failures.
        if not kernel.ReplaceFileW(str(target), str(candidate), str(backup), 0, None, None):
            raise ReplacementUncertain('Windows replacement outcome is unverified; candidate/recovery copies were retained beside the file. Inspect locally before retrying.')
        try:
            if security(target, system) != expected:
                # ReplaceFileW may materialize inherited ACEs as explicit entries.
                # Restore the original inheritance state, then verify exact ACLs.
                copy_metadata(backup, target, system, expected)
                if security(target, system) != expected:
                    raise ReplacementUncertain('Replaced file permissions could not be verified; recovery copy retained. Inspect locally before retrying.')
        except OSError as exc:
            raise ReplacementUncertain('Replaced file permissions are unverified; recovery copy retained. Inspect locally before retrying.') from exc
        try:
            backup.unlink(missing_ok=True)
        except OSError:
            pass  # Successful save remains successful; private original copy is retained.
    else:
        os.replace(candidate, target)
