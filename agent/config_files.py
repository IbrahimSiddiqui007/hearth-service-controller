"""Approved config edits with native metadata checks and conservative secret exclusion."""
import hashlib
import os
import stat
import tempfile
import threading
from pathlib import Path

from fastapi import HTTPException

from shared.configuration import secret_filename, secret_reasons, validate_configuration
from agent.file_metadata import security, copy_metadata, replace, ReplacementUncertain

_write_lock = threading.Lock()


def editable(config, ref, target, content, truncated, os_name, original_path=None):
    if os_name not in ('Linux', 'Windows', 'Darwin') or ref not in config.get('allow_file_edits', []) or truncated or secret_filename(target) or secret_reasons(content):
        return False
    try:
        original = Path(original_path or target)
        if any(part.is_symlink() or getattr(part, 'is_junction', lambda: False)() for part in (original, *original.parents)):
            return False
        metadata = target.stat()
        security(target, os_name)
        return (stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 2_000_000 and metadata.st_nlink == 1
                and (not hasattr(os, 'getuid') or metadata.st_uid == os.getuid())
                and os.access(target.parent, os.W_OK))
    except OSError:
        return False


def atomic_edit(config, ref, root_index, path, body, safe_path, os_name, command=None):
    if os_name not in ('Linux', 'Windows', 'Darwin'):
        raise HTTPException(409, 'Config edits require a supported native file metadata adapter')
    if ref not in config.get('allow_file_edits', []):
        raise HTTPException(403, 'File editing is not enabled for this service on the agent')
    roots = config.get('file_roots', {}).get(ref, [])
    if not isinstance(roots, list) or root_index >= len(roots):
        raise HTTPException(403, 'No approved file root')
    root = Path(roots[root_index])
    with _write_lock:
        try:
            target = safe_path(root, path)
            cursor = root
            if any(part.is_symlink() or getattr(part, 'is_junction', lambda: False)() for part in (root, *root.parents)):
                raise HTTPException(403, 'Symlink or junction roots are read-only')
            for part in Path(path).parts:
                cursor = cursor / part
                if cursor.is_symlink() or getattr(cursor, 'is_junction', lambda: False)():
                    raise HTTPException(403, 'Symlink paths are read-only')
            if not target.is_file() or target.stat().st_size > 2_000_000:
                raise HTTPException(413, 'Only existing regular text files of at most 2 MB can be edited')
            metadata = target.stat()
            if metadata.st_nlink != 1:
                raise HTTPException(403, 'Files with multiple hard links are read-only')
            permissions = security(target, os_name)
            if hasattr(os, 'getuid') and metadata.st_uid != os.getuid():
                raise HTTPException(403, 'The agent must own a file before editing it')
            raw = target.read_bytes()
            if hashlib.sha256(raw).hexdigest() != body.etag:
                raise HTTPException(409, 'File changed since it was opened; reload before saving')
            original = raw.decode('utf-8')
            if secret_filename(target) or secret_reasons(original) or '\x00' in original:
                raise HTTPException(403, 'Secret-bearing or binary files remain read-only and are excluded from history')
            validation = validate_configuration(path, body.content)
            content = body.content.replace('\r\n', '\n')
            if b'\r\n' in raw and b'\n' not in raw.replace(b'\r\n', b''):
                content = content.replace('\n', '\r\n')
            encoded = content.encode('utf-8')
            if len(encoded) > 2_000_000:
                raise HTTPException(413, 'File exceeds 2 MB after preserving line endings')
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.psc-edit-', delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                if os_name == 'Linux':
                    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
                copy_metadata(target, temporary, os_name, permissions)
                if body.validate_runtime:
                    profile = config.get('config_validators', {}).get(ref)
                    argv = profile.get('argv') if isinstance(profile, dict) else None
                    if not isinstance(argv, list) or '{file}' not in argv or len(argv) > 30 or any(not isinstance(arg, str) or '\x00' in arg or len(arg) > 1024 for arg in argv):
                        raise HTTPException(409, 'No fixed runtime validator with a {file} argument is configured for this service')
                    try:
                        command([str(temporary) if arg == '{file}' else arg for arg in argv], timeout=15)
                    except HTTPException:
                        raise HTTPException(422, 'Agent runtime validation failed; the original file was preserved')
                if target.stat().st_ino != metadata.st_ino or hashlib.sha256(target.read_bytes()).hexdigest() != body.etag:
                    raise HTTPException(409, 'File changed while preparing the save; no content was replaced')
                if security(target, os_name) != permissions:
                    raise HTTPException(409, 'File permissions changed while preparing the save; no content was replaced')
                if hashlib.sha256(temporary.read_bytes()).hexdigest() != hashlib.sha256(encoded).hexdigest() or security(temporary, os_name) != permissions:
                    raise HTTPException(409, 'Candidate content or permissions changed during validation; no content was replaced')
                with temporary.open('r+b') as candidate:
                    os.fsync(candidate.fileno())
                try:
                    replace(temporary, target, os_name, permissions)
                except ReplacementUncertain as exc:
                    temporary = None  # Preserve recovery evidence after native partial failures.
                    raise HTTPException(503, str(exc)) from exc
                temporary = None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            return {'kind': 'file', 'root_index': root_index, 'path': path, 'resolved_path': str(target), 'etag': hashlib.sha256(encoded).hexdigest(), 'content': content.replace('\r\n', '\n'), 'editable': True, 'readonly': False, 'validation': validation}
        except (FileNotFoundError, NotADirectoryError):
            raise HTTPException(404, 'File not found')
        except PermissionError:
            raise HTTPException(403, 'Agent cannot safely replace this file')
        except UnicodeError:
            raise HTTPException(415, 'Only UTF-8 text files can be edited')
        except OSError:
            raise HTTPException(409, 'Native file metadata could not be preserved; inspect the file before retrying')
