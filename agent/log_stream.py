"""Bounded log followers; only approved argument vectors and paths reach this layer."""
import asyncio
import os
import re
import time

from agent.extra_runtimes import approved_log
from shared.models import redact
from shared.streams import frame, LineMask


async def command_lines(argv, env=None, duration=300, budget=2_000_000):
    process = None
    masker, total = LineMask(), 0
    try:
        process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, stdin=asyncio.subprocess.DEVNULL, env=env, limit=65536)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and total < budget:
            try:
                raw = await asyncio.wait_for(process.stdout.readline(), timeout=min(10, max(.01, deadline - time.monotonic())))
            except asyncio.TimeoutError:
                yield frame('heartbeat', '')
                continue
            except (ValueError, asyncio.LimitOverrunError):
                yield frame('error', 'Oversized log line; follower closed safely')
                return
            if not raw:
                break
            total += len(raw)
            yield frame('log', masker.apply(raw.decode('utf-8', errors='replace')))
        yield frame('end', 'Follower ended; start again for another bounded session')
    except OSError:
        yield frame('error', 'Log follower could not be started')
    finally:
        if process is not None:
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    # This is our read-only follower child, never the service.
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    await process.wait()
            else:
                await process.wait()


async def file_lines(config, ref, safe_path, lines=300, duration=300, budget=2_000_000):
    path = approved_log(config, ref, safe_path)
    masker, total = LineMask(), 0
    deadline = time.monotonic() + duration
    with path.open('rb') as stream:
        identity = os.fstat(stream.fileno())
        stream.seek(max(0, identity.st_size - 2_000_000))
        raw = stream.read(2_000_000)
        if b'\x00' in raw:
            yield frame('error', 'Binary logs cannot be displayed')
            return
        text = raw.decode('utf-8', errors='replace')
        if identity.st_size > 2_000_000:
            text = text.partition('\n')[2]
        yield frame('log', redact('\n'.join(text.splitlines()[-lines:]))[-100_000:] + '\n')
        while time.monotonic() < deadline and total < budget:
            current_path = approved_log(config, ref, safe_path)
            info = current_path.stat()
            if (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino) or info.st_size < stream.tell():
                yield frame('end', 'Log rotated or truncated; start again to read its current contents')
                return
            offset = stream.tell()
            raw = stream.readline(65537)
            if len(raw) > 65536 or b'\x00' in raw:
                yield frame('error', 'Oversized or binary log line; follower closed safely')
                return
            if raw and raw.endswith(b'\n'):
                total += len(raw)
                yield frame('log', masker.apply(raw.decode('utf-8', errors='replace')))
            else:
                stream.seek(offset)  # Hold incomplete lines so masking spans writes.
                await asyncio.sleep(.5)
                yield frame('heartbeat', '')
        yield frame('end', 'Follower ended; start again for another bounded session')
