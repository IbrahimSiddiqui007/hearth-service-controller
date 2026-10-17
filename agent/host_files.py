"""Separately approved, read-only host browsing; never grants service editing."""
import os
import stat
from pathlib import Path
from fastapi import HTTPException
from shared.configuration import secret_filename,secret_reasons

PRIVATE={'.ssh','.gnupg','.aws','.azure','.kube','.config','.local','.codex','.agents','.git','appdata','keychains','shadow','gshadow','sam','security','system','ntuser.dat','login.keychain-db'}


def read(config,profile,path,state=None):
    roots=config.get('host_browse_roots',{})
    if not isinstance(roots,dict) or profile not in roots:raise HTTPException(403,'Host browsing needs separate local root approval')
    root=Path(roots[profile])
    if not root.is_absolute() or not root.is_dir():raise HTTPException(403,'Host browse root must be an existing absolute directory')
    relative=Path(path)
    if relative.is_absolute() or '..' in relative.parts or '\x00' in path:raise HTTPException(403,'Use a relative path inside the approved host root')
    target=root/relative
    for part in (target,*target.parents):
        if part.is_symlink() or getattr(part,'is_junction',lambda:False)():raise HTTPException(403,'Linked host paths are refused')
    target=target.resolve(strict=True);root=root.resolve(strict=True)
    if not target.is_relative_to(root) or any(p.lower() in PRIVATE for p in target.parts) or any(secret_filename(p) for p in (root.name,*relative.parts)):raise HTTPException(403,'Private host paths are excluded')
    if os.name!='nt' and target.parts[1:2] and target.parts[1] in ('proc','sys','dev','run'):raise HTTPException(403,'Virtual host paths are excluded')
    if state and target.is_relative_to(Path(state).resolve()):raise HTTPException(403,'Agent private state is excluded')
    try:
        if target.is_dir():
            entries=[]
            for item in target.iterdir():
                if len(entries)>=500:break
                if item.name.lower() in PRIVATE or secret_filename(item) or item.is_symlink() or getattr(item,'is_junction',lambda:False)():continue
                try:
                    info=item.stat(follow_symlinks=False)
                    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):continue
                    entries.append({'name':item.name,'directory':stat.S_ISDIR(info.st_mode),'size':info.st_size if stat.S_ISREG(info.st_mode) else None})
                except OSError:continue
            return {'kind':'directory','path':path,'entries':sorted(entries,key=lambda r:(not r['directory'],r['name'].lower())),'readonly':True}
        before=target.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise HTTPException(403,'Only ordinary single-link files can be previewed')
        fd=os.open(target,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
        with os.fdopen(fd,'rb') as stream:
            opened=os.fstat(stream.fileno())
            if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise HTTPException(409,'Host file changed before preview')
            raw=stream.read(2_000_001)
        content=raw[:2_000_000].decode('utf-8')
        if '\x00' in content or secret_reasons(content):raise HTTPException(403,'Binary or suspected secret-bearing host files cannot be previewed')
        return {'kind':'file','path':path,'content':content,'truncated':len(raw)>2_000_000,'readonly':True}
    except (PermissionError,UnicodeError):raise HTTPException(403,'This host file cannot be safely previewed')
