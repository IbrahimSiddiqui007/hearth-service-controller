"""Opt-in restic profiles. No repository creation, mounts, credentials or pruning.

Only configured paths are read, and restores overlay verified regular files from
private staging after a mandatory safety snapshot. Unknown outcomes hold writes.
"""
import hashlib
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time

from fastapi import HTTPException
from shared.models import redact
from agent.file_metadata import security,copy_metadata,replace as replace_preserving_metadata,ReplacementUncertain


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()


def safe_directory(value):
    path=Path(value)
    if not path.is_absolute() or not path.is_dir() or any(p.is_symlink() or getattr(p,'is_junction',lambda:False)() for p in (path,*path.parents)):
        raise HTTPException(403,'Backup directories must be existing absolute paths without links or junctions')
    return path.resolve()


def invoke(argv, env, *, cwd=None, timeout=600):
    # Spool output to avoid unbounded backup progress accumulation in memory.
    with tempfile.TemporaryFile() as output:
        try:
            result=subprocess.run(argv,env=env,cwd=cwd,stdout=output,stderr=subprocess.DEVNULL,timeout=timeout)
        except (OSError,subprocess.TimeoutExpired):
            raise HTTPException(503,'Backup tool unavailable or interrupted; inspect repository and runtime before retrying')
        if result.returncode:
            raise HTTPException(502,'Restic could not complete the scoped operation; no raw file names or credential output retained')
        if output.tell()>4_000_000:
            raise HTTPException(413,'Backup metadata exceeds the supported review limit')
        output.seek(0)
        try:return output.read().decode('utf-8')
        except UnicodeError:raise HTTPException(502,'Invalid backup metadata')


class Backups:
    def __init__(self,config,replay,execute=None,observer=None):
        self.config,self.replay,self.execute=config,replay,execute or invoke
        self.observer=observer
        self.lock=threading.Lock()
        if replay:
            with self.db() as db:
                db.execute('CREATE TABLE IF NOT EXISTS backup_intents(id TEXT PRIMARY KEY,profile TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL)')
                if 'result' not in {row[1] for row in db.execute('PRAGMA table_info(backup_intents)')}:
                    db.execute("ALTER TABLE backup_intents ADD COLUMN result TEXT NOT NULL DEFAULT '{}'")
                db.execute("UPDATE backup_intents SET status='unknown' WHERE status='running'")

    def db(self):return sqlite3.connect(self.replay.path,timeout=5)

    def inspection(self,identifier):
        if not self.replay:raise HTTPException(403,'Backup inspection requires signed private state')
        with self.db() as db:row=db.execute('SELECT profile,status,active,result FROM backup_intents WHERE id=?',(identifier,)).fetchone()
        if not row:return {'operation_id':identifier,'status':'unreceived','profile':None,'active':False,'result':{}}
        return {'operation_id':identifier,'profile':row[0],'status':row[1],'active':bool(row[2]),'result':json.loads(row[3])}

    def remember(self,profile,result):
        with self.db() as db:
            db.execute("UPDATE backup_intents SET result=? WHERE profile=? AND active=1 AND status='running'",(json.dumps(result),profile['name']))

    def profile(self,name):
        if not self.replay:raise HTTPException(403,'Backup profiles require signed transport and private durable state')
        value=self.config.get('backup_profiles',{}).get(name)
        if not isinstance(value,dict):raise HTTPException(403,'Select a locally approved backup profile')
        mount=safe_directory(value.get('storage_root',''))
        if not os.path.ismount(mount):raise HTTPException(409,'Approved backup storage is not mounted; local fallback is refused')
        repository=safe_directory(value.get('repository',''))
        if not repository.is_relative_to(mount) or not (repository/'config').is_file() or (repository/'config').is_symlink():
            raise HTTPException(409,'Use an existing owner-provisioned restic repository inside the approved mount')
        roots=[safe_directory(p) for p in value.get('paths',[])]
        if not roots or len(roots)>8 or len(set(roots))!=len(roots):raise HTTPException(409,'Approve one to eight distinct service data/config/volume directories')
        state=self.replay.path.parent.resolve()
        if any(a.is_relative_to(b) or b.is_relative_to(a) for i,a in enumerate(roots) for b in roots[i+1:]):
            raise HTTPException(409,'Backup source directories must not overlap')
        if any(repository.is_relative_to(p) or p.is_relative_to(repository) or state.is_relative_to(p) or p.is_relative_to(state) or p==Path(p.anchor) for p in roots):
            raise HTTPException(403,'Sources must be separate from host roots, backup storage and agent state')
        password_env=value.get('password_env','')
        if not re.fullmatch(r'PSC_[A-Z0-9_]+',password_env) or not os.environ.get(password_env):
            raise HTTPException(409,'Supply the vault-managed repository password through the approved private agent environment')
        # Restrict paths before dispatch. Descendant links are checked again for restore.
        fingerprint=digest({'name':name,'config':value,'roots':[(str(p),p.stat().st_dev,p.stat().st_ino) for p in roots],
                            'repository':(str(repository),repository.stat().st_dev,repository.stat().st_ino),
                            'mount':(str(mount),mount.stat().st_dev,mount.stat().st_ino)})
        return {'name':name,'repository':repository,'roots':roots,'password_env':password_env,'fingerprint':fingerprint,
                'allow_restore':value.get('allow_restore') is True,'allow_retention':value.get('allow_retention') is True,
                'live_allowed':value.get('consistency')=='static',
                'max_files':min(int(value.get('max_restore_files',10000)),100000),
                'max_bytes':min(int(value.get('max_restore_bytes',4*1024**3)),100*1024**3)}

    def run(self,profile,args,**kwargs):
        if self.profile(profile['name'])['fingerprint']!=profile['fingerprint']:
            raise HTTPException(409,'Storage mount, source identity or local profile changed before tool dispatch')
        # Never inherit repository/password-command overrides from a shell.
        env={key:value for key,value in os.environ.items() if not key.startswith('RESTIC_')}
        password=os.environ.get(profile['password_env'],'')
        if not password:raise HTTPException(409,'Repository password is no longer available in its approved environment reference')
        env['RESTIC_PASSWORD']=password
        cache=self.replay.path.parent/'restic-cache'
        if cache.is_symlink() or getattr(cache,'is_junction',lambda:False)():raise HTTPException(403,'Unsafe private restic cache path')
        cache.mkdir(mode=0o700,exist_ok=True)
        env['RESTIC_CACHE_DIR']=str(cache)
        return self.execute(['restic','--repo',str(profile['repository']),'--json',*args],env,**kwargs)

    def snapshots(self,profile):
        try:rows=json.loads(self.run(profile,['snapshots','--tag','hearth:'+profile['name']]))
        except ValueError:raise HTTPException(502,'Invalid snapshot listing')
        if not isinstance(rows,list) or len(rows)>1000:raise HTTPException(413,'Snapshot listing exceeds review budget')
        result=[]
        for row in rows:
            if not isinstance(row,dict) or not re.fullmatch(r'[a-f0-9]{64}',str(row.get('id',''))) or 'hearth:'+profile['name'] not in row.get('tags',[]):
                raise HTTPException(502,'Unscoped snapshot metadata refused')
            result.append({'id':row['id'],'time':str(row.get('time',''))[:80],'tags':[t for t in row.get('tags',[]) if t in ('hearth:'+profile['name'],'hearth-safety','hearth-data')],
                           'size_bytes':(row.get('summary') or {}).get('total_bytes_processed')})
        return result

    def retention_plan(self,profile,daily,weekly):
        if not profile['allow_retention']:return None
        if not 1<=daily<=90 or not 0<=weekly<=52:raise HTTPException(422,'Invalid bounded retention policy')
        args=['forget','--tag','hearth:'+profile['name']+',hearth-data','--keep-daily',str(daily),'--keep-weekly',str(weekly)]
        try:groups=json.loads(self.run(profile,[*args,'--dry-run']))
        except ValueError:raise HTTPException(502,'Invalid retention preview')
        if not isinstance(groups,list):raise HTTPException(502,'Invalid retention groups')
        remove=[]
        for group in groups:
            for snapshot in group.get('remove',[]) or []:
                identifier=snapshot.get('id','')
                if not re.fullmatch(r'[a-f0-9]{64}',identifier) or 'hearth-safety' in snapshot.get('tags',[]) or 'hearth:'+profile['name'] not in snapshot.get('tags',[]):raise HTTPException(403,'Retention cannot remove unscoped or safety snapshots')
                remove.append(identifier)
        selected={'remove':sorted(remove),'keep_daily':daily,'keep_weekly':weekly,'safety_snapshots_preserved':True,'pruned':False}
        return selected|{'fingerprint':digest(selected)}

    def plan(self,name,keep_daily=7,keep_weekly=4):
        profile=self.profile(name)
        return {'profile':name,'fingerprint':profile['fingerprint'],'paths':[str(p) for p in profile['roots']],
                'physical_host_id':self.config.get('physical_host_id',''),'os':platform.system(),
                'repository':str(profile['repository']),'snapshots':self.snapshots(profile),
                'allow_restore':profile['allow_restore'],'allow_retention':profile['allow_retention'],
                'live_allowed':profile['live_allowed'],
                'retention_preview':self.retention_plan(profile,keep_daily,keep_weekly),
                'notice':'Encrypted/deduplicated restic snapshots on the existing mounted storage. Password values are never returned. Restores overlay selected files and preserve extra current files. Repository integrity and application recovery require separate verification.'}

    def selected(self,profile,identifier):
        if identifier not in {r['id'] for r in self.snapshots(profile)}:raise HTTPException(404,'Snapshot is not in this approved service backup set')

    def quiesced(self,profile):
        config=self.config['backup_profiles'][profile['name']]
        target=config.get('runtime',{});handle=target.get('handle',{})
        if not handle or not self.observer:raise HTTPException(409,'Restore/consistent backup needs a locally configured observable runtime')
        rows=self.observer().get('services',[])
        matches=[row for row in rows if row.get('runtime')==target.get('runtime') and all(row.get('control_handle',{}).get(k)==v for k,v in handle.items())]
        if len(matches)!=1 or matches[0].get('status')!='stopped':raise HTTPException(409,'The approved runtime must be observed stopped before copying data')

    def tree(self,profile,identifier):
        self.selected(profile,identifier)
        try:records=[json.loads(line) for line in self.run(profile,['ls',identifier]).splitlines() if line.strip()]
        except ValueError:raise HTTPException(502,'Invalid snapshot file metadata')
        rows=[]; size=0
        for row in records:
            if row.get('struct_type')!='node':continue
            path=PurePosixPath(row.get('path',''))
            if not path.is_absolute() or '..' in path.parts or row.get('type') not in ('file','dir') or row.get('links',1)>1:
                raise HTTPException(403,'Snapshots containing unsafe paths, links or special files cannot be restored')
            if row.get('type')=='file':
                allowed=[PurePosixPath('/'+p.as_posix().replace(':','').lstrip('/')) for p in profile['roots']]
                document=PurePosixPath('/'+self.document_path(profile).as_posix().replace(':','').lstrip('/'))
                if path!=document and not any(path.is_relative_to(root) for root in allowed):
                    raise HTTPException(403,'Snapshot contains files outside the currently approved roots')
            size+=int(row.get('size',0))
            rows.append({'path':str(path),'type':row['type'],'size':row.get('size',0)})
            if len(rows)>profile['max_files'] or size>profile['max_bytes']:raise HTTPException(413,'Restore exceeds the locally approved file/byte budget')
        if not rows:raise HTTPException(409,'Snapshot has no reviewable regular files')
        return rows

    def preview(self,name,identifier):
        profile=self.profile(name)
        if not profile['allow_restore']:raise HTTPException(403,'Restore needs separate local profile approval')
        rows=self.tree(profile,identifier)
        return {'snapshot':identifier,'files':rows,'fingerprint':digest({'profile':profile['fingerprint'],'snapshot':identifier,'files':rows}),
                'notice':'Mandatory current-data safety snapshot precedes all overwrites; extra current files are preserved.'}

    def document_path(self,profile):
        return self.replay.path.parent/'backup-notebooks'/(profile['name']+'.md')

    def backup(self,profile,documentation='',safety=False):
        tag='hearth-safety' if safety else 'hearth-data'
        paths=[str(p) for p in profile['roots']]
        if documentation:
            target=self.document_path(profile)
            if target.parent.is_symlink() or target.is_symlink():raise HTTPException(403,'Unsafe private notebook staging path')
            target.parent.mkdir(mode=0o700,exist_ok=True)
            fd,temporary=tempfile.mkstemp(dir=target.parent,prefix='note-')
            try:
                with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(documentation)
                os.replace(temporary,target)
            finally:
                if os.path.exists(temporary):os.unlink(temporary)
            paths.append(str(target))
        args=['backup','--tag','hearth:'+profile['name'],'--tag',tag,'--',*paths]
        try:rows=[json.loads(line) for line in self.run(profile,args).splitlines() if line.strip()]
        except ValueError:raise HTTPException(502,'Invalid backup result')
        summary=next((r for r in reversed(rows) if r.get('message_type')=='summary'),{})
        identifier=summary.get('snapshot_id','')
        if not re.fullmatch(r'[a-f0-9]{8,64}',identifier):raise HTTPException(502,'Restic did not confirm a completed snapshot')
        matches=[row['id'] for row in self.snapshots(profile) if row['id'].startswith(identifier)]
        if len(matches)!=1:raise HTTPException(409,'Completed snapshot identity could not be resolved in this service backup set')
        identifier=matches[0]
        return {'snapshot_id':identifier,'size_bytes':summary.get('total_bytes_processed'),'safety':safety,'documentation_included':bool(documentation)}

    def restore(self,profile,identifier):
        self.quiesced(profile)
        preview=self.preview(profile['name'],identifier)
        # Record current file identities so ordinary concurrent local changes are not
        # overwritten after the safety snapshot. No links or special files allowed.
        def current_files():
            result={};started=time.monotonic()
            for root in profile['roots']:
                for path in root.rglob('*'):
                    info=path.lstat()
                    if path.is_symlink() or getattr(path,'is_junction',lambda:False)() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or info.st_nlink>1 and path.is_file():
                        raise HTTPException(403,'Restore refuses existing links or special files')
                    if path.is_file():
                        result[str(path)]=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
                    if len(result)>profile['max_files'] or time.monotonic()-started>30:raise HTTPException(413,'Existing restore tree exceeds review budget')
            return result
        before=current_files()
        safety=self.backup(profile,safety=True)
        self.remember(profile,{'safety_snapshot_id':safety['snapshot_id'],'snapshot_id':identifier,'phase':'safety-snapshot-complete'})
        with tempfile.TemporaryDirectory(dir=self.replay.path.parent,prefix='restore-stage-') as folder:
            stage=Path(folder)
            self.run(profile,['restore',identifier,'--target',str(stage),'--verify'])
            candidates=[];documentation=None;staged_bytes=0
            for path in stage.rglob('*'):
                info=path.lstat()
                if path.is_symlink() or getattr(path,'is_junction',lambda:False)() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or path.is_file() and info.st_nlink>1:
                    raise HTTPException(403,'Restored archive contains unsafe filesystem entries')
                if path.is_file():
                    staged_bytes+=info.st_size
                    if staged_bytes>profile['max_bytes'] or len(candidates)>profile['max_files']:raise HTTPException(413,'Staged restore exceeds approved budget')
                    # restic stores absolute POSIX paths under staging; Windows
                    # drive roots become /C/..., as in restic's ls output.
                    relative=path.relative_to(stage).as_posix()
                    document=self.document_path(profile).as_posix().replace(':','').lstrip('/')
                    if relative==document:
                        if info.st_size>100000:raise HTTPException(413,'Restored notebook exceeds its budget')
                        documentation=redact(path.read_text(encoding='utf-8'))
                        continue
                    matching=[]
                    for root in profile['roots']:
                        parts=root.as_posix().replace(':','').lstrip('/')
                        prefix=PurePosixPath(parts)
                        try:tail=PurePosixPath(relative).relative_to(prefix)
                        except ValueError:continue
                        matching.append(root/Path(str(tail)))
                    if len(matching)!=1:raise HTTPException(403,'Snapshot file falls outside approved restore roots')
                    candidates.append((path,matching[0]))
            if not candidates or current_files()!=before:raise HTTPException(409,'Data changed during staging; no restore files were installed')
            if self.profile(profile['name'])['fingerprint']!=profile['fingerprint']:raise HTTPException(409,'Mount or profile changed before restore')
            self.quiesced(profile)
            self.remember(profile,{'safety_snapshot_id':safety['snapshot_id'],'snapshot_id':identifier,'phase':'installing-reviewed-files'})
            for source,target in candidates:
                # Recheck every existing ancestor before an atomic file overlay.
                if any(p.exists() and (p.is_symlink() or getattr(p,'is_junction',lambda:False)()) for p in (target,*target.parents)):
                    raise HTTPException(403,'Restore destination changed to a linked path')
                if target.exists():
                    info=target.stat()
                    if before.get(str(target))!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns):raise HTTPException(409,'Current file changed during restore; inspect the safety snapshot and partial result')
                elif str(target) in before:raise HTTPException(409,'Current file disappeared during restore')
                target.parent.mkdir(parents=True,exist_ok=True)
                fd,temporary=tempfile.mkstemp(prefix='.hearth-restore-',dir=target.parent)
                preserve_candidate=False
                try:
                    with os.fdopen(fd,'wb') as output,source.open('rb') as stream:
                        shutil.copyfileobj(stream,output,1024*1024);output.flush();os.fsync(output.fileno())
                    candidate=Path(temporary);system=platform.system();existing=target.exists()
                    metadata_source=target if existing else source
                    permissions=security(metadata_source,system)
                    if hasattr(os,'getuid') and metadata_source.stat().st_uid!=os.getuid():raise HTTPException(403,'Agent must own restored source and existing target files')
                    shutil.copystat(metadata_source,candidate,follow_symlinks=False)
                    copy_metadata(metadata_source,candidate,system,permissions)
                    if system=='Linux' and hasattr(os,'listxattr'):
                        if {key:os.getxattr(metadata_source,key) for key in os.listxattr(metadata_source)}!={key:os.getxattr(candidate,key) for key in os.listxattr(candidate)}:raise HTTPException(409,'Existing extended permissions could not be preserved')
                    if security(metadata_source,system)!=permissions:raise HTTPException(409,'File permissions changed during restore preparation')
                    if not existing and system!='Windows':os.chmod(candidate,stat.S_IMODE(source.stat().st_mode)&0o700)
                    if existing:replace_preserving_metadata(candidate,target,system,permissions)
                    else:os.replace(candidate,target)
                except ReplacementUncertain:
                    preserve_candidate=True
                    raise HTTPException(503,'Native replacement is uncertain; candidate/recovery evidence and safety snapshot retained for inspection')
                finally:
                    if not preserve_candidate and os.path.exists(temporary):os.unlink(temporary)
        return {'snapshot_id':identifier,'safety_snapshot_id':safety['snapshot_id'],'restored_files':len(candidates),'extra_files_preserved':True,'documentation':documentation}

    def request(self,body):
        profile=self.profile(body.profile)
        if not body.confirmed or body.fingerprint!=profile['fingerprint']:raise HTTPException(409,'Review and confirm the current backup profile')
        if redact(body.documentation)!=body.documentation:raise HTTPException(422,'Backup documentation must not contain credential values')
        if body.action=='restore' and not profile['allow_restore'] or body.action=='retention' and not profile['allow_retention']:
            raise HTTPException(403,'This backup operation is not approved locally')
        if body.action=='restore':self.tree(profile,body.snapshot)
        if body.action=='retention':
            selected=self.retention_plan(profile,body.keep_daily,body.keep_weekly)
            if selected['fingerprint']!=body.retention_fingerprint:raise HTTPException(409,'Retention candidates changed; review the current removal set')
        if body.action=='backup':
            if body.mode=='live' and not profile['live_allowed']:raise HTTPException(403,'Live backups are only approved for explicitly static source profiles')
            if body.mode=='stop-copy-start':self.quiesced(profile)
        with self.lock,self.db() as db:
            if db.execute('SELECT 1 FROM backup_intents WHERE active=1').fetchone():raise HTTPException(409,'Another backup intent is active or uninspected')
            try:db.execute('INSERT INTO backup_intents(id,profile,status,active) VALUES(?,?,?,1)',(body.operation_id,body.profile,'running'))
            except sqlite3.IntegrityError:raise HTTPException(409,'Backup intent was already used; automatic replay is refused')
        status='unknown'
        try:
            if body.action=='backup':result=self.backup(profile,body.documentation)
            elif body.action=='restore':result=self.restore(profile,body.snapshot)
            else:
                # No prune: deletion is restricted to this set, reviewed separately,
                # and safety snapshots are never eligible for retention removal.
                # Delete only the immutable IDs shown in the approved dry run.
                # Re-evaluating a policy here could select newly arrived snapshots.
                if selected['remove']:
                    self.run(profile,['forget','--',*selected['remove']])
                if set(selected['remove']).intersection(row['id'] for row in self.snapshots(profile)):raise HTTPException(409,'Retention result could not be verified')
                result={'retention_applied':True,'safety_snapshots_preserved':True,'pruned':False}
            status='success'
            self.remember(profile,{k:v for k,v in result.items() if k in ('snapshot_id','safety_snapshot_id','restored_files','size_bytes','retention_applied')})
            return result|{'status':status,'operation_id':body.operation_id}
        finally:
            with self.db() as db:
                db.execute('UPDATE backup_intents SET status=?,active=? WHERE id=?',(status,0 if status=='success' else 1,body.operation_id))

    def acknowledge(self,body):
        if not self.replay:raise HTTPException(403,'Backup inspection requires signed private state')
        if not body.confirmed:raise HTTPException(409,'Inspect the host and repository before clearing an uncertain backup intent')
        with self.lock,self.db() as db:
            row=db.execute('SELECT status FROM backup_intents WHERE id=?',(body.operation_id,)).fetchone()
            if row and row[0]=='running':raise HTTPException(409,'Backup dispatch is still in flight; wait for its tool result before acknowledgement')
            if row:db.execute('UPDATE backup_intents SET active=0 WHERE id=?',(body.operation_id,))
            else:
                # Tombstone an unreceived request so an old delayed packet cannot
                # execute after the controller owner releases its uncertain hold.
                db.execute("INSERT INTO backup_intents(id,profile,status,active) VALUES(?,'unreceived','acknowledged',0)",(body.operation_id,))
        return {'status':'acknowledged','outcome_verified':False}
