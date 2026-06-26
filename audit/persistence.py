from __future__ import annotations
import json, os, tempfile
from dataclasses import asdict,is_dataclass
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime
STATE_VERSION=1
class StateLockError(RuntimeError): pass
@contextmanager
def file_lock(path):
 lock=Path(str(path)+".lock")
 try:
  fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
 except FileExistsError:
  raise StateLockError("state locked")
 try:
  yield
 finally:
  os.close(fd); os.unlink(lock)
def _default(o):
 if is_dataclass(o): return asdict(o)
 if isinstance(o,Path): return str(o)
 if isinstance(o,datetime): return o.isoformat()
 raise TypeError(type(o))
def save_raw(path,obj):
 path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
 with file_lock(path):
  d={"version":STATE_VERSION,"data":obj}
  fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=path.name,suffix=".tmp")
  with os.fdopen(fd,"w") as f: json.dump(d,f,default=_default,indent=2)
  os.replace(tmp,path)
def load_raw(path):
 path=Path(path)
 if not path.exists(): return {"version":STATE_VERSION,"data":{}}
 d=json.loads(path.read_text())
 if d.get("version")!=STATE_VERSION: d=migrate(d)
 return d["data"]
def migrate(doc):
 v=doc.get("version",0)
 while v<STATE_VERSION: v+=1
 doc["version"]=STATE_VERSION
 return doc
