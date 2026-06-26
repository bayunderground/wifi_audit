from audit.persistence import save_raw,load_raw
from pathlib import Path
p=Path("state/test.json")
save_raw(p,{"a":1})
assert load_raw(p)=={"a":1}
