"""Reconstitute the six exact public ACVP record bytes from the distributed nine-column TSV."""
from pathlib import Path
import csv
import hashlib
import json

EXPECTED="ffedf4bd0a25a2ea9d249ff02720db71431b3412587fa8f044cf3e29e13bcf7d"
def materialize(table:Path,out:Path)->Path:
    records=[]
    with table.open(encoding="utf-8",newline="") as f:
        for r in csv.DictReader(f,delimiter="\t"):
            case={"tcId":int(r["tcId"]),"testPassed":bool(int(r["testPassed"])),"deferred":False,"pk":r["pk"],"sk":r["sk"],
                  "message":r["message"],"context":r["context"],"hashAlg":"none","signature":r["signature"],"reason":r["reason"]}
            records.append({"p":int(r["parameter"]),"op":2,"t":case})
    encoded=json.dumps(records).encode("utf-8")
    if len(records)!=6 or hashlib.sha256(encoded).hexdigest()!=EXPECTED:
        raise ValueError("TSV does not reconstruct exactly the six frozen NIST public records")
    out.mkdir(exist_ok=True,parents=True);f=out/"nist-sigver-projection.json";f.write_bytes(encoded)
    return f
