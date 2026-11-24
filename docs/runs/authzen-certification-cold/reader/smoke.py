"""Own smoke checks of the 8 fixture rules and basic transport (no scenario test was read)."""
import json, sys, importlib.util
s = importlib.util.spec_from_file_location("p", sys.argv[1]); p = importlib.util.module_from_spec(s); s.loader.exec_module(p)
H = {"Content-Type": "application/json", "X-Request-ID": "r1"}
def ev(sub, act, res):
    st, h, b = p.handle("POST", "/access/v1/evaluation", H, json.dumps({"subject": sub, "action": act, "resource": res}).encode())
    return st, json.loads(b) if st == 200 else b.decode(), h.get("X-Request-ID")
A = {"type": "user", "id": "alice"}; B = {"type": "user", "id": "bob"}; R1 = {"type": "record", "id": "record-1"}
arch = {"type": "record", "id": "record-2", "properties": {"status": "archived"}}
cases = [(A, {"name": "read"}, R1, True), (A, {"name": "write"}, R1, True), (B, {"name": "read"}, R1, True), (B, {"name": "write"}, R1, False),
         (A, {"name": "write"}, arch, False), ({"type": "user", "id": "bob", "properties": {"role": "admin"}}, {"name": "write"}, arch, True),
         (A, {"name": "delete", "properties": {"soft": True}}, R1, True), (A, {"name": "delete", "properties": {"soft": False}}, R1, False)]
print([ev(*c[:3])[1]["decision"] == c[3] for c in cases])
print(p.handle("POST", "/access/v1/evaluation", {"Content-Type": "text/plain"}, b"{}")[0], p.handle("POST", "/access/v1/evaluation", H, b"{")[0], p.handle("GET", p.WELL_KNOWN, {}, b"")[0])
