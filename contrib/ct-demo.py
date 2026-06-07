#!/usr/bin/env python3
import json, os, urllib.request, secrets

RPC = "http://u:p@127.0.0.1:18443/"

def call(method, params=None):
    body = json.dumps({"jsonrpc":"1.0","id":"ct","method":method,"params":params or []}).encode()
    req = urllib.request.Request("http://127.0.0.1:18443/", data=body,
        headers={"Content-Type":"text/plain"})
    import base64
    req.add_header("Authorization", "Basic "+base64.b64encode(b"u:p").decode())
    try:
        r = urllib.request.urlopen(req)
        return json.load(r)["result"]
    except urllib.error.HTTPError as e:
        return {"__error__": json.load(e)["error"]}

# --- pure-python secp256k1 pubkey derivation (one-off demo use only) ---
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def inv(a,m): return pow(a,m-2,m)
def add(p1,p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1,y1),(x2,y2)=p1,p2
    if x1==x2 and (y1+y2)%P==0: return None
    if p1==p2: lam=(3*x1*x1)*inv(2*y1,P)%P
    else: lam=(y2-y1)*inv(x2-x1,P)%P
    x3=(lam*lam-x1-x2)%P; y3=(lam*(x1-x3)-y1)%P
    return (x3,y3)
def mul(k):
    r=None; a=(Gx,Gy)
    while k:
        if k&1: r=add(r,a)
        a=add(a,a); k>>=1
    return r
def pubkey(priv_hex):
    x,y=mul(int(priv_hex,16))
    return ("02" if y%2==0 else "03")+format(x,"064x")

priv1=secrets.token_hex(32); priv2=secrets.token_hex(32)
pub1=pubkey(priv1); pub2=pubkey(priv2)

# 1. pick a mature coinbase UTXO
u = call("listunspent",[1,9999])
utxo = u[0]
txid, vout = utxo["txid"], utxo["vout"]
print(f"input: {txid}:{vout} = {utxo['amount']} BTC")

p1 = call("getnewaddress"); p2 = call("getnewaddress")
raw = call("createrawtransaction", [[{"txid":txid,"vout":vout}], [{p1:30},{p2:19.9999}]])

# 2. blind outputs 0,1; append explicit fee 0.0001
blinded = call("blindrawtransaction", [raw, [50.0],
    [{"vout":0,"pubkey":pub1},{"vout":1,"pubkey":pub2}], 0.0001])
print("blinded:", "ok" if isinstance(blinded,str) else blinded)

# 3. sign the explicit coinbase input
s = call("signrawtransactionwithwallet", [blinded])
print("sign complete:", s.get("complete"))
signed = s["hex"]

# 4. submit to the node -> consensus validates the commitment tally + range proofs
sent = call("sendrawtransaction", [signed])
print("sendrawtransaction ->", sent)

# 5. mine and inspect on-chain: outputs 0,1 hidden, output 2 explicit fee
call("generatetoaddress",[1, p1])
dec = call("getrawtransaction",[sent, True])
for o in dec["vout"]:
    v = o.get("value")
    conf = o.get("valuecommitment") or ("CONFIDENTIAL" if v in (None,-1,-1.0,"-0.00000001") else None)
    print(f"  vout[{o['n']}] value={v} {'(CONFIDENTIAL)' if (v in (None,) or (isinstance(v,(int,float)) and v<0)) else ''}")

# 6. unblind outputs with the receiver blinding keys
for idx,priv in ((0,priv1),(1,priv2)):
    r = call("unblindrawtransaction", [signed, idx, priv])
    print(f"  unblind vout[{idx}] with its key ->", r)
# wrong key fails
print("  unblind vout[0] with WRONG key ->", call("unblindrawtransaction",[signed,0,priv2]).get("__error__",{}).get("message"))
