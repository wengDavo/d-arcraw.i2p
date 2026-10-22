"""
SAM validation harness for D'Arcraw. Validates sam_transport.py against a LIVE
I2P router's SAM bridge. It cannot run without a router.

Enable SAM first:
  I2P (Java):  router console -> I2P Internals -> Clients -> SAM application bridge -> Start
  i2pd:        set sam.enabled=true (and sam.address=127.0.0.1, sam.port=7656)

I2P tunnels take time to build, so the first cross-node call can take 30 to 60s.

Run: python3 sam_check.py
"""
import socket
import sys
import time

from gate import ContentGate, sha256
from netdb import Node

SAM_HOST, SAM_PORT = "127.0.0.1", 7656


def sam_up() -> bool:
    try:
        s = socket.create_connection((SAM_HOST, SAM_PORT), timeout=5)
        s.sendall(b"HELLO VERSION MIN=3.0 MAX=3.3\n")
        line = b""
        while not line.endswith(b"\n"):
            c = s.recv(1)
            if not c:
                break
            line += c
        s.close()
        return b"RESULT=OK" in line
    except Exception as e:
        print("   SAM not reachable:", e)
        return False


def main():
    print("1. SAM bridge reachable at %s:%d" % (SAM_HOST, SAM_PORT))
    if not sam_up():
        print("   FAIL. Enable the SAM application bridge in your router, then retry.")
        sys.exit(1)
    print("   OK")

    from sam_transport import SAMTransport
    gate = ContentGate(exact_hashes={sha256(b"BLOCKED")}, perceptual_hashes=[])

    print("2. Create two SAM sessions (two nodes)")
    t1 = SAMTransport("darcraw-a")
    t2 = SAMTransport("darcraw-b")
    n1 = Node(t1, gate, difficulty=8, replication=2)
    n2 = Node(t2, gate, difficulty=8, replication=2)
    print("   node A:", n1.me.destination[:20], "...")
    print("   node B:", n2.me.destination[:20], "...")
    print("   distinct destinations:", n1.me.destination != n2.me.destination)

    n1.learn(n2.me)
    n2.learn(n1.me)

    print("3. Publish on A, fetch from B over I2P (first tunnel build is slow)")
    good = b"an intense but lawful shitpost"
    cid = n1.publish(good)
    got = None
    for _ in range(6):
        got = n2.get(cid)
        if got is not None:
            break
        time.sleep(10)
    print("   cross-node lookup over SAM:", got == good)

    print("4. Gate still blocks over SAM")
    print("   blocked content refused:", n1.publish(b"BLOCKED") is None)

    t1.stop()
    t2.stop()
    print("done.")


if __name__ == "__main__":
    main()
