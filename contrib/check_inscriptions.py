#!/usr/bin/env python3
"""Check fork-generated reveals against an isolated Bitcoin Core regtest node."""

import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    addresses = json.loads(subprocess.check_output(
        [str(fixture), "addresses"], text=True, timeout=30))
    assert len(addresses) == 6 and len(set(addresses)) == 6, addresses

    with tempfile.TemporaryDirectory(prefix="miniscript-inscriptions-") as directory:
        datadir = Path(directory)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        def rpc(method, params=(), wallet=False):
            cookie = (datadir / "regtest" / ".cookie").read_bytes().strip()
            endpoint = f"http://127.0.0.1:{port}"
            if wallet:
                endpoint += "/wallet/inscription-tests"
            request = Request(endpoint, data=json.dumps({
                "jsonrpc": "2.0", "id": "inscriptions", "method": method,
                "params": params,
            }).encode(), headers={
                "Authorization": "Basic " + base64.b64encode(cookie).decode(),
                "Content-Type": "application/json",
            })
            with urlopen(request, timeout=30) as response:
                result = json.load(response)
            if result.get("error"):
                if result["error"]["code"] == -28:
                    return None
                raise RuntimeError(f"{method}: {result['error']}")
            return result["result"]

        with (datadir / "console.log").open("w+") as console:
            node = subprocess.Popen([
                str(args.bitcoind.resolve()), "-regtest", f"-datadir={datadir}",
                "-server", "-listen=0", "-networkactive=0", "-dnsseed=0",
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", f"-rpcport={port}",
                "-fallbackfee=0.0002", "-printtoconsole=1",
            ], stdout=console, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if node.poll() is not None:
                        console.seek(0)
                        raise RuntimeError(console.read())
                    try:
                        if rpc("getblockchaininfo") is not None:
                            break
                    except (FileNotFoundError, URLError):
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Bitcoin Core did not become ready")
                    time.sleep(0.1)
                rpc("createwallet", ["inscription-tests"])
                mining_address = rpc("getnewaddress", wallet=True)
                rpc("generatetoaddress", [101, mining_address])
                txid = rpc("sendmany", ["", {address: 0.001 for address in addresses}], wallet=True)
                funding = rpc("gettransaction", [txid], wallet=True)["hex"]
                rpc("generatetoaddress", [1, mining_address])
                result = subprocess.run([str(fixture), "spends"], input=funding,
                                        text=True, capture_output=True, check=True, timeout=30)
                vectors = json.loads(result.stdout)
                assert len(vectors) == 26, len(vectors)
                accepted = 0
                for vector in vectors:
                    response = rpc("testmempoolaccept", [[vector["hex"]]])[0]
                    assert response.get("allowed") is vector["allowed"], (vector["name"], response)
                    if vector["reject_contains"]:
                        reason = response.get("reject-reason", "") + response.get("reject-details", "")
                        assert vector["reject_contains"] in reason, (vector["name"], response)
                    accepted += vector["allowed"]
                print(f"Bitcoin Core accepted {accepted} valid reveals and rejected {len(vectors) - accepted} invalid variants")
            finally:
                node.terminate()
                try:
                    node.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()


if __name__ == "__main__":
    main()
