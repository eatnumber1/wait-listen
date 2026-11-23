#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write third_party/debian/lock.json: the exact Debian packages the build's
sysroots and test VMs are made of, each pinned by URL and SHA-256.

Trust chain: the snapshot's InRelease must carry a good signature from a key
in third_party/debian/keys/ (checked with gpgv); the Packages index must match
the SHA-256 InRelease gives for it; each package's SHA-256 is the index's.
snapshot.debian.org keeps every file forever, so the pins never rot.

  tools/debian_lock.py            # rewrite lock.json from lock-request.json
  tools/debian_lock.py --check    # exit 1 if lock.json differs (a test)

Run it only to move the pin (edit lock-request.json first); the build itself
never touches the network beyond the pinned URLs.
"""
import argparse
import hashlib
import json
import lzma
import os
import subprocess
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEB = os.path.join(ROOT, "third_party", "debian")
KEYS = os.path.join(DEB, "keys")


def fetch(url):
  with urllib.request.urlopen(url, timeout=120) as r:  # follows redirects
    return r.read()


def verified_inrelease(base, suite):
  data = fetch(f"{base}/dists/{suite}/InRelease")
  with tempfile.NamedTemporaryFile() as f:
    f.write(data)
    f.flush()
    # The archive signs with several keys at once (here also trixie's, which
    # our keyring may lack): gpgv then exits non-zero for the unknown one.
    # Accept a VALIDSIG from one of our keys, and refuse any BADSIG.
    for key in sorted(os.listdir(KEYS)):
      r = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", os.path.join(KEYS, key), f.name],
                         capture_output=True, text=True)
      status = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("[GNUPG:] ")]
      if "BADSIG" in status:
        sys.exit(f"{base}/dists/{suite}/InRelease: BAD signature")
      if "VALIDSIG" in status:
        return data.decode()
  sys.exit(f"{base}/dists/{suite}/InRelease: no good signature from a key in {KEYS}")


def index_sha256(inrelease, path):
  in_sha = False
  for line in inrelease.splitlines():
    if line.startswith("SHA256:"):
      in_sha = True
      continue
    if in_sha:
      if not line.startswith(" "):
        break
      digest, _size, name = line.split()
      if name == path:
        return digest
  sys.exit(f"InRelease lists no {path}")


def packages(base, suite, inrelease, component, arch):
  path = f"{component}/binary-{arch}/Packages.xz"
  data = fetch(f"{base}/dists/{suite}/{path}")
  if hashlib.sha256(data).hexdigest() != index_sha256(inrelease, path):
    sys.exit(f"{path}: SHA-256 doesn't match InRelease")
  out = {}
  for stanza in lzma.decompress(data).decode().split("\n\n"):
    fields = {}
    for line in stanza.splitlines():
      if line and not line[0].isspace() and ":" in line:
        k, v = line.split(":", 1)
        fields[k] = v.strip()
    if "Package" in fields:
      out[fields["Package"]] = fields
  return out


def resolve(request):
  base = f"https://snapshot.debian.org/archive/debian/{request['snapshot']}"
  inrelease = verified_inrelease(base, request["suite"])
  lock = {"snapshot": request["snapshot"], "suite": request["suite"], "packages": {}}
  for arch, names in sorted(request["packages"].items()):
    index = packages(base, request["suite"], inrelease, "main", arch)
    lock["packages"][arch] = {}
    for name in sorted(names):
      if name not in index:
        sys.exit(f"{request['suite']}/{arch} has no package {name}")
      p = index[name]
      lock["packages"][arch][name] = {
          "version": p["Version"],
          "url": f"{base}/{p['Filename']}",
          "sha256": p["SHA256"],
      }
  return lock


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--check", action="store_true")
  args = ap.parse_args()
  with open(os.path.join(DEB, "lock-request.json")) as f:
    request = json.load(f)
  text = json.dumps(resolve(request), indent=2, sort_keys=True) + "\n"
  path = os.path.join(DEB, "lock.json")
  if args.check:
    with open(path) as f:
      if f.read() != text:
        sys.exit("lock.json is out of date: run tools/debian_lock.py")
    return
  with open(path, "w") as f:
    f.write(text)


if __name__ == "__main__":
  main()
