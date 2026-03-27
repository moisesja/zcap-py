"""Resolve a did:key DID to its verification method — entirely offline, no network I/O."""

from zcap_py import resolve_did_key

vm = resolve_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

print(vm.id)  # did:key:z6Mk...#z6Mk...
print(vm.type)  # Ed25519VerificationKey2020
print(vm.controller)  # did:key:z6Mk...
print(vm.public_key_multibase)  # z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
