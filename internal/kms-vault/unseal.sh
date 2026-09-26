#!/bin/bash

for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-1 vault operator unseal "$token"
  docker exec prod-vault-2 vault operator unseal "$token"
  docker exec prod-vault-3 vault operator unseal "$token"
done

docker exec prod-vault-1 vault
docker exec prod-vault-2 vault
docker exec prod-vault-3 vault
echo "vault 节点解封完成"

