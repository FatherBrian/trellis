# A local Keycloak for the "Bring your own IdP" demo

`trellis-realm.json` is a demo realm, `trellis`, with throwaway secrets. Never use it
outside a laptop.

- **People:** ana@example.com (password `ana-demo`) and tom@example.com (`tom-demo`). They
  sign in through the public client `trellis-cli`; their tokens are for audience `trellis`.
- **Agents:** `report-bot`, `inspector-bot` and `rogue-bot` sign in with client
  credentials. `rogue-bot` isn't in Trellis's agent registry, so Trellis refuses it.
- **Trellis's own client:** `trellis` (secret `trellis-demo-secret`) may use standard token
  exchange to get a token for `ledger-mcp`, a downstream server, that still names the person.

```bash
docker run -d --name trellis-keycloak -p 8183:8080 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_HOSTNAME=http://localhost:8183 \
    -v "$PWD/examples/idp/keycloak:/opt/keycloak/data/import:ro" \
    keycloak/keycloak:26.4.0 start-dev --import-realm
```
