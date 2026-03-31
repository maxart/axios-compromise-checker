# Axios NPM Supply Chain Attack — Incident Response

## Summary

On **March 30-31, 2026**, malicious versions **`axios@1.14.1`** and **`axios@0.30.4`** were published to npm after maintainer account `jasonsaayman` was compromised. A hidden dependency (`plain-crypto-js@4.2.1`) ran a postinstall script that deployed a cross-platform Remote Access Trojan (RAT). The payload executed within seconds of `npm install` and then self-deleted evidence. The malicious versions were live on npm for approximately **2-3 hours** before being removed.

## Affected Versions

| Package | Compromised | Safe |
|---|---|---|
| axios | 1.14.1 | 1.14.0 |
| axios | 0.30.4 | 0.30.3 |
| plain-crypto-js | 4.2.1 (phantom dep) | N/A — should not exist |

## Attack Flow

1. `npm install` triggers `postinstall` hook in `plain-crypto-js@4.2.1`
2. Obfuscated `setup.js` contacts C2 server
3. Platform-specific RAT payload is downloaded and executed
4. Malicious `package.json` is replaced with a clean stub to hide evidence

## Indicators of Compromise (IOCs)

### Network

| Type | Value |
|---|---|
| Domain | `sfrclak.com` |
| IP | `142.11.206.73` |
| C2 endpoint | `http://sfrclak.com:8000/6202033` |

### POST Body Identifiers

| Platform | Identifier |
|---|---|
| macOS | `packages.npm.org/product0` |
| Windows | `packages.npm.org/product1` |
| Linux | `packages.npm.org/product2` |

### Dropped Payloads

| OS | File Path | Notes |
|---|---|---|
| macOS | `/Library/Caches/com.apple.act.mond` | Persistent |
| Windows | `%PROGRAMDATA%\wt.exe` | Persistent |
| Windows | `%TEMP%\6202033.vbs` | Temp, self-deletes |
| Windows | `%TEMP%\6202033.ps1` | Temp, self-deletes |
| Linux | `/tmp/ld.py` | |

### Package Hashes

| Package | SHA |
|---|---|
| axios@1.14.1 | `2553649f232204966871cea80a5d0d6adc700ca` |
| axios@0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js@4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### Attacker Accounts

| Account | Email |
|---|---|
| jasonsaayman (compromised) | `ifstap@proton.me` |
| nrwise (attacker-created) | `nrwise@proton.me` |

## Remediation Steps

### 1. Containment

- Isolate the affected machine from the network
- Kill any active RAT payload processes
- Block `sfrclak.com` and `142.11.206.73` at firewall/DNS

### 2. Credential Rotation

Rotate **every secret** accessible from the compromised machine:

- npm / registry tokens
- SSH keys (regenerate, remove old public keys)
- AWS / GCP / Azure credentials
- CI/CD secrets (GitHub Actions, GitLab CI, etc.)
- Database credentials
- API keys and service tokens
- Browser-stored passwords

### 3. Cleanup

- Pin axios to `1.14.0` or `0.30.3`
- Remove `node_modules/plain-crypto-js`
- Clean reinstall: `rm -rf node_modules && npm ci --ignore-scripts`
- Delete dropped payloads from disk
- If RAT persisted (especially `wt.exe` on Windows), consider a clean OS reinstall

### 4. Prevention

Add to `~/.npmrc`:

```ini
ignore-scripts=true
min-release-age=7
```

Other package managers:

- **pnpm**: `minimum-release-age=10080` (minutes)
- **bun**: `minimumReleaseAge = 604800` (seconds)

Consider replacing axios with native `fetch()` (stable since Node.js v21).

## References

- [StepSecurity Blog Post](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Hacker News Discussion](https://news.ycombinator.com/item?id=47582220)
