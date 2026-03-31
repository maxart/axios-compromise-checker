# axios NPM Supply Chain Attack - Detection & Response

On **March 30, 2026**, the popular [`axios`](https://www.npmjs.com/package/axios) npm package was compromised after a maintainer account was hijacked. Two malicious versions were published that silently installed a **Remote Access Trojan (RAT)** on any machine that ran `npm install`. The malicious versions were live on npm for approximately **2-3 hours** before being removed.

This repository provides **detection and cleanup scripts** for Windows, WSL (Windows Subsystem for Linux), Linux, and macOS. The scripts scan your system for indicators of compromise, help you clean up, and harden your environment against future attacks.

> **You do not need to be a developer to use these scripts.** Follow the steps for your platform:
> - [Windows (PowerShell)](#windows-powershell)
> - [WSL / Linux / macOS (Bash)](#wsl--linux--macos-bash)

---

## Am I affected?

You may be affected if **all** of the following are true:

1. You ran `npm install` (or `yarn install`, `pnpm install`) in **any** JavaScript/Node.js project between **March 31 ~00:21 UTC and ~03:15 UTC** (the ~3 hour window the malicious versions were live on npm)
2. Your project installed one of these specific versions:
   - `axios@1.14.1`
   - `axios@0.30.4`

**If you are on `axios@1.14.0` or `axios@0.30.3` (or any earlier version), you are not affected.**

### What the malware does

When you ran `npm install`, a hidden dependency called `plain-crypto-js` executed a script that:

1. Contacted a command-and-control server (`sfrclak.com`)
2. Downloaded a RAT (Remote Access Trojan) tailored to your operating system
3. Gave the attacker remote access to your machine
4. Deleted its own traces to avoid detection

The entire attack happened **within seconds** of running `npm install`.

---

## Quick start

Pick the script for your environment and follow the steps below.

### Windows (PowerShell)

This is the best option if you primarily develop on Windows outside of WSL.

1. **Open PowerShell as Administrator**
   - Press `Win + X` on your keyboard
   - Click **Terminal (Admin)** or **Windows PowerShell (Admin)**
   - If prompted by User Account Control, click **Yes**

2. **Download and run the script**
   ```powershell
   # Download the script
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/maxart/axios-compromise-checker/main/respond.ps1" -OutFile "$env:TEMP\respond.ps1"

   # Allow the script to run (this session only)
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

   # Run it
   & "$env:TEMP\respond.ps1"
   ```

3. **Follow the prompts** - the script will ask before making any changes

> **Already have the repo cloned?** Navigate to the folder and run `.\respond.ps1` directly.

### WSL / Linux / macOS (Bash)

This is the best option if you develop inside WSL, or on a Linux or macOS machine. On WSL, this script also checks the Windows side automatically.

1. **Open your terminal**
   - **WSL**: Open your Ubuntu/Debian terminal from the Start menu or Windows Terminal
   - **macOS**: Open Terminal (Applications > Utilities > Terminal)
   - **Linux**: Open your terminal emulator

2. **Download and run the script**
   ```bash
   # Download the script
   curl -fsSL "https://raw.githubusercontent.com/maxart/axios-compromise-checker/main/respond.sh" -o /tmp/respond.sh

   # Make it executable
   chmod +x /tmp/respond.sh

   # Run it
   /tmp/respond.sh
   ```

3. **Follow the prompts** - the script will ask before making any changes

> **Already have the repo cloned?** Navigate to the folder and run `./respond.sh` directly.

---

## What the scripts check

| Check | `respond.sh` (WSL/Linux/macOS) | `respond.ps1` (Windows) |
|---|:---:|:---:|
| RAT payload on Linux (`/tmp/ld.py`) | Yes | Yes (via WSL) |
| RAT payload on macOS (`/Library/Caches/com.apple.act.mond`) | Yes | Yes |
| RAT payload on Windows (`%PROGRAMDATA%\wt.exe`) | Yes (via mount) | Yes |
| Windows dropper artifacts (`%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`) | Yes (via mount) | Yes |
| Active network connections to C2 server | Yes | Yes |
| DNS cache for C2 domain | Yes | Yes |
| Hosts file blocking of C2 domain | Yes (Linux + Windows) | Yes |
| Scan all projects for compromised axios versions | Yes (recursive) | Yes (recursive) |
| Scan all projects for `plain-crypto-js` phantom dependency | Yes | Yes |
| Clean and reinstall compromised projects | Yes | Yes |
| Harden `.npmrc` to prevent future attacks | Yes (Linux + Windows) | Yes (Linux + Windows) |

---

## Script modes

Both scripts support three modes:

| Mode | Bash | PowerShell | Behavior |
|---|---|---|---|
| **Interactive** (default) | `./respond.sh` | `.\respond.ps1` | Prompts before every action |
| **Scan only** | `./respond.sh --scan-only` | `.\respond.ps1 -ScanOnly` | Reports findings, changes nothing |
| **Auto clean** | `./respond.sh --auto-clean` | `.\respond.ps1 -AutoClean` | Fixes everything without prompting |

**If you are unsure, use the default interactive mode.** It will explain each finding and ask before doing anything.

---

## If you are infected

If the scripts find indicators of compromise on your machine, you need to take these steps **immediately**:

### 1. Assume full compromise

The RAT had access to everything your user account could access. This includes files, credentials, environment variables, browser data, and SSH keys.

### 2. Rotate all credentials

Change **every password, token, and key** that was accessible from the infected machine:

- **npm tokens** - run `npm token revoke` and generate new ones at [npmjs.com](https://www.npmjs.com/settings/~/tokens)
- **SSH keys** - generate new keys (`ssh-keygen`) and remove old public keys from GitHub, GitLab, servers, etc.
- **Cloud credentials** - AWS, GCP, Azure access keys and secrets
- **CI/CD secrets** - GitHub Actions, GitLab CI, CircleCI, etc.
- **Database passwords**
- **API keys** for any services (Stripe, Twilio, SendGrid, etc.)
- **Browser-stored passwords** - change them on the websites directly, consider using a password manager

### 3. Check for persistence

If the Windows payload (`wt.exe`) was found **and was running**, the attacker may have installed additional backdoors. In that case, **a clean OS reinstall is the safest option**.

### 4. Monitor

- Watch for unauthorized access to your accounts over the next few weeks
- Enable 2FA/MFA on all services if you haven't already
- Check your email for password reset notifications you didn't request

---

## Prevention

The single most effective thing you can do is **disable npm lifecycle scripts** globally. This would have **completely blocked this attack**.

### npm

Add these lines to your `~/.npmrc` file (the scripts can do this for you):

```ini
ignore-scripts=true
min-release-age=7
```

Then when a project legitimately needs lifecycle scripts (e.g., for `node-gyp` native modules), run:

```bash
npm install --ignore-scripts=false
```

### pnpm

pnpm disables lifecycle scripts by default. To also set a minimum release age:

```ini
# .npmrc
minimum-release-age=10080
```

### bun

bun disables lifecycle scripts by default. To also set a minimum release age, add to `bunfig.toml`:

```toml
minimumReleaseAge = 604800
```

### Consider dropping axios entirely

Node.js has included a native `fetch()` API since **v21** (stable). If you're using a modern version of Node.js, you may not need axios at all:

```javascript
// Before (axios)
const { data } = await axios.get('https://api.example.com/data');

// After (native fetch)
const data = await fetch('https://api.example.com/data').then(r => r.json());
```

---

## Timeline

All times are UTC, March 30-31, 2026.

| Time | Event |
|---|---|
| Mar 30, 05:57 | `plain-crypto-js@4.2.0` published (clean decoy to build account history) |
| Mar 30, 23:59 | `plain-crypto-js@4.2.1` published with malicious `postinstall` hook |
| Mar 31, 00:21 | `axios@1.14.1` published via compromised maintainer account |
| Mar 31, 01:00 | `axios@0.30.4` published (39 minutes later) |
| Mar 31, ~03:15 | npm unpublished both malicious axios versions |
| Mar 31, 03:25 | npm placed security hold on `plain-crypto-js` |
| Mar 31, 04:26 | npm published security-holder stub replacing malicious package |

---

## Indicators of Compromise (IOCs)

For security teams, incident responders, or anyone who wants to check manually.

### Malicious packages

| Package | Version | SHA |
|---|---|---|
| axios | 1.14.1 | `2553649f232204966871cea80a5d0d6adc700ca` |
| axios | 0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js | 4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### Network indicators

| Type | Value |
|---|---|
| C2 domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 endpoint | `http://sfrclak.com:8000/6202033` |
| C2 POST body (macOS) | `packages.npm.org/product0` |
| C2 POST body (Windows) | `packages.npm.org/product1` |
| C2 POST body (Linux) | `packages.npm.org/product2` |

### File system indicators

| OS | Path | Notes |
|---|---|---|
| macOS | `/Library/Caches/com.apple.act.mond` | Persistent |
| Windows | `%PROGRAMDATA%\wt.exe` | Persistent |
| Windows | `%TEMP%\6202033.vbs` | Temp, self-deletes |
| Windows | `%TEMP%\6202033.ps1` | Temp, self-deletes |
| Linux | `/tmp/ld.py` | |

### Attacker accounts

| Account | Email |
|---|---|
| `jasonsaayman` (compromised maintainer) | `ifstap@proton.me` |
| `nrwise` (attacker-created) | `nrwise@proton.me` |

---

## Files in this repo

| File | Description |
|---|---|
| [`respond.sh`](respond.sh) | Bash script for WSL, Linux, and macOS |
| [`respond.ps1`](respond.ps1) | PowerShell script for Windows |
| [`INCIDENT.md`](INCIDENT.md) | Full technical incident report |
| [`README.md`](README.md) | This file |

---

## References

- [StepSecurity: Axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) - Original analysis
- [Hacker News Discussion](https://news.ycombinator.com/item?id=47582220) - Community discussion and additional mitigations

---

## Contributing

Found an issue or want to improve the scripts? PRs are welcome. Please test on the relevant platform before submitting.

## License

MIT - Use freely. If these scripts help you, consider starring the repo so others can find it.
