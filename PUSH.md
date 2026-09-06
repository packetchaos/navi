# Pushing Commands and Files with `navi action push`

`navi action push` runs a command on — or copies a file to — one or more Linux hosts over SSH.
It reads one SSH service account from navi's config, connects to each target in turn, reports the
remote exit status, and keeps going if a single host fails.

> This is remote code execution. Only point it at hosts you are authorized to administer.

## One-time credential setup[PUSH.md](PUSH.md)

Store an SSH service account once with `navi config ssh`. You can use a password, a private key,
or both:

```
# password auth
navi config ssh --username deploy

# key-based auth (press enter at the password prompt to leave it blank)
navi config ssh --username deploy --key ~/.ssh/id_ed25519
```

Credentials live in the `ssh` table of `navi.db`. If you upgraded from a build without key support,
re-run `navi config ssh` once so the new `key_file` column is created — until then push falls back
to password-only automatically, so nothing breaks.

## Flags

| Flag | Purpose |
|------|---------|
| `--command` | Command to run on the target(s), in double quotes. |
| `--file` | Local file to copy to the target(s). Mutually exclusive with `--command`. |
| `--dest` | Remote destination path for `--file`. Default `~/` (the SSH user's home). |
| `--run-after` | Command to run on each host *after* `--file` is copied (copy-then-run). Only valid with `--file`, and only runs if the copy succeeded. |
| `--target` | A single IP or a comma-separated list, e.g. `10.0.0.1,10.0.0.2`. |
| `--targets-file` | Path to a file with one target per line. Blank lines and `#` comments (including inline) are ignored. |
| `--key` | Path to an SSH private key, overriding the stored password for this run. |
| `--timeout` | Seconds to wait for a command or copy to finish. Default `300`. Raise it for large updates/installs. |
| `--wait-online` | After a reboot, wait up to N seconds for the host to come back before moving on. `0` (default) means don't wait. |
| `--wait-interval` | Seconds between reconnection probes while `--wait-online` polls. Default `15`. |
| `--log` | Append a per-host result row (timestamp, host, action, result, exit code, attempts, detail) to this file. |
| `--retries` | Retry a host up to N times on a *transport* failure (SSH couldn't connect). Default `0` (off). A command that ran and returned non-zero is never retried. |
| `--retry-base` | First retry delay in seconds; it doubles each attempt up to 60s. Default `5`. |

Supply `--command` or `--file` (not both), and at least one of `--target` / `--targets-file`.
Hosts from `--target` and `--targets-file` are merged and de-duplicated. Targets are processed
one at a time (a rolling operation), and one host failing does not stop the rest.

## Examples

Run a command on two hosts:

```
navi action push --target 10.0.0.1,10.0.0.2 --command "uptime"
```

Restart a service with sudo (the account password is fed to `sudo -S` on stdin, never echoed):

```
navi action push --target 10.0.0.5 --command "sudo systemctl restart nginx"
```

Run across a list of hosts from a file, using a private key for this run:

```
navi action push --targets-file webhosts.txt --key ~/.ssh/deploy_key --command "apt list --upgradable"
```

Copy a file to a specific directory on several hosts:

```
navi action push --target 10.0.0.1,10.0.0.2 --file patch.sh --dest /tmp/
```

### Automating reboots, updates and installs

Run a long software update, raising the timeout and logging every result:

```
navi action push --targets-file webhosts.txt \
  --command "sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade" \
  --timeout 1800 --log /var/log/navi-patch.tsv
```

Rolling reboot — reboot each host, wait up to 5 minutes for it to come back, then move to the next:

```
navi action push --targets-file webhosts.txt --command "sudo reboot" \
  --wait-online 300 --wait-interval 15 --log /var/log/navi-reboot.tsv
```

Copy an install script and run it in one call (copy-then-run):

```
navi action push --target 10.0.0.5 --file install.sh --dest /tmp/ \
  --run-after "sudo bash /tmp/install.sh" --timeout 900
```

A `--targets-file` looks like:

```
# Web tier
10.0.0.10
10.0.0.11   # canary

# DB tier (a line may itself be a comma-separated list)
10.0.1.20,10.0.1.21
```

## What you get back

For each host, push prints an audit line of what ran, the remote output, and a status line:

```
>> Running on 10.0.0.5: sudo systemctl restart nginx
  [OK] 10.0.0.5: exit 0
```

Non-zero exit codes are reported as `[FAIL] <host>: exit <n>`, and when more than one target is
supplied a final `succeeded / failed / total` summary is printed. File pushes report scp's own
exit status the same way. With `--log`, each host also gets a tab-separated row in the log file
(the `attempts` column shows how many tries it took when `--retries` is in play):

```
timestamp             host       action   result  exit_code  attempts  detail
2026-07-21T10:00:05   10.0.0.5   command  OK      0          1         sudo apt-get -y upgrade
2026-07-21T10:03:11   10.0.0.6   command  FAIL    100        1         sudo apt-get -y upgrade
2026-07-21T10:05:40   10.0.0.7   command  OK      0          2         sudo apt-get -y upgrade
```

## Notes and limits

- **Timeout:** `--timeout` (default 300s) governs how long push waits for a command or copy to
  finish. Full `apt`/`dnf` upgrades routinely exceed five minutes — raise it accordingly.
- **Retries (conservative):** `--retries N` retries a host only when the failure was a *transport*
  failure — the SSH connection couldn't be established, so the remote command never ran and a
  retry can't double-apply anything. A command that connected, ran, and returned a non-zero exit
  is treated as a real result and is **not** retried, because push can't know whether a
  non-idempotent command partially applied. Backoff is exponential (`--retry-base`, doubling up to
  60s), and the `attempts` count is printed and logged. Retries default to off.
- **Reboots:** a command containing `reboot`, `shutdown -r`, `init 6`, `halt` or `poweroff` is
  treated as a reboot: push issues it, treats the dropped SSH session as success, and (with
  `--wait-online N`) reconnects every `--wait-interval` seconds until the host answers again or N
  seconds pass. Because detection is by keyword, avoid these words in non-reboot commands (e.g. a
  path like `/opt/reboot-helper.sh`) or push will skip the exit-status check for that command.
- **Non-interactive:** push has no TTY to answer prompts, so make commands non-interactive —
  `DEBIAN_FRONTEND=noninteractive apt-get -y ...`, `dnf -y ...`. A command that stops to ask a
  question will hang until `--timeout`.
- **Passwordless sudo:** for unattended reboots/patching, a scoped sudoers `NOPASSWD` entry on the
  service account is cleaner and more reliable than storing the sudo password.
- **sudo:** commands containing `sudo` are rewritten to `sudo -S -p ''` so the password is read
  from stdin with no prompt. A wrong password makes `sudo -S` wait for more input, so the run will
  hit the timeout and report a failure rather than retrying.
- **Keys:** key-based auth currently assumes a passphraseless key (the usual automation case). A
  passphrase-protected key is not handled yet.
- **Exit sentinel:** push appends `; echo NAVI_EXIT:$?` to each non-reboot command to read the
  remote exit code. Avoid backgrounding the whole command (`cmd &`), which conflicts with the
  appended statement.
- **Host keys:** an unknown host key is accepted automatically on first connect so unattended runs
  don't hang on the prompt.
- **Scheduling:** to run on a schedule, invoke `navi action push` from cron or a systemd timer on
  the machine where navi runs (it needs `navi.db` and network reach to the targets).
