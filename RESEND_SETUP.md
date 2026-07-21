# Emailing Reports with Resend

navi can now email reports through [Resend](https://resend.com) - no mail server, port or
mailbox password required. Once an operator does the one-time setup below, anyone running
`navi action mail` (or an email-capable Hound) only supplies the **recipient address**.

When a Resend key is present, navi uses it automatically. When no key is present, navi falls
back to the classic SMTP path (`navi config smtp`) - nothing about the old behavior changes.

navi uses the official [resend python library](https://github.com/resend/resend-python),
installed automatically with navi (`pip install resend` if you set navi up manually).

## One-time operator setup

1. Create a free account at https://resend.com and generate an API key (starts with `re_`).
2. Give navi the key **one** of these ways (never on a command line argument):

   ```
   export RESEND_API_KEY=re_xxxxxxxx
   ```

   or store it in navi's config database (prompted via getpass, never echoed):

   ```
   navi config resend
   ```

3. Optionally set the sender address:

   ```
   export HOUNDS_FROM=hounds@yourdomain.com
   ```

   or provide it when running `navi config resend`.

That's it. `navi action mail --to someone@example.com --file report.pdf` now works.

## Sender address and deliverability

- With no sender configured, navi uses `onboarding@resend.dev` - Resend's zero-setup testing
  sender. **This only delivers to the email address that owns your Resend account.** It is
  fine for trying things out, not for mailing your team.
- To send to arbitrary recipients you must verify a domain at https://resend.com/domains,
  then set `HOUNDS_FROM` (or `navi config resend`) to an address at that domain - for the
  launch, that means a verified `thehounds.ai` address, e.g. `HOUNDS_FROM=hounds@thehounds.ai`.

## How the key is resolved

Explicit function argument → `RESEND_API_KEY` environment variable → the `resend` table in
`navi.db` (written by `navi config resend`). The from-address resolves the same way:
argument → `HOUNDS_FROM` → config → `onboarding@resend.dev`.

## Security notes

- The API key is read via getpass or env - it never appears on a command line, in shell
  history or in process listings.
- No navi list/status command prints the key in cleartext; `navi config resend` confirms
  with only the last four characters.
- Reports go out as a PDF attachment **plus** a plaintext executive summary in the body, so
  recipients don't have to open an attachment blind.

## Troubleshooting

- `403` from Resend usually means you are sending from `onboarding@resend.dev` to someone
  other than yourself - verify a domain and set the sender.
- No key configured? navi prints a pointer to this file instead of a stack trace, and falls
  back to SMTP if that is configured.
