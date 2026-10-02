# KODA Security Policy

Reviewed: 2026-10-02

## Supported source

Security maintenance targets the latest `main` source. An installed app or offline
package must be checked against its build revision; this policy does not promise
that earlier binaries contain changes from a local development checkout.

## Reporting a vulnerability

Do not publish credentials, private source, exploit details, or sensitive scan
reports in a public issue.

GitHub private vulnerability reporting was **disabled** when checked on
2026-10-02. The old `security@example.com` address was a placeholder and is not
a reporting channel. No dedicated private contact address is currently listed
in this repository.

Use the [repository](https://github.com/jhny-kor/KODA) to check for an updated
reporting channel. If none is available, open a minimal public issue requesting
a confidential contact route, without vulnerability details or attachments.
Share details only after the maintainer provides that route. If private reporting
is enabled later, use the repository's **Security → Report a vulnerability** form.

## Handling

1. Confirm the report and assign an owner.
2. Reproduce it in an isolated environment.
3. Prepare a patch and regression evidence; record compatibility changes and
   integration checks that could not run.
4. Release the fix and rotate any exposed credentials.
5. Publish an advisory after users have a remediation path.

For development status and current verification boundaries, see the
[implementation snapshot](docs/current-status.en.md).
For Korean, see [SECURITY.ko.md](SECURITY.ko.md).
