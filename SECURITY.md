# Security

## Reporting a vulnerability

Report privately, through this repository's **Security** tab →
**Report a vulnerability**. That opens a GitHub private security advisory,
visible only to you and the maintainer (edleft, the copyright holder — see
[`LICENSE`](LICENSE)).

CloudBasher is an independent personal project. There is no organization, vendor
security team or response SLA behind this address — reports are read by one
person.

Do not open a public issue for a security-sensitive report, exposed credentials,
or confidential information that has been published by accident. A public issue
is world-readable the moment it is filed and cannot be un-read.

## What is in scope

CloudBasher drives cloud provider CloudShell environments with credentials you
supply. Reports about the following are in scope:

- credential material reaching a surface it should not: the terminal, a pane,
  the process table inside a container, or a file written outside the intended
  paths;
- a defect in the masking or redaction pipeline;
- the encrypted session store (`state.bin`) being readable, forgeable, or
  weaker than documented;
- a way to make CloudBasher act as a principal the operator did not declare.

Reports about the following are **not** vulnerabilities in CloudBasher, though
they are worth knowing about:

- the log file containing unmasked text. This is deliberate and documented: it
  is a local audit trail, written with your umask, while the terminal may be
  screen-shared. Place it accordingly with `-l/--log`.
- behaviour of AWS, GCP or Azure CloudShell itself. Report those to the
  provider.

## Using this tool

CloudBasher automates access to cloud environments. Only test systems you own
or are explicitly authorized to test. The license grants intellectual-property
permission only; it is not authorization to access anything.

## Anything that is not a security report

| What | Where |
|---|---|
| Bugs, defects, technical problems | this repository's **Issues** |
| Questions, general inquiries | this repository's **Discussions** |
| Licensing, authorization requests, private matters | <cloudbasher@edleft.org> |

The licensing address is not monitored as a security channel. A vulnerability sent
there is slower to reach anyone than one filed as a private advisory.
