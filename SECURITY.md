# Security Policy

This repository intentionally includes vulnerable benchmark applications for security testing and evaluation.

## Policy Scope

In-scenario vulnerabilities in benchmark apps are expected behavior and are not considered security defects for this repository.

Examples of intentional benchmark behavior:

- broken access control
- injection flaws
- weak token handling
- insecure object references
- mass assignment

Please report issues that affect the repository, tooling, or supply chain instead.

Examples of in-scope reports:

- accidental exposure of real credentials or private keys
- vulnerable CI/CD or dependency-chain risks in project infrastructure
- unsafe automation that can impact systems outside benchmark scope
- repository permission or disclosure issues

## Legal Disclaimer

These benchmarks are provided for educational and security research purposes only.

The maintainers are not responsible for any misuse, damage, or legal consequences resulting from:

- deploying these applications in production environments
- exposing them to public networks
- using them for unauthorized testing against third-party systems

Users are solely responsible for complying with applicable laws and regulations.

## Threat Model

These benchmarks are designed to simulate real-world API vulnerabilities including:

- authorization bypass scenarios (BOLA, BFLA)
- business logic abuse
- token misuse and trust violations
- data exposure patterns

They are intended to test:
- API security scanners
- behavior analysis systems
- detection and triage workflows

## Acceptable Use

You may:

- run benchmarks locally or in isolated lab environments
- use them to evaluate security tools
- modify scenarios for research purposes

You must NOT:

- deploy benchmarks to publicly accessible environments
- use them to attack real systems
- integrate them into production pipelines

## Researcher Notes

If you are evaluating these benchmarks:

- vulnerabilities are intentionally present and should be discoverable
- focus on detection capability, not exploit novelty
- some scenarios may require multi-step interaction flows

False positives or unclear behavior should be reported.

## Out of Scope

The following are explicitly out of scope:

- vulnerabilities inside benchmark scenarios
- exploitation of intentionally vulnerable endpoints
- denial-of-service attacks against benchmark apps
- findings that require modifying benchmark assumptions

These are expected behaviors and will not be treated as valid reports.

## Stability Notice

Benchmarks may change over time to improve realism or coverage.

- vulnerability patterns may evolve
- APIs and endpoints may be updated
- backward compatibility is not guaranteed

## Environment Isolation Requirements

Benchmarks must be executed in isolated environments:

- containerized environments (Docker recommended)
- no outbound internet access unless explicitly required
- no access to internal or production systems

Failure to isolate environments may result in unintended security exposure.

## Data Safety

All data used in benchmarks is synthetic.

- no real user data is included
- no production credentials are used
- all tokens, keys, and flags are generated for testing purposes only

## Benchmark Integrity

Do not patch or remove vulnerabilities unless explicitly required for testing.

These scenarios are designed to remain vulnerable by design.

## How To Report

Use a private disclosure channel:

1. Open a private vulnerability report using GitHub Security Advisories ("Report a vulnerability").
2. If private reporting is unavailable, open a normal issue with minimal detail and request a private contact channel.

Do not post exploit details publicly before maintainers confirm triage.

## Report Classification

Reports are evaluated based on impact:

- High: Issues affecting repository security, infrastructure, or external systems
- Medium: Issues in tooling or configurations with limited impact
- Low: Documentation issues or minor inconsistencies

Reports related to intentional benchmark vulnerabilities will be closed as "by design".

## Response Targets

Maintainers aim to:

- acknowledge receipt within 3 business days
- provide initial triage within 7 business days
- share status updates at least every 14 days until resolution

Timelines are targets, not guarantees.

## Coordinated Disclosure

Please allow maintainers reasonable time to investigate and remediate before public disclosure.
When a fix is available, maintainers may publish an advisory and release notes.

## Intended Audience

This repository is intended for:

- security engineers
- API security tool developers
- researchers evaluating detection capabilities
- organizations testing defensive systems

It is not intended for general-purpose application deployment.

## Safe Use Requirements

- Do not deploy these benchmarks in production
- Do not expose them to the public internet
- Run them only in isolated local or lab environments
- Use synthetic credentials, flags, and data only

## Security Contact

For sensitive disclosures, you may also contact:

- Email: security@apyguard.com

Please avoid sharing sensitive details in public issues.