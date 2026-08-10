# SOCProbe Team Contribution Record

This document supplements the Git history for the SOCProbe Sheridan College Cybersecurity Capstone project. It explains the development record in readable form while preserving the original commits, pull request, file lineage, and authorship metadata.

## Attribution basis

The record below uses three evidence sources:

1. Git author names and email addresses stored in each commit.
2. The files and line-level changes recorded by each commit.
3. Ahsan Siddiq's confirmation that the three early commits recorded as `unknown <Administrator@SOCLAB.LOCAL>` were his work.

The original Git history has not been rewritten. Git will continue to display those three early commits as `unknown`; this document provides the confirmed human attribution without altering historical metadata.

## Team and repository identities

| Team member | Git identities in the repository | Main repository-evidenced areas |
| --- | --- | --- |
| Ahsan Siddiq | `unknown <Administrator@SOCLAB.LOCAL>` (confirmed by Ahsan), `siddahsa`, `Ahsan Siddiq`, and GitHub user `a-sidd` | Initial local assessment prototype, Windows/AD collectors, scoring and reports, early UI and packaging experiments, Ahsan development versions, repository organization, final modular integration, release cleanup, documentation, and submission preparation |
| Syed Ahmed | `cybersyed` | Repository collaboration test, AD-account functionality, and the Entra-enabled `SOC_PROBE_v7.py` / `SOC_PROBE_v8_ENTRAworking.py` development line |
| Vaqas Mirza | `vaqasm` | First external pull request, UI v6, later application revision, configurable-controls interface line, and the source file that became the base lineage for the final `SOCProbe.py` entry point |

## Ahsan Siddiq

### Initial prototype and repository foundation

| Author date | Commit | What the commit records |
| --- | --- | --- |
| 2026-04-15 | [`f4e9cd6`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/f4e9cd6c02a995455e26a1eaa53be0097df7ba0c) | Created the initial SOCProbe capstone source. The commit added the local application entry point, Active Directory connection and assessment modules, privileged-group, stale-account, disabled-account, event-log and scoring logic, JSON/PDF report generation, configuration templates, multiple Tkinter UI prototypes, requirements, and an early PyInstaller build experiment. Git records the author as `unknown <Administrator@SOCLAB.LOCAL>`; Ahsan has confirmed this was his work. |
| 2026-04-16 | [`d0e04df`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/d0e04df9d1eeb930bb66f33a2841bce3fbf66d35) | Initialized the GitHub-facing repository record and added the first README through the `siddahsa` identity. |
| 2026-04-16 | [`5336168`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/533616821da4938ce98b3359749647cd28021602) | Recorded an early SOCProbe checkpoint. The commit has no material tree change, so it is treated as a historical marker rather than a separate feature contribution. Git records `unknown`; Ahsan confirms the commit was his. |
| 2026-04-16 | [`ec55683`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/ec55683bcbd112459ac1a820ef7de6f2961ff6d4) | Revised `main.py`, configuration loading, the activity simulator, and desktop UI. The diff records improvements across four runtime and interface files. Git records `unknown`; Ahsan confirms the commit was his. |

### Integration, organization, and Ahsan development line

| Author date | Commit | What the commit records |
| --- | --- | --- |
| 2026-06-02 | [`6c5390b`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/6c5390bcd8a63ca6dd9adbcf903369c223bf79bd) | Reviewed and merged Vaqas's first contribution through pull request 1. The contributed file itself remains attributed to Vaqas; Ahsan is credited for repository integration and merge administration. |
| 2026-06-05 | [`01422f7`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/01422f740cfdabbf829c2e94e48f6f1e08e7ff8b) | Moved the historical `launch_socprobe.pyw` launcher into the `Drafts` area. |
| 2026-06-05 | [`4612d45`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/4612d4513a75a50c7b7a4327c66a87a17b0a96dd) | Moved the early PyInstaller batch build script into `Drafts`. |
| 2026-06-05 | [`fef9e60`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/fef9e607f191b3db4676cfbb811ee88350dd99d5) | Moved the activity-simulator launcher into `Drafts`. |
| 2026-06-05 | [`cb738e1`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/cb738e1466f5c31e852c6cbcb4e7d0f8f9766c40) | Reorganized the earlier modular prototype under `Drafts` and added the 2,021-line `socprobe_ahsan_v1` development file. This separated historical work from the next active development line. |
| 2026-06-05 | [`fbcd890`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/fbcd890127fe893dc860a0d0040af3158a3ae3b5) | Renamed `socprobe_ahsan_v1` to `socprobe_ahsan_v1.py` and made two small source corrections. |
| 2026-06-05 | [`3b6ccfa`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/3b6ccfaf680dcb296f83e9417e139b8ad7979b7b) | Removed a redundant 570-line project explanation from the active repository. |
| 2026-06-05 | [`0e18327`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/0e18327276bbbd562e5ea7af7a5f8306aacf0af7) | Added the 37-line assessment configuration file used by that development stage. |
| 2026-06-07 | [`3e0fa9e`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/3e0fa9e590c071b891305edf1e21f98a7534f4ea) | Added draft JSON/PDF assessment output and score-history artifacts for review of the reporting workflow. |
| 2026-06-07 | [`4b1281e`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/4b1281ec79a9a6f6b67dd85a5da32de413a0fd17) | Removed those generated draft report artifacts after review so they would not remain as active source. |
| 2026-06-07 | [`61c5468`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/61c54688e4872191d9bae388a2c33620fd6086b4) | Added and revised Ahsan's v1, v2, and v3 development line, updated configuration, and added an HTML assessment report. The diff records 6,183 insertions and 2,028 deletions across the evolving application versions. |

### Final integration and release preparation

| Author date | Commit or milestone | What the record shows |
| --- | --- | --- |
| 2026-07-28 | [`91adb60`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/91adb60d01a2e42e3f130b246aaafb8443fd2aaf) | Performed the final large integration and repository cleanup. The commit renamed Vaqas's `Edit_controls_NEW(Vaqas).py` into `SOCProbe.py` and substantially revised it, removed historical single-file drafts from the current tree, and introduced the maintained modular structure: the 30-control SAF library, environment-aware assessment engine, Windows/AD/Entra/custom collectors, SQLite repository, profile and control-library interfaces, Entra configuration, and JSON/HTML reports. The commit records 4,288 insertions and 13,591 deletions across 54 files. |
| v4.2.1 release preparation | Current release-finalization changes | Corrected the stale-AD-user PowerShell collector and its failure handling; replaced the README with current installation, operation, architecture, database, security, limitations, troubleshooting, and version-control guidance; added this contribution record; expanded `.gitignore`; removed an obsolete environment note, unused methodology editor, and empty services package; synchronized visible and report version strings to 4.2.1; and prepared the source-only release for validation. |

## Syed Ahmed

| Author date | Commit | What the commit records |
| --- | --- | --- |
| 2026-06-02 | [`f02cfaa`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/f02cfaa66c7a712e89bee4348ff640397ad21c6e) | Updated the small `test1` collaboration file. This was a repository workflow contribution, not an application feature. |
| 2026-06-09 | [`d0f7da2`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/d0f7da24705912565ae1e15f20ec486a9df45bd5) | Added the 1,497-line `SOC_PROBE_v7.py` application version. The commit message identifies the addition of AD accounts-tab functionality and plans for Entra ID support. |
| 2026-06-09 | [`1216c3d`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/1216c3d97a57a03214269897cf1e342017899746) | Renamed v7 to `SOC_PROBE_v8_ENTRAworking.py` and expanded it by 278 insertions and 5 deletions, establishing Syed's Entra-enabled development line. |
| 2026-06-29 | [`f4ad65a`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/f4ad65ac226310db773a120ebc7764414126ecb3) | Made a final one-line adjustment to the Entra-working version. |

## Vaqas Mirza

| Author date | Commit | What the commit records |
| --- | --- | --- |
| 2026-06-02 | [`c1ee35c`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/c1ee35c26ce6fce52b62e7869bfddff2a4971f78) | Created the `test1` collaboration file through the branch later merged as pull request 1. This established the first external contribution workflow; it was not an application feature. |
| 2026-06-02 | [`ca372ac`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/ca372ac93fd0a86e86b6b21e8f4782b61cbbaa60) | Added the 1,243-line `socprobe_ui_v6(vaqas).py` interface development version. |
| 2026-07-03 | [`5162b37`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/5162b37a3d1c0b05d325ec9fa7e06d28cbcd4b4e) | Added the 688-line `socprobe_NEW (vaqas).py` application revision. |
| 2026-07-12 | [`0824d24`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/0824d2426938ddd1a3b23a945b1ec700ff9a4176) | Added the 1,678-line `Edit_controls_NEW.py` configurable-controls and interface development file. |
| 2026-07-12 | [`72473c8`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/72473c87dd85fc589aeff22ecbda82ea125b6b84) | Removed `Edit_controls_NEW.py` before correcting its filename and attribution. |
| 2026-07-12 | [`90461bb`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/90461bbefb58d6e439f96c007df55dbf28aafd18) | Re-added the same 1,678-line development file as `Edit_controls_NEW(Vaqas).py`. This file is the direct Git lineage renamed and substantially revised into the final `SOCProbe.py` entry point in Ahsan's July 28 integration commit. |

## Final maintained v4.2.1 source

The v4.2.1 release retains the team's development history while keeping only the maintained source and essential repository documentation in the current tree:

- `SOCProbe.py` desktop application entry point
- `assessment/engine.py` environment detection, applicability, orchestration, scoring, and report assembly
- `framework/saf_controls.py` 30 built-in SAF controls
- Windows, Active Directory, Microsoft Entra, and approved custom collectors
- SQLite methodology, profile, control, and assessment-history repository
- profile, control-library, and Entra configuration interfaces
- JSON and HTML report generation
- source installation and operating guidance in `README.md`
- this team contribution record

Historical prototypes, generated reports, databases, credentials, caches, compiled bytecode, packaging output, and obsolete empty modules are not kept in the release tree. Their earlier development remains visible through Git history.

## Verification

Repository views after the repository rename:

- [Main branch history](https://github.com/a-sidd/SOCProbe-Enterprise/commits/main/)
- [Contributor graph](https://github.com/a-sidd/SOCProbe-Enterprise/graphs/contributors)
- [Pull request 1](https://github.com/a-sidd/SOCProbe-Enterprise/pull/1)
- [Final pre-release integration milestone](https://github.com/a-sidd/SOCProbe-Enterprise/commit/91adb60d01a2e42e3f130b246aaafb8443fd2aaf)

Local verification commands:

```bash
git log --reverse --date=short --format="%h  %ad  %an <%ae>  %s"
git shortlog -sne --all
git show --stat 91adb60d01a2e42e3f130b246aaafb8443fd2aaf
```

## Interpretation note

Commit counts and line counts are not percentages of total project effort. Architecture discussions, framework design, testing, laboratory setup, documentation, presentation work, and team decisions may occur outside individual commits. This record therefore distinguishes verified repository changes from broader capstone participation and does not assign percentage ownership.
