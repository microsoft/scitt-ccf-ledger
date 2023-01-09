---
name: Release checklist
about: Issue for tracking the release of a new version
title: x.y.z release checklist
labels: release-checklist
assignees: ''

---

Checklist:
- [ ] Link this issue to the correct milestone for this version.
- [ ] Make sure all issues/PRs for the milestone are closed/merged.
- [ ] Create a PR to update `CHANGELOG.md`.
  - [ ] If this release upgrades CCF to the next major version, add the following note in the changelog:
         "In order to upgrade an existing service to this version, it must first be upgraded to the version preceding this version."
- [ ] Create a [release](https://github.com/microsoft/scitt-ccf-ledger/releases) with the new version number as git tag.
- [ ] Check that CI is green.
- [ ] Close the [milestone](https://github.com/microsoft/scitt-ccf-ledger/milestones) for this release.
- [ ] Close this issue.
