Ruleset definitions for GH-TEST-01 (synthetic dry run). Written for the REST endpoint
POST /repos/{owner}/{repo}/rulesets. Not verified against GitHub yet (NV):
- actor_id 1 with actor_type OrganizationAdmin, and bypass_mode "pull_request".
- integration_id 15368 as the GitHub Actions app.
- No push ruleset: GitHub documents push rulesets for private and internal repositories only,
  so DT-10 is NOT APPLICABLE on a public Free repository.
