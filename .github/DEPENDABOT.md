# Dependabot Configuration

This repository uses [Dependabot](https://docs.github.com/en/code-security/dependabot) to automatically keep dependencies up to date.

## What's Monitored

The Dependabot configuration (`.github/dependabot.yml`) monitors:

1. **Go Modules** (`go.mod`)
   - Checks for updates to Go dependencies weekly
   - Opens up to 10 PRs at a time
   - Labels: `dependencies`, `go`

2. **GitHub Actions** (`.github/workflows/*.yaml`)
   - Checks for updates to GitHub Actions weekly
   - Opens up to 5 PRs at a time
   - Labels: `dependencies`, `github-actions`

3. **Docker** (`Dockerfile`)
   - Checks for updates to base images weekly
   - Opens up to 5 PRs at a time
   - Labels: `dependencies`, `docker`

## Schedule

All dependency checks run **weekly on Mondays**.

## Testing the Configuration

To validate the Dependabot configuration locally:

```bash
./scripts/validate-dependabot.sh
```

This script checks:
- YAML syntax validity
- Required fields presence
- Configuration structure

## How It Works

1. Dependabot scans the repository on the configured schedule
2. When updates are found, it creates pull requests automatically
3. Each PR includes:
   - Updated dependency version
   - Changelog information (when available)
   - Compatibility score
   - Appropriate labels

4. The existing CI/CD pipeline (`.github/workflows/test.yaml`) will run tests on Dependabot PRs
5. Review and merge PRs that pass all checks

## Commit Message Format

Dependabot PRs use the commit message format:
```
chore(scope): update dependency-name from x.y.z to a.b.c
```

This aligns with the repository's existing commit conventions (as seen in recent commits like `cdb0dd4`).

## Managing Dependabot PRs

### Auto-merge (Optional)
You can enable auto-merge for Dependabot PRs that pass all checks:
```bash
gh pr merge <PR-NUMBER> --auto --squash
```

### Ignoring Updates
To ignore a specific dependency version:
```bash
@dependabot ignore this major version
@dependabot ignore this minor version
@dependabot ignore this dependency
```

### Rebasing PRs
If a Dependabot PR becomes stale:
```bash
@dependabot rebase
```

## References

- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Configuration Options](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
