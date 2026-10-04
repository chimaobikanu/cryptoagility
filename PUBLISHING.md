# Publishing CryptoAgility

Everything is prepared. Nothing has been pushed — this environment has no GitHub or PyPI credentials, and making
source public is irreversible, so the last step is yours to run.

## Pre-flight checklist

- [ ] `./.venv/bin/python -m pytest tests -q` — all 53 tests pass
- [ ] `./.venv/bin/cryptoagility sample --cbom /tmp/c.json --report /tmp/r.md` — exit code is **1**, which is correct
- [ ] `git status` is clean and `.gitignore` covers `.venv/`, `__pycache__/`, `*.egg-info/`
- [ ] No credentials anywhere in the tree: `git grep -nEi "token|api[_-]?key|password|secret" -- ':!*.md'`
- [ ] `CHANGELOG.md` has an entry for the version in `pyproject.toml`
- [ ] Decided: the scanner **is** going public (AGPL-3.0-or-later). Migration orchestration stays commercial.

## 1. GitHub

Use the script. It creates the repository, sets the description and topics, pushes a single clean commit from an
export of the working tree, and verifies the result at the far end:

```bash
cd /data/ventures/funding/cryptoagility-mvp
GITHUB_TOKEN=... ./scripts/publish_github.sh              # private (default)
GITHUB_TOKEN=... ./scripts/publish_github.sh --public     # public
```

It reads the token from the environment only — never from a command argument, never written into `.git/config`, never
echoed. Add `GITHUB_TOKEN` in **hPanel → Hermes Agent → Dashboard → Environment** so it survives redeploys.

The script exports the current tree rather than pushing local history, so documents that were once tracked but are not
for publication (the internal commercial plan) do not travel into the repository.

Doing it by hand instead:

```bash
git branch -M main
git remote add origin git@github.com:<your-account>/cryptoagility.git
git push -u origin main
```

Then set, in the GitHub UI:

- **Description:** `Cryptographic asset discovery and post-quantum migration register. Finds cryptography in source, config, certificates and live TLS connections. Runs offline.`
- **Topics:** `cryptography` `post-quantum` `pqc` `cbom` `cyclonedx` `security-tools` `compliance` `nisc`
- Enable **private vulnerability reporting** under Settings → Security, so `SECURITY.md` has somewhere to point.
- Confirm the CI workflow runs green on the first push.

If you would rather not publish immediately, push to a **private** repository first. The README, licence and CI are
identical; you can flip it public whenever you are ready, and nothing is lost by waiting.

## 2. PyPI

Check the name first — `cryptoagility` may be taken:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/cryptoagility/json
```

`404` means the name is free. `200` means it is taken and you need a different distribution name (the import name
and the CLI command can stay `cryptoagility`).

Install the build tools and produce artefacts:

```bash
./.venv/bin/pip install build twine
./.venv/bin/python -m build            # writes dist/*.whl and dist/*.tar.gz
./.venv/bin/twine check dist/*
```

Test against TestPyPI before touching the real index:

```bash
./.venv/bin/twine upload --repository testpypi dist/*
./.venv/bin/pip install --index-url https://test.pypi.org/simple/ cryptoagility
```

Then the real one:

```bash
./.venv/bin/twine upload dist/*        # needs a PyPI API token, username __token__
```

Better than a token on disk: **Trusted Publishing**. On PyPI, add a publisher for this repository with workflow
`release.yml` and environment `pypi`, then publish from a GitHub Release — no long-lived secret anywhere. Say the
word and I will write that workflow.

## 3. What to do before the next release

1. Bump `version` in `pyproject.toml`.
2. Add a `CHANGELOG.md` entry. The `[Unreleased]` section is the template.
3. Run the full suite and the CLI smoke test.
4. Tag it: `git tag -a v0.2.0 -m "v0.2.0" && git push --tags`.

## 4. A note on the licence choice

The scanner is AGPL-3.0-or-later. Using it internally costs the user nothing and requires nothing of them; the AGPL
only bites if they **distribute** it or offer it **as a service**, which is exactly the case where a commercial
licence should be paid for. This is deliberate: the scanner is the commodity, so give it away loudly and charge for
the orchestration above it.

If the commercial layer is ever published in the same repository, AGPL applies to the whole repository by default.
Keep the two separate.

## 5. After publishing

The point of publishing is distribution, not tidiness. In the first fortnight:

- announce it where post-quantum practitioners actually are, and describe the *runtime* layer — that is the part
  that is genuinely less common
- note honestly in the announcement what CryptoAgility does not do yet (HSM and firmware discovery), because the
  people who care about this will find out anyway and it costs nothing to say first
- put the repository link on the landing page (`site/index.html`) and on `mainnoltd.com`
