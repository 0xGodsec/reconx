# Push reconx to your GitHub

`reconx-repo.zip` is a ready-to-push git repository: `main` branch, initial
commit, LICENSE, `.gitignore`, README, and `reconx.py` already staged and
committed. You just create an empty repo on GitHub and push.

## Option A — GitHub CLI (fastest)

If you have `gh` installed and logged in (`gh auth login`):

```bash
unzip reconx-repo.zip && cd reconx
gh repo create reconx --public --source=. --remote=origin --push
```

Done. Change `--public` to `--private` if you prefer.

## Option B — plain git + web UI

1. On github.com click **New repository**, name it `reconx`, leave it **empty**
   (no README/license — the zip already has them), and create it.
2. Then:

```bash
unzip reconx-repo.zip && cd reconx
git remote add origin https://github.com/<YOUR_USERNAME>/reconx.git
git push -u origin main
```

Use a **Personal Access Token** as the password when git prompts (GitHub no
longer accepts account passwords). Create one at
Settings → Developer settings → Personal access tokens → Fine-grained,
with `Contents: Read and write` on the new repo.

## Option C — SSH remote

If your SSH key is on GitHub:

```bash
unzip reconx-repo.zip && cd reconx
git remote add origin git@github.com:<YOUR_USERNAME>/reconx.git
git push -u origin main
```

## After pushing

- Add topics on the repo page: `oscp`, `pentesting`, `recon`, `enumeration`,
  `autorecon`, `security`.
- The README renders as the landing page automatically.
- Future changes: `git add -A && git commit -m "..." && git push`.
