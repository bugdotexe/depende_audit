-----

```
 █████                             █████           █████
░░███                             ░░███           ░░███
 ░███████  █████ ████  ███████  ███████   ██████  ███████    ██████  █████ █████  ██████
 ░███░░███░░███ ░███  ███░░███ ███░░███  ███░░███░░░███░    ███░░███░░███ ░░███  ███░░███
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███    ░███████  ░░░█████░  ░███████
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███ ███░███░░░    ███░░░███ ░███░░░
 ████████  ░░████████░░███████░░████████░░██████   ░░█████ ░░██████  █████ █████░░██████
░░░░░░░░    ░░░░░░░░  ░░░░░███ ░░░░░░░░  ░░░░░░     ░░░░░   ░░░░░░  ░░░░░ ░░░░░  ░░░░░░
                      ███ ░███
                     ░░██████
                      ░░░░░░                                                             
```

# Depende Audit

This script is a comprehensive security auditing tool designed to scan GitHub organizations, user repositories, GitLab groups, or local codebases. It automates repository cloning, dependency extraction, and vulnerability checking, with a strong focus on **supply chain security** and **secret detection**.

## 🚀 Features

  * **Multi-Platform Scanning**: Clones and analyzes repositories from:
      * GitHub Organizations (`-o`)
      * GitHub Users (`-u`)
      * GitLab Groups (`-g`)
      * Local Folders (`-f`)
  * **Dependency Confusion**: Checks for potential dependency confusion/hijacking vulnerabilities across seven major ecosystems:
      * NPM (`package.json`)
      * Pip (`requirements.txt`)
      * RubyGems (`Gemfile`)
      * Go (`go.mod`)
      * Maven (`pom.xml`)
      * Docker (`Dockerfile`, `docker-compose.yml`, etc.)
      * Rust (`Cargo.toml`)
  * **Broken Link & Takeover**:
      * Scans for broken GitHub repository URLs.
      * Identifies broken GitHub Action workflows (`uses: ...`) that could be vulnerable to takeover.
  * **Secret Scanning**: Integrates with `trufflehog` to perform high-signal, verified-only secret scanning on the entire codebase, including commit history and issue comments (for GitHub orgs).
  * **Organized Output**: Saves all extracted dependency lists and potential findings into a clean, timestamped output directory (`/tmp/<TARGET>`) for easy review.

## 🛠️ Prerequisites

This script relies on several external tools. Please ensure they are installed and available in your `$PATH`.

  * **[ghorg](https://github.com/gabrie30/ghorg)**: Used to clone repositories from GitHub and GitLab.
  * **[trufflehog](https://github.com/trufflesecurity/trufflehog)**: Used for secret scanning.
  * **[anew](https://github.com/tomnomnom/anew)**: Used for appending unique lines to output files.
  * **[get-dependencies](https://www.npmjs.com/package/get-dependencies)**: An NPM package to parse `package.json` files. Install via `$ npm i -g get-dependencies`.
  * **[pip-name](https://github.com/danishprakash/pip-name)**: Use to check pypi package name availability.Install via `$ pip install pip-name`
   * **[pip-name](https://www.npmjs.com/package/npm-name-cli)**: Use to check npm package name availability.Install via `$ npm i -g npm-name-cli `
   *  
## ⚙️ Configuration

You must export a **GitHub Token** with sufficient permissions (`repo`, `read:org`) for `ghorg` and `trufflehog` to function correctly.

```bash
export GITHUB_TOKEN="ghp_..."
```

## Usage

```bash
# Scan a GitHub Organization
bash scan.sh -o <org_name>

# Scan a GitHub User
bash scan.sh -u <user_name>

# Scan a GitLab Group
bash scan.sh -g <gitlab_group_name>

# Scan a local folder
bash scan.sh -f /path/to/local/codebase
```

### Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-u`, `--user` | `<USER>` | Specify a GitHub User to scan. |
| `-o`, `--org` | `<ORG>` | Specify a GitHub Organization to scan. |
| `-g`, `--gitlab` | `<GITLAB>` | Specify a GitLab Group to scan. |
| `-f`, `--folder` | `<FOLDER>` | Specify a local folder to scan. |

> **Note:** You must specify one target (`-u`, `-o`, `-g`, or `-f`).

## 📜 Output

All results are saved in a target-specific directory under `/tmp/`. For example, scanning `bugdotexe` would save results to `/tmp/bugdotexe/`.

The output directory contains:

  * All cloned repositories.
  * A `DEP/` folder containing:
      * `.deps` files (e.g., `npm.deps`): A list of all unique dependencies found.
      * `.checked` files: The raw output from the registry check.
      * `.potential` files (e.g., `npm.potential`): A clean list of dependencies that appear to be available for registration (potential vulnerabilities).
      * `github.account`, `github.action`, `github.potential`: Lists of found GitHub links and those that were found to be broken (404).

A final summary is printed to the console, highlighting the number of potential findings for each category.

```
[WARN] [+] Scan completed for bugdotexe — results in /tmp/bugdotexe

[INFO] === POTENTIAL FINDINGS SUMMARY ===
[WARN] docker: 3 potential vulnerabilities
[INFO] gem: 0 potential vulnerabilities
[WARN] github: 1 potential vulnerabilities
[INFO] go: 0 potential vulnerabilities
[INFO] maven: 0 potential vulnerabilities
[INFO] npm: 0 potential vulnerabilities
[INFO] pip: 0 potential vulnerabilities
[INFO] rust: 0 potential vulnerabilities
```

