# Method of Procedure

- **Source manifest:** `manifest.yaml`
- **Generated:** 2026-09-18 15:42:42 by bert.validator 1.7.1

This document lists the steps `validator` would run for the manifest above, for use when the `validator` command itself can't be run. Follow the steps in order; for each one, run the command in a terminal and compare its exit code against the listed expected results.

---

## Step INIT-1 — Prerequisite: Check for required binaries

- **Manifest:** `manifest.yaml`

```bash
MANIFEST_DIR="/Users/etejeda/git/self/bert.validator"
global_var=123
my_shared_func() { echo "This is a shared utility"; }

missing=""
for binary in jq yq git; do
  if ! command -v "$binary" >/dev/null 2>&1; then
    missing="$missing $binary"
  fi
done
if [ -z "$missing" ]; then
  echo "All required binaries found"
  exit 0
else
  echo "Missing binaries:$missing"
  exit 1
fi

```

**Expected result:**

- ✅ **PASS** if the exit code is `0`.
- ❌ **FAIL** otherwise.

If this step fails: **stop here** — do not continue with the remaining steps.

---

## Step INIT-2 — Prerequisite: Check File Exists

- **Manifest:** `manifest.yaml`

```bash
MANIFEST_DIR="/Users/etejeda/git/self/bert.validator"
global_var=123
my_shared_func() { echo "This is a shared utility"; }

if [ -f "/etc/hosts" ]; then
  echo "File exists"
  exit 0
else
  exit 1
fi

```

**Expected result:**

- ✅ **PASS** if the exit code is `0`.
- ❌ **FAIL** otherwise.

If this step fails: note the failure and continue to the next step.

---

## Step 2@Loop 1 — Validation: Check File Exists \[Loop 1\]

- **Manifest:** `manifest.yaml`
- **Tags:** system, core

```bash
MANIFEST_DIR="/Users/etejeda/git/self/bert.validator"
LOOP_NAME="Loop 1"
LOOP_INDEX=0
global_var=123
my_shared_func() { echo "This is a shared utility"; }

my_shared_func
if [ -f "/etc/hosts" ]; then
  echo "MyApp config found"
  exit 0
elif [ ! -s "/etc/hosts" ]; then
  exit 2
else
  exit 1
fi

```

**Expected result:**

- ⚠️ **WARN** if exit code is one of: 2 — File is present, but empty
- ✅ **PASS** if exit code is one of: 0 — File is present
- Any other exit code: **PASS** if `0`, **FAIL** otherwise.

**Notes:**

- This is an override for loop 1 [google](https://google.com)

---

## Step 2@Loop 2 — Validation: Check File Exists \[Loop 2\]

- **Manifest:** `manifest.yaml`
- **Tags:** system, core

```bash
MANIFEST_DIR="/Users/etejeda/git/self/bert.validator"
LOOP_NAME="Loop 2"
LOOP_INDEX=1
global_var=123
my_shared_func() { echo "This is a shared utility"; }

my_shared_func
if [ -f "/etc/hosts" ]; then
  echo "MyApp config found"
  exit 0
elif [ ! -s "/etc/hosts" ]; then
  exit 2
else
  exit 1
fi

```

**Expected result:**

- ⚠️ **WARN** if exit code is one of: 2 — File is present, but empty
- ✅ **PASS** if exit code is one of: 0 — File is present
- Any other exit code: **PASS** if `0`, **FAIL** otherwise.

**Notes:**

- Checked file, my app name is MyApp
- Check out this link - [google](https://www.google.com)

---

## Step 2@Loop 3 — Validation: Check File Exists \[Loop 3\]

- **Manifest:** `manifest.yaml`
- **Tags:** system, core

```bash
MANIFEST_DIR="/Users/etejeda/git/self/bert.validator"
LOOP_NAME="Loop 3"
LOOP_INDEX=2
global_var=123
my_shared_func() { echo "This is a shared utility"; }

my_shared_func
if [ -f "/etc/hosts" ]; then
  echo "MyApp config found"
  exit 0
elif [ ! -s "/etc/hosts" ]; then
  exit 2
else
  exit 1
fi

```

**Expected result:**

- ⚠️ **WARN** if exit code is one of: 2 — File is present, but empty
- ✅ **PASS** if exit code is one of: 0 — File is present
- Any other exit code: **PASS** if `0`, **FAIL** otherwise.

**Notes:**

- Checked file, my app name is MyApp
- Check out this link - [google](https://www.google.com)

---

