# Exposed S3 Bucket Hunting: Public Read = Open Filing Cabinet

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Misconfiguration That Cost Companies Millions

In 2019, Capital One had 100 million customer records exposed through a misconfigured AWS S3 bucket. In 2020, a major healthcare provider left 500,000 patient files publicly readable. In 2022, a fintech startup exposed their entire transaction database via an S3 bucket set to public-read.

S3 misconfiguration is one of the most common and impactful cloud security failures in bug bounty hunting — and finding it is surprisingly simple.

---

## How S3 Buckets Work

AWS S3 (Simple Storage Service) stores files ("objects") in containers called "buckets." Every bucket has a URL:

```
https://BUCKET-NAME.s3.amazonaws.com          # new style
https://s3.amazonaws.com/BUCKET-NAME           # old style  
https://BUCKET-NAME.s3.REGION.amazonaws.com   # region-specific
```

Access is controlled by bucket policies and ACLs. When a developer sets the bucket policy to `s3:GetObject` for `Principal: *` — everyone — the bucket becomes publicly readable.

---

## Bucket Name Discovery

S3 bucket names are globally unique and must be guessed or enumerated:

```bash
TARGET="target"

# Common naming patterns — try all of these
PATTERNS=(
    "$TARGET"
    "$TARGET-prod"
    "$TARGET-production"
    "$TARGET-dev"
    "$TARGET-staging"
    "$TARGET-backup"
    "$TARGET-backups"
    "$TARGET-data"
    "$TARGET-assets"
    "$TARGET-static"
    "$TARGET-media"
    "$TARGET-uploads"
    "$TARGET-logs"
    "$TARGET-archive"
    "prod-$TARGET"
    "dev-$TARGET"
    "backup-$TARGET"
    "${TARGET}app"
    "${TARGET}api"
)

for bucket in "${PATTERNS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        "https://${bucket}.s3.amazonaws.com")
    case $code in
        200) echo "PUBLIC READ: https://${bucket}.s3.amazonaws.com" ;;
        403) echo "EXISTS (private): ${bucket}" ;;
        301) echo "REDIRECT: ${bucket} (different region)" ;;
    esac
done
```

### Reading Bucket ACL Response

```xml
<!-- Public bucket response — you get a file listing -->
<ListBucketResult>
  <Name>target-backup</Name>
  <Contents>
    <Key>prod_db_backup_20240115.sql.gz</Key>   ← database backup!
    <Size>8589934592</Size>
  </Contents>
  <Contents>
    <Key>user_data_export.csv</Key>              ← user PII!
    <Size>245678901</Size>
  </Contents>
</ListBucketResult>

<!-- Private bucket response — access denied -->
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
</Error>

<!-- Non-existent bucket -->
<Error>
  <Code>NoSuchBucket</Code>
</Error>
```

---

## Tools for S3 Bucket Hunting

### s3scanner

```bash
# Install
pip3 install s3scanner --break-system-packages

# Check a single bucket
s3scanner scan --bucket target-backup

# Scan a list of bucket names
s3scanner scan --bucket-file bucket_names.txt

# Output:
# target-backup | bucket_exists | public_read | public_write
# target-prod   | bucket_exists | private     | private
# target-dev    | bucket_exists | public_read | private  ← vulnerable!
```

### AWS CLI — No Credentials Required

```bash
# List files in a public bucket (no AWS account needed)
aws s3 ls s3://target-backup --no-sign-request

# Download a specific file
aws s3 cp s3://target-backup/prod_db.sql.gz . --no-sign-request

# Sync everything (careful with large buckets)
aws s3 sync s3://target-backup ./downloaded/ --no-sign-request

# Check if bucket allows write (DON'T WRITE — just test list)
aws s3api get-bucket-acl --bucket target-backup --no-sign-request
```

### GrayHatWarfare — Pre-Indexed Public Buckets

```bash
# Visit: https://grayhatwarfare.com
# Search: target.com or target-company
# Returns: pre-indexed public buckets with file contents
# Free tier shows limited results, paid shows everything
```

### AWSBucketDump

```bash
# Clone
git clone https://github.com/jordanpotti/AWSBucketDump
pip3 install -r requirements.txt --break-system-packages

# Run with wordlist
python3 AWSBucketDump.py -l bucket_names.txt -g interesting_files.txt
# Downloads matching files automatically
```

---

## What to Look for Inside

Once you have listing access, prioritize these files:

```bash
# Download and inspect the file listing
aws s3 ls s3://target-backup --recursive --no-sign-request > file_list.txt

# Filter for high-value files
grep -iE "\.(sql|sql\.gz|dump|bak|backup)$" file_list.txt    # databases
grep -iE "\.(env|config|cfg|conf|properties)$" file_list.txt  # configs
grep -iE "\.(pem|key|p12|pfx|jks)$" file_list.txt             # crypto keys
grep -iE "(password|cred|secret|token|api)" file_list.txt     # credentials
grep -iE "(user|customer|employee|patient)" file_list.txt     # PII files
grep -iE "\.(csv|xlsx|json)$" file_list.txt                   # data exports
```

---

## The Bug Report

```
Title: Public S3 Bucket — target-backup.s3.amazonaws.com — Sensitive Data Exposed

Severity: CRITICAL

Description:
The AWS S3 bucket "target-backup" is publicly readable, exposing sensitive
company data including database backups and user PII.

Proof of Concept:
$ curl https://target-backup.s3.amazonaws.com
[Returns XML file listing with 47 files]

$ aws s3 ls s3://target-backup --no-sign-request
2024-01-15 prod_db_backup_20240115.sql.gz  (8.0 GB)
2024-01-10 user_data_export.csv             (234 MB)
2024-01-01 app_config.json                  (2.1 KB)

Files of concern:
1. prod_db_backup_20240115.sql.gz → production database backup
2. user_data_export.csv → user PII (name, email, address)
3. app_config.json → contains API keys (not downloaded, confirmed exists)

Impact:
Complete exposure of production database backup and user PII for
[X] users. Potential for credential theft via app_config.json.

Remediation:
1. Set bucket to private immediately: 
   aws s3api put-bucket-acl --bucket target-backup --acl private
2. Enable Block Public Access at account level
3. Audit all S3 buckets for public access
4. Move sensitive data to encrypted private storage
```

---

## Key Takeaways

```
1. S3 public-read = entire bucket listable + downloadable by anyone
2. Bucket names are predictable: target, target-backup, target-prod, etc.
3. HTTP 200 = public, 403 = exists but private, NoSuchBucket = doesn't exist
4. aws s3 ls s3://BUCKET --no-sign-request = list without AWS account
5. s3scanner: fastest tool for checking access level on many buckets
6. GrayHatWarfare: check if bucket already indexed publicly
7. Prioritize: .sql, .env, .pem, .csv, config files in listing
8. Report with: URL + file listing + 1-2 file names showing sensitivity
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
