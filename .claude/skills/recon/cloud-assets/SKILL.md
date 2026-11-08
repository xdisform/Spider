---
name: cloud-assets
description: Enumerate cloud storage (S3/GCS/Azure) tied to the target and test buckets for public listing/read/write exposure.
category: recon
tags: [cloud, s3, buckets, storage, exposure]
chains_with: [js-secret-mining, archive-urls]
tools: [cloud_enum, s3scanner, bucketloot]
version: "1.2"
---

# Cloud storage enumeration

## Objective
Find the object-storage buckets belonging to the target and determine whether any are publicly
listable, readable, or writable — a classic path to data exposure and supply-chain tampering.

## Methodology
1. **Build candidate names.** From the org/brand, subdomains, JS references (`js-secret-mining`), and
   archived URLs (`archive-urls`) pointing at `s3.amazonaws.com`, `storage.googleapis.com`,
   `*.blob.core.windows.net`. Generate permutations (org-prod, org-assets, org-backups, org-dev).
1a. **Multi-cloud keyword sweep (cloud_enum).** Discover buckets/blobs/apps across ALL THREE providers
   in one pass from the org keyword — catches names your permutation list misses:
   `bin/cloud_enum -k <org-keyword> -k <brand> --disable-azure-nothing -l raw/cloud-assets/cloud_enum.txt`
   (run once per distinct keyword; AWS S3 + Azure blob/file/apps + GCP buckets/apps). It hits the cloud
   providers directly, NOT the in-scope target — run DIRECT, no leash. Feed every OPEN/PROTECTED hit it
   reports into step 2 for the ACL verdict. Keyless.
2. **Scan ACLs.** `bin/s3scanner scan -f candidates.txt --json` (or `-b <bucket>`) — it resolves the
   bucket, identifies the provider, and reports the ACL/permissions (list/read/write) without
   touching the in-scope web app.
2a. **Inspect contents (bucketloot).** For any bucket that exists and is listable/readable, run
   `bin/bucketloot https://<bucket>.s3.amazonaws.com -search "password" -save raw/cloud-assets/<bucket>-loot.json`.
   bucketloot works across AWS S3, GCS, DO Spaces, and any S3-API-compatible endpoint (Alibaba OSS,
   Cloudflare R2) via custom URL. It enumerates assets AND runs 80+ regex secret signatures over
   their contents in one pass — turns a bucket-ACL finding and a secret-leak finding into a single
   proof chain. Keyless for unauth scans. Hit the cloud endpoint direct, NOT through the leash.
3. **Classify exposure.** For each bucket that exists, record: public LIST (index disclosure), public
   READ (object download), public WRITE (tamper/upload). Enumerate a listable bucket's object keys.
4. **Assess sensitivity.** A readable bucket only matters if its objects are sensitive — sample one or
   two keys (per policy), never bulk-exfiltrate. A public-writable bucket is high on its own.

## What to return
Per discovered bucket: provider, existence, ACL verdict (list/read/write), and a sensitivity note on
what its objects contain. Public-write or sensitive-public-read buckets are findings-in-waiting;
name-only guesses that don't resolve are leads.

## Evidence
The `s3scanner` JSON, the bucket's object-key listing (keys, not bulk contents), and one sample
proving read/write access, under `raw/cloud-assets/`.

## Notes
`s3scanner` hits the cloud provider's storage endpoints, NOT the in-scope target host — run it direct,
WITHOUT the leash. A public bucket is a finding only when it's tied to the target and its exposure is
proven (a listed/read/written object) per `poc-standard`; otherwise it's a lead. Never delete or
overwrite an existing object.
