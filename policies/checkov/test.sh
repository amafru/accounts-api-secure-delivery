#!/usr/bin/env bash
# Proves the Terraform policies FAIL on the original and PASS on the fixed config.
# Run from the repo root:  bash policies/checkov/test.sh
set -u
CHECKS="CKV2_ACCT_001,CKV2_ACCT_002,CKV2_ACCT_003,CKV2_ACCT_004,CKV2_ACCT_005,CKV2_ACCT_006,CKV2_ACCT_007,CKV2_ACCT_008,CKV2_ACCT_009,CKV2_ACCT_010"
run() { checkov -d "$1" --framework terraform --external-checks-dir policies/checkov --check "$CHECKS" --compact --quiet; }

echo "=== BEFORE (must fail) ==="; run review/terraform/original; before=$?
echo "=== AFTER (must pass) ===";  run review/terraform/fixed;    after=$?

if [ "$before" -ne 0 ] && [ "$after" -eq 0 ]; then
  echo "PASS: policies reject the original and accept the fix"; exit 0
else
  echo "FAIL: before=$before after=$after"; exit 1
fi
