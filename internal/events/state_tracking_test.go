package events

import (
	"path/filepath"
	"testing"

	"github.com/bilals12/iota/internal/state"
)

func TestStateTrackingIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "test_state.db")

	stateDB, err := state.Open(stateFile)
	if err != nil {
		t.Fatalf("failed to open state database: %v", err)
	}
	defer func() { _ = stateDB.Close() }()

	bucket := "test-bucket"
	accountID := "123456789012"
	region := "us-east-1"
	key1 := "AWSLogs/123456789012/CloudTrail/us-east-1/2024/12/01/123456789012_CloudTrail_us-east-1_20241201T0005Z_abc123.json.gz"
	key2 := "AWSLogs/123456789012/CloudTrail/us-east-1/2024/12/01/123456789012_CloudTrail_us-east-1_20241201T0010Z_xyz789.json.gz"

	lastKey, err := stateDB.GetLastProcessedKey(bucket, accountID, region)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey != "" {
		t.Errorf("expected empty last key, got %s", lastKey)
	}

	err = stateDB.UpdateLastProcessedKey(bucket, accountID, region, key1)
	if err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	lastKey, err = stateDB.GetLastProcessedKey(bucket, accountID, region)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey != key1 {
		t.Errorf("expected last key %s, got %s", key1, lastKey)
	}

	err = stateDB.UpdateLastProcessedKey(bucket, accountID, region, key2)
	if err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	lastKey, err = stateDB.GetLastProcessedKey(bucket, accountID, region)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey != key2 {
		t.Errorf("expected last key %s, got %s", key2, lastKey)
	}
}

func TestStateTrackingWithS3KeyParser(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "test_state.db")

	stateDB, err := state.Open(stateFile)
	if err != nil {
		t.Fatalf("failed to open state database: %v", err)
	}
	defer func() { _ = stateDB.Close() }()

	bucket := "test-bucket"
	key1 := "AWSLogs/123456789012/CloudTrail/us-east-1/2024/12/01/123456789012_CloudTrail_us-east-1_20241201T0005Z_abc123.json.gz"
	key2 := "AWSLogs/o-f4709b1n6a/655631470870/CloudTrail/us-west-2/2025/12/01/655631470870_CloudTrail_us-west-2_20251201T0010Z_def456.json.gz"

	accountID1, region1, err := ExtractAccountRegionFromKey(key1)
	if err != nil {
		t.Fatalf("failed to extract account/region from key1: %v", err)
	}
	if accountID1 != "123456789012" || region1 != "us-east-1" {
		t.Errorf("expected account=123456789012, region=us-east-1, got account=%s, region=%s", accountID1, region1)
	}

	accountID2, region2, err := ExtractAccountRegionFromKey(key2)
	if err != nil {
		t.Fatalf("failed to extract account/region from key2: %v", err)
	}
	if accountID2 != "655631470870" || region2 != "us-west-2" {
		t.Errorf("expected account=655631470870, region=us-west-2, got account=%s, region=%s", accountID2, region2)
	}

	lastKey1, err := stateDB.GetLastProcessedKey(bucket, accountID1, region1)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey1 != "" {
		t.Errorf("expected empty last key for account1/region1, got %s", lastKey1)
	}

	err = stateDB.UpdateLastProcessedKey(bucket, accountID1, region1, key1)
	if err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	lastKey1, err = stateDB.GetLastProcessedKey(bucket, accountID1, region1)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey1 != key1 {
		t.Errorf("expected last key %s, got %s", key1, lastKey1)
	}

	lastKey2, err := stateDB.GetLastProcessedKey(bucket, accountID2, region2)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey2 != "" {
		t.Errorf("expected empty last key for account2/region2, got %s", lastKey2)
	}

	err = stateDB.UpdateLastProcessedKey(bucket, accountID2, region2, key2)
	if err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	lastKey2, err = stateDB.GetLastProcessedKey(bucket, accountID2, region2)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}
	if lastKey2 != key2 {
		t.Errorf("expected last key %s, got %s", key2, lastKey2)
	}

	if lastKey1 == lastKey2 {
		t.Error("expected different keys for different account/region combinations")
	}
}

func TestDuplicateDetection(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "test_state.db")

	stateDB, err := state.Open(stateFile)
	if err != nil {
		t.Fatalf("failed to open state database: %v", err)
	}
	defer func() { _ = stateDB.Close() }()

	bucket := "test-bucket"
	key := "AWSLogs/123456789012/CloudTrail/us-east-1/2024/12/01/123456789012_CloudTrail_us-east-1_20241201T0005Z_abc123.json.gz"

	accountID, region, err := ExtractAccountRegionFromKey(key)
	if err != nil {
		t.Fatalf("failed to extract account/region: %v", err)
	}

	lastKey, err := stateDB.GetLastProcessedKey(bucket, accountID, region)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}

	if lastKey == key {
		t.Error("key should not be marked as processed initially")
	}

	err = stateDB.UpdateLastProcessedKey(bucket, accountID, region, key)
	if err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	lastKey, err = stateDB.GetLastProcessedKey(bucket, accountID, region)
	if err != nil {
		t.Fatalf("failed to get last processed key: %v", err)
	}

	if lastKey != key {
		t.Errorf("key should be marked as processed, expected %s, got %s", key, lastKey)
	}

	if lastKey == key {
		t.Log("✓ Duplicate detection working: key is correctly identified as already processed")
	}
}
