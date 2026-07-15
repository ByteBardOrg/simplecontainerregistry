package storage

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectGarbageDeletesOnlyOldUntaggedManifests(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	now := time.Now().UTC()

	taggedDigest, _, err := fs.PutManifest("team/app", "stable", "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2,"name":"stable"}`))
	if err != nil {
		t.Fatalf("PutManifest(tagged) error = %v", err)
	}
	oldContent := []byte(`{"schemaVersion":2,"name":"old"}`)
	oldDigest, _, err := fs.PutManifest("team/app", sha256DigestForTest(oldContent), "application/vnd.oci.image.manifest.v1+json", oldContent)
	if err != nil {
		t.Fatalf("PutManifest(old) error = %v", err)
	}
	recentContent := []byte(`{"schemaVersion":2,"name":"recent"}`)
	recentDigest, _, err := fs.PutManifest("team/app", sha256DigestForTest(recentContent), "application/vnd.oci.image.manifest.v1+json", recentContent)
	if err != nil {
		t.Fatalf("PutManifest(recent) error = %v", err)
	}

	oldPath, err := fs.manifestDigestPath("team/app", oldDigest)
	if err != nil {
		t.Fatalf("ManifestPath(old) error = %v", err)
	}
	if err := touchTree(oldPath, now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("touchTree(old) error = %v", err)
	}
	recentPath, err := fs.manifestDigestPath("team/app", recentDigest)
	if err != nil {
		t.Fatalf("ManifestPath(recent) error = %v", err)
	}
	if err := touchTree(recentPath, now); err != nil {
		t.Fatalf("touchTree(recent) error = %v", err)
	}

	result, err := fs.CollectGarbage(now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("CollectGarbage() error = %v", err)
	}
	if result.DeletedManifests != 1 {
		t.Fatalf("expected one deleted manifest, got %#v", result)
	}
	if _, _, _, err := fs.GetManifest("team/app", taggedDigest); err != nil {
		t.Fatalf("expected tagged manifest by digest to remain, got %v", err)
	}
	if _, _, _, err := fs.GetManifest("team/app", "stable"); err != nil {
		t.Fatalf("expected tagged manifest by tag to remain, got %v", err)
	}
	if _, _, _, err := fs.GetManifest("team/app", recentDigest); err != nil {
		t.Fatalf("expected recent untagged manifest to remain, got %v", err)
	}
	if _, _, _, err := fs.GetManifest("team/app", oldDigest); err == nil {
		t.Fatal("expected old untagged manifest to be deleted")
	}
}

func TestCommitBlobFromUploadSupportsSHA512(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	content := []byte("hello sha512 blob")
	sum := sha512.Sum512(content)
	digest := "sha512:" + hex.EncodeToString(sum[:])
	uploadPath := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(uploadPath, content, 0o640); err != nil {
		t.Fatalf("WriteFile(upload) error = %v", err)
	}

	size, err := fs.CommitBlobFromUpload(uploadPath, digest)
	if err != nil {
		t.Fatalf("CommitBlobFromUpload() error = %v", err)
	}
	if size != int64(len(content)) {
		t.Fatalf("expected size %d, got %d", len(content), size)
	}
	exists, storedSize, err := fs.HasBlob(digest)
	if err != nil {
		t.Fatalf("HasBlob() error = %v", err)
	}
	if !exists || storedSize != int64(len(content)) {
		t.Fatalf("expected stored sha512 blob, exists=%v size=%d", exists, storedSize)
	}
	file, _, err := fs.OpenBlob(digest)
	if err != nil {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	defer file.Close()
	stored, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll(blob) error = %v", err)
	}
	if string(stored) != string(content) {
		t.Fatalf("unexpected stored blob %q", string(stored))
	}
}

func TestFilesystemRejectsUnsafeTagReferences(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	content := []byte(`{"schemaVersion":2}`)
	digest, _, err := fs.PutManifest("team/app", "safe-1.0", "application/vnd.oci.image.manifest.v1+json", content)
	if err != nil {
		t.Fatalf("PutManifest(safe) error = %v", err)
	}

	unsafeTags := []string{"", "../secret", "nested/tag", `nested\tag`, "dot..dot", "bad:tag", "bad tag", "bad@tag"}
	for _, tag := range unsafeTags {
		t.Run(tag, func(t *testing.T) {
			if _, _, err := fs.PutManifest("team/app", tag, "application/vnd.oci.image.manifest.v1+json", content); err == nil {
				t.Fatal("expected PutManifest to reject unsafe tag")
			}
			if err := fs.LinkManifestTag("team/app", tag, digest); err == nil {
				t.Fatal("expected LinkManifestTag to reject unsafe tag")
			}
			if _, _, _, err := fs.GetManifest("team/app", tag); err == nil {
				t.Fatal("expected GetManifest to reject unsafe tag")
			}
			if _, err := fs.DeleteManifest("team/app", tag); err == nil {
				t.Fatal("expected DeleteManifest to reject unsafe tag")
			}
		})
	}
}

func touchTree(path string, at time.Time) error {
	return os.Chtimes(path, at, at)
}

func sha256DigestForTest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
