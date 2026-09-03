package storage

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
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

func TestRepositoryBlobLinksAreIsolated(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	content := []byte("private layer")
	digest := sha256DigestForTest(content)
	uploadPath := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(uploadPath, content, 0o640); err != nil {
		t.Fatalf("WriteFile(upload) error = %v", err)
	}
	if _, err := fs.CommitBlobFromUpload(uploadPath, digest); err != nil {
		t.Fatalf("CommitBlobFromUpload() error = %v", err)
	}
	if err := fs.LinkRepositoryBlob("team-a/app", digest); err != nil {
		t.Fatalf("LinkRepositoryBlob() error = %v", err)
	}
	if linked, err := fs.HasRepositoryBlob("team-a/app", digest); err != nil || !linked {
		t.Fatalf("expected blob linked to team-a/app, linked=%v err=%v", linked, err)
	}
	if linked, err := fs.HasRepositoryBlob("team-b/app", digest); err != nil || linked {
		t.Fatalf("expected blob isolated from team-b/app, linked=%v err=%v", linked, err)
	}
	if err := fs.DeleteRepositoryBlob("team-a/app", digest); err != nil {
		t.Fatalf("DeleteRepositoryBlob() error = %v", err)
	}
	if exists, _, err := fs.HasBlob(digest); err != nil || !exists {
		t.Fatalf("expected shared blob content to survive repository unlink, exists=%v err=%v", exists, err)
	}
}

func TestMigrateRepositoryBlobLinksPreservesExistingManifestBlobs(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	content := []byte("existing layer")
	digest := sha256DigestForTest(content)
	uploadPath := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(uploadPath, content, 0o640); err != nil {
		t.Fatalf("WriteFile(upload) error = %v", err)
	}
	if _, err := fs.CommitBlobFromUpload(uploadPath, digest); err != nil {
		t.Fatalf("CommitBlobFromUpload() error = %v", err)
	}
	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"` + digest + `"},"layers":[]}`)
	if _, _, err := fs.PutManifest("legacy/app", "latest", "application/vnd.oci.image.manifest.v1+json", manifest); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	if err := fs.MigrateRepositoryBlobLinks(); err != nil {
		t.Fatalf("MigrateRepositoryBlobLinks() error = %v", err)
	}
	if linked, err := fs.HasRepositoryBlob("legacy/app", digest); err != nil || !linked {
		t.Fatalf("expected migration to link existing manifest blob, linked=%v err=%v", linked, err)
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

func TestPutManifestContentCanBeLinkedAfterward(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystem() error = %v", err)
	}
	content := []byte(`{"schemaVersion":2}`)
	digest := sha256DigestForTest(content)
	if _, _, err := fs.PutManifestContent("team/app", digest, "application/vnd.oci.image.manifest.v1+json", content); err != nil {
		t.Fatalf("PutManifestContent() error = %v", err)
	}
	if _, _, _, err := fs.GetManifest("team/app", "release"); err == nil {
		t.Fatal("expected manifest to be untagged before linking")
	}
	if err := fs.LinkManifestTag("team/app", "release", digest); err != nil {
		t.Fatalf("LinkManifestTag() error = %v", err)
	}
	resolved, err := fs.ManifestTagDigest("team/app", "release")
	if err != nil {
		t.Fatalf("ManifestTagDigest() error = %v", err)
	}
	if resolved != digest {
		t.Fatalf("expected linked digest %s, got %s", digest, resolved)
	}
}

func TestManifestBlobDigestsExcludesNondistributableLayers(t *testing.T) {
	content := []byte(`{"config":{"digest":"sha256:config"},"layers":[{"mediaType":"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip","digest":"sha256:oci-external"},{"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","digest":"sha256:docker-external"},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:local"}]}`)
	want := []string{"sha256:config", "sha256:local"}
	if got := ManifestBlobDigests(content); !slices.Equal(got, want) {
		t.Fatalf("ManifestBlobDigests() = %v, want %v", got, want)
	}
}

func touchTree(path string, at time.Time) error {
	return os.Chtimes(path, at, at)
}

func sha256DigestForTest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
