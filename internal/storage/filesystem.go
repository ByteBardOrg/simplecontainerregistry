package storage

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotFound      = os.ErrNotExist
	ErrInvalidDigest = errors.New("invalid digest")
)

type Filesystem struct {
	root string
}

type GCResult struct {
	DeletedManifests int
}

type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func NewFilesystem(root string) (Filesystem, error) {
	if err := EnsureRoot(root); err != nil {
		return Filesystem{}, err
	}
	return Filesystem{root: root}, nil
}

func EnsureRoot(root string) error {
	if root == "" {
		return fmt.Errorf("storage root is required")
	}
	return os.MkdirAll(root, 0o750)
}

func (fs Filesystem) Root() string {
	return fs.root
}

func (fs Filesystem) BlobPath(digest string) (string, error) {
	algorithm, encoded, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	return fs.safeJoin("blobs", algorithm, encoded[:2], encoded), nil
}

func (fs Filesystem) ManifestPath(repository, reference string) (string, error) {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return "", err
	}
	return fs.safeJoin("repositories", repoPath, "manifests", sanitizeReference(reference)), nil
}

func (fs Filesystem) PutManifest(repository, reference, mediaType string, content []byte) (string, int64, error) {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return "", 0, err
	}
	digest := digestForContent(manifestDigestAlgorithm(content), content)
	if strings.Contains(reference, ":") {
		if err := verifyDigest(content, reference); err != nil {
			return "", 0, err
		}
		digest = reference
	}
	digestPath, err := fs.manifestDigestPath(repoPath, digest)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(digestPath, 0o750); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(filepath.Join(digestPath, "content"), content, 0o640); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(filepath.Join(digestPath, "mediaType"), []byte(mediaType), 0o640); err != nil {
		return "", 0, err
	}

	if !strings.Contains(reference, ":") {
		if err := fs.linkManifestTag(repoPath, reference, digest); err != nil {
			return "", 0, err
		}
	}
	return digest, int64(len(content)), nil
}

func (fs Filesystem) LinkManifestTag(repository, tag, digest string) error {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return err
	}
	digestPath, err := fs.manifestDigestPath(repoPath, digest)
	if err != nil {
		return err
	}
	if _, err := os.Stat(digestPath); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return fs.linkManifestTag(repoPath, tag, digest)
}

func (fs Filesystem) GetManifest(repository, reference string) ([]byte, string, string, error) {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return nil, "", "", err
	}
	digest := reference
	if !strings.Contains(reference, ":") {
		tagPath := fs.safeJoin("repositories", repoPath, "tags", sanitizeReference(reference))
		data, err := os.ReadFile(tagPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", "", ErrNotFound
			}
			return nil, "", "", err
		}
		digest = strings.TrimSpace(string(data))
	}
	digestPath, err := fs.manifestDigestPath(repoPath, digest)
	if err != nil {
		return nil, "", "", err
	}
	content, err := os.ReadFile(filepath.Join(digestPath, "content"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", "", ErrNotFound
		}
		return nil, "", "", err
	}
	mediaTypeBytes, err := os.ReadFile(filepath.Join(digestPath, "mediaType"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", "", ErrNotFound
		}
		return nil, "", "", err
	}
	return content, strings.TrimSpace(string(mediaTypeBytes)), digest, nil
}

func (fs Filesystem) DeleteManifest(repository, reference string) (string, error) {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return "", err
	}
	digest := reference
	if !strings.Contains(reference, ":") {
		tagPath := fs.safeJoin("repositories", repoPath, "tags", sanitizeReference(reference))
		data, err := os.ReadFile(tagPath)
		if err != nil {
			if os.IsNotExist(err) {
				return "", ErrNotFound
			}
			return "", err
		}
		digest = strings.TrimSpace(string(data))
		if err := os.Remove(tagPath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return digest, nil
	}

	digestPath, err := fs.manifestDigestPath(repoPath, digest)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(digestPath); err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	if err := os.RemoveAll(digestPath); err != nil {
		return "", err
	}
	if _, err := os.Stat(digestPath); err == nil {
		return "", fmt.Errorf("failed to delete manifest")
	}
	if err := fs.deleteTagReferences(repoPath, digest); err != nil {
		return "", err
	}
	return digest, nil
}

func (fs Filesystem) DeleteBlob(digest string) error {
	path, err := fs.BlobPath(digest)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (fs Filesystem) ListTags(repository string) ([]string, error) {
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return nil, err
	}
	tagDir := fs.safeJoin("repositories", repoPath, "tags")
	entries, err := os.ReadDir(tagDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	tags := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		tags = append(tags, entry.Name())
	}
	sort.Strings(tags)
	return tags, nil
}

func (fs Filesystem) ListReferrers(repository, subjectDigest, artifactType string) ([]Descriptor, error) {
	if _, _, err := parseDigest(subjectDigest); err != nil {
		return nil, err
	}
	repoPath, err := safeRepositoryPath(repository)
	if err != nil {
		return nil, err
	}
	manifestRoot := fs.safeJoin("repositories", repoPath, "manifests")
	if _, err := os.Stat(manifestRoot); err != nil {
		if os.IsNotExist(err) {
			return []Descriptor{}, nil
		}
		return nil, err
	}

	var descriptors []Descriptor
	err = filepath.WalkDir(manifestRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Base(path) != "content" {
			return nil
		}
		digestDir := filepath.Dir(path)
		algorithm := filepath.Base(filepath.Dir(digestDir))
		encoded := filepath.Base(digestDir)
		digest := algorithm + ":" + encoded
		if _, _, err := parseDigest(digest); err != nil {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mediaTypeBytes, err := os.ReadFile(filepath.Join(digestDir, "mediaType"))
		if err != nil {
			return err
		}
		desc, ok := descriptorForReferrer(content, strings.TrimSpace(string(mediaTypeBytes)), digest)
		if !ok || SubjectDigest(content) != subjectDigest {
			return nil
		}
		if artifactType != "" && desc.ArtifactType != artifactType {
			return nil
		}
		descriptors = append(descriptors, desc)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Digest < descriptors[j].Digest })
	return descriptors, nil
}

func (fs Filesystem) UploadPath(uploadID string) (string, error) {
	if uploadID == "" || strings.Contains(uploadID, "/") || strings.Contains(uploadID, "..") {
		return "", fmt.Errorf("invalid upload id")
	}
	return fs.safeJoin("uploads", uploadID), nil
}

func (fs Filesystem) HasBlob(digest string) (bool, int64, error) {
	path, err := fs.BlobPath(digest)
	if err != nil {
		return false, 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil
		}
		return false, 0, err
	}
	return true, info.Size(), nil
}

func (fs Filesystem) CommitBlobFromUpload(uploadPath, expectedDigest string) (int64, error) {
	algorithm, _, err := parseDigest(expectedDigest)
	if err != nil {
		return 0, err
	}
	h := digestHash(algorithm)
	if h == nil {
		return 0, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	file, err := os.Open(uploadPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	size, err := io.Copy(h, file)
	if err != nil {
		return 0, err
	}
	actual := algorithm + ":" + hex.EncodeToString(h.Sum(nil))
	if actual != expectedDigest {
		return 0, fmt.Errorf("digest mismatch: expected %s, got %s", expectedDigest, actual)
	}

	destination, err := fs.BlobPath(expectedDigest)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return 0, err
	}
	if err := os.Rename(uploadPath, destination); err != nil {
		if os.IsExist(err) {
			_ = os.Remove(uploadPath)
			return size, nil
		}
		return 0, err
	}
	return size, nil
}

func (fs Filesystem) OpenBlob(digest string) (*os.File, int64, error) {
	path, err := fs.BlobPath(digest)
	if err != nil {
		return nil, 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}
	return file, info.Size(), nil
}

func (fs Filesystem) CollectGarbage(cutoff time.Time) (GCResult, error) {
	repositoriesRoot := fs.safeJoin("repositories")
	if _, err := os.Stat(repositoriesRoot); err != nil {
		if os.IsNotExist(err) {
			return GCResult{}, nil
		}
		return GCResult{}, err
	}

	var result GCResult
	err := filepath.WalkDir(repositoriesRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() || filepath.Base(path) != "manifests" {
			return nil
		}
		repoPath, err := filepath.Rel(repositoriesRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		referenced, err := fs.referencedManifestDigests(repoPath)
		if err != nil {
			return err
		}
		algorithmDirs, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, algorithmDir := range algorithmDirs {
			if !algorithmDir.IsDir() {
				continue
			}
			digestRoot := filepath.Join(path, algorithmDir.Name())
			digestDirs, err := os.ReadDir(digestRoot)
			if err != nil {
				return err
			}
			for _, digestDir := range digestDirs {
				if !digestDir.IsDir() {
					continue
				}
				digest := algorithmDir.Name() + ":" + digestDir.Name()
				if referenced[digest] {
					continue
				}
				digestPath := filepath.Join(digestRoot, digestDir.Name())
				info, err := digestDir.Info()
				if err != nil {
					return err
				}
				if info.ModTime().After(cutoff) {
					continue
				}
				if err := os.RemoveAll(digestPath); err != nil {
					return err
				}
				result.DeletedManifests++
			}
		}
		return filepath.SkipDir
	})
	return result, err
}

func (fs Filesystem) referencedManifestDigests(repoPath string) (map[string]bool, error) {
	referenced := make(map[string]bool)
	tagDir := fs.safeJoin("repositories", repoPath, "tags")
	entries, err := os.ReadDir(tagDir)
	if err != nil {
		if os.IsNotExist(err) {
			return referenced, nil
		}
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tagDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		referenced[strings.TrimSpace(string(data))] = true
	}
	return referenced, nil
}

func (fs Filesystem) deleteTagReferences(repoPath, digest string) error {
	tagDir := fs.safeJoin("repositories", repoPath, "tags")
	entries, err := os.ReadDir(tagDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(tagDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) == digest {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func (fs Filesystem) safeJoin(parts ...string) string {
	joined := filepath.Join(append([]string{fs.root}, parts...)...)
	return joined
}

func (fs Filesystem) manifestDigestPath(repoPath, digest string) (string, error) {
	algorithm, encoded, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	return fs.safeJoin("repositories", repoPath, "manifests", algorithm, encoded), nil
}

func (fs Filesystem) linkManifestTag(repoPath, tag, digest string) error {
	tagPath := fs.safeJoin("repositories", repoPath, "tags", sanitizeReference(tag))
	if err := os.MkdirAll(filepath.Dir(tagPath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(tagPath, []byte(digest), 0o640)
}

func parseDigest(digest string) (string, string, error) {
	algorithm, encoded, ok := strings.Cut(digest, ":")
	if !ok || algorithm == "" || encoded == "" {
		return "", "", ErrInvalidDigest
	}
	if algorithm != "sha256" && algorithm != "sha512" {
		return "", "", fmt.Errorf("%w: unsupported digest algorithm %q", ErrInvalidDigest, algorithm)
	}
	if len(encoded) != digestHexLength(algorithm) {
		return "", "", fmt.Errorf("%w: invalid digest length", ErrInvalidDigest)
	}
	for _, r := range encoded {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", "", fmt.Errorf("%w: invalid digest encoding", ErrInvalidDigest)
		}
	}
	return algorithm, encoded, nil
}

func verifyDigest(content []byte, expected string) error {
	algorithm, _, err := parseDigest(expected)
	if err != nil {
		return err
	}
	actual := digestForContent(algorithm, content)
	if actual != expected {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidDigest, expected, actual)
	}
	return nil
}

func digestForContent(algorithm string, content []byte) string {
	h := digestHash(algorithm)
	_, _ = h.Write(content)
	return algorithm + ":" + hex.EncodeToString(h.Sum(nil))
}

func digestHash(algorithm string) hash.Hash {
	switch algorithm {
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	default:
		return nil
	}
}

func digestHexLength(algorithm string) int {
	switch algorithm {
	case "sha256":
		return sha256.Size * 2
	case "sha512":
		return sha512.Size * 2
	default:
		return 0
	}
}

func SubjectDigest(content []byte) string {
	var manifest struct {
		Subject *Descriptor `json:"subject"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil || manifest.Subject == nil {
		return ""
	}
	return manifest.Subject.Digest
}

func manifestDigestAlgorithm(content []byte) string {
	var manifest struct {
		Config    *Descriptor  `json:"config"`
		Layers    []Descriptor `json:"layers"`
		Manifests []Descriptor `json:"manifests"`
		Subject   *Descriptor  `json:"subject"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return "sha256"
	}
	algorithm := ""
	for _, descriptor := range manifestDescriptors(manifest.Config, manifest.Layers, manifest.Manifests, manifest.Subject) {
		candidate, _, err := parseDigest(descriptor.Digest)
		if err != nil {
			continue
		}
		if algorithm == "" {
			algorithm = candidate
			continue
		}
		if algorithm != candidate {
			return "sha256"
		}
	}
	if algorithm == "" {
		return "sha256"
	}
	return algorithm
}

func manifestDescriptors(config *Descriptor, layers []Descriptor, manifests []Descriptor, subject *Descriptor) []Descriptor {
	descriptors := make([]Descriptor, 0, 1+len(layers)+len(manifests)+1)
	if config != nil {
		descriptors = append(descriptors, *config)
	}
	descriptors = append(descriptors, layers...)
	descriptors = append(descriptors, manifests...)
	if subject != nil {
		descriptors = append(descriptors, *subject)
	}
	return descriptors
}

func descriptorForReferrer(content []byte, mediaType, digest string) (Descriptor, bool) {
	var manifest struct {
		MediaType    string            `json:"mediaType"`
		ArtifactType string            `json:"artifactType"`
		Config       *Descriptor       `json:"config"`
		Subject      *Descriptor       `json:"subject"`
		Annotations  map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil || manifest.Subject == nil {
		return Descriptor{}, false
	}
	artifactType := manifest.ArtifactType
	if artifactType == "" && manifest.Config != nil {
		artifactType = manifest.Config.MediaType
	}
	return Descriptor{
		MediaType:    mediaType,
		ArtifactType: artifactType,
		Digest:       digest,
		Size:         int64(len(content)),
		Annotations:  manifest.Annotations,
	}, true
}

func safeRepositoryPath(repository string) (string, error) {
	repository = strings.Trim(repository, "/")
	if repository == "" || strings.Contains(repository, "..") {
		return "", fmt.Errorf("invalid repository name")
	}
	for _, part := range strings.Split(repository, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid repository name")
		}
	}
	return repository, nil
}

func sanitizeReference(reference string) string {
	reference = strings.ReplaceAll(reference, "/", "_")
	reference = strings.ReplaceAll(reference, ":", "_")
	return reference
}
