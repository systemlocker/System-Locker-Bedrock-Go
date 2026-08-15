package bedrock

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
)

const (
	invisibleDownloadPrefix = "/a/"
	invisibleMetadataPrefix = "/api/v1/files/"
	invisibleMetadataSuffix = "/metadata"
	revisionsMetadataKey    = "__revisions"
)

// InvisibleFolderFile describes a file in Invisible Folder.
type InvisibleFolderFile struct {
	ID               string
	ReferenceID      string
	Name             string
	MimeType         string
	Size             uint64
	Downloads        uint64
	UploadedAt       string
	PermissionTypeID int64
}

// InvisibleFolderMetadataValue is one metadata entry.
type InvisibleFolderMetadataValue struct {
	Value     string
	CreatedAt string // empty when absent
}

// InvisibleFolderMetadata is a file description plus its metadata entries.
type InvisibleFolderMetadata struct {
	File   InvisibleFolderFile
	Values map[string]InvisibleFolderMetadataValue
}

// DownloadIfNewResult is the outcome of DownloadIfNew.
type DownloadIfNewResult struct {
	Downloaded  bool
	Revision    string
	Metadata    InvisibleFolderMetadata
	Bytes       []byte // set when downloaded to memory
	Destination string // set when downloaded to disk
}

// InvisibleFolder accesses file delivery through the authenticated Bedrock
// session. Obtain a token with the RequestInvisibleFolderToken option during
// authentication or a heartbeat.
type InvisibleFolder struct {
	client *Client

	tokenMutex sync.Mutex
	token      string
}

func newInvisibleFolder(client *Client) *InvisibleFolder {
	return &InvisibleFolder{client: client}
}

func (f *InvisibleFolder) setToken(token string) {
	f.tokenMutex.Lock()
	defer f.tokenMutex.Unlock()
	f.token = token
}

func (f *InvisibleFolder) clearToken() {
	f.tokenMutex.Lock()
	defer f.tokenMutex.Unlock()
	f.token = ""
}

// HasToken reports whether a Bedrock Invisible Folder token is held.
func (f *InvisibleFolder) HasToken() bool {
	f.tokenMutex.Lock()
	defer f.tokenMutex.Unlock()
	return f.token != ""
}

func validReferenceID(referenceID string) bool {
	if len(referenceID) < 4 || len(referenceID) > 128 {
		return false
	}
	for i := 0; i < len(referenceID); i++ {
		c := referenceID[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// percentEncode keeps alphanumerics and -_. unescaped and percent-encodes
// everything else with uppercase hex, matching the reference clients.
func percentEncode(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			encoded.WriteByte(c)
		default:
			encoded.WriteByte('%')
			encoded.WriteByte(hexDigits[c>>4])
			encoded.WriteByte(hexDigits[c&0x0F])
		}
	}
	return encoded.String()
}

func invisibleErrorMessage(response HTTPResponse) string {
	var parsed struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(response.Body, &parsed); err == nil {
		if parsed.Message != "" {
			return parsed.Message
		}
		if parsed.Error != "" {
			return parsed.Error
		}
	}
	return ""
}

func invisibleTransportError(action string, response HTTPResponse) *Error {
	if response.Err != nil {
		return fail(ErrTransport, "Invisible Folder %s failed: %s", action, response.Err.Error())
	}
	return fail(ErrTransport, "Invisible Folder %s returned HTTP %d.", action, response.StatusCode)
}

// Download fetches a file into memory.
func (f *InvisibleFolder) Download(ctx context.Context, referenceID string) ([]byte, error) {
	config := f.client.config
	if !strings.HasPrefix(config.InvisibleFolderBaseURL, "https://") {
		return nil, fail(ErrConfiguration, "Invisible Folder base URL must use HTTPS.")
	}
	if !validReferenceID(referenceID) {
		return nil, fail(ErrConfiguration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.")
	}

	f.tokenMutex.Lock()
	token := f.token
	f.tokenMutex.Unlock()
	if token == "" {
		return nil, fail(ErrSessionTerminated, "No Invisible Folder token is available. Request one during initialization or a heartbeat.")
	}

	response := f.client.transport().PostForm(
		ctx,
		f.client.endpoint(config.InvisibleFolderBaseURL, invisibleDownloadPrefix)+referenceID,
		url.Values{"invisiblefolder_token": {token}},
		nil)
	if !response.OK() {
		if message := invisibleErrorMessage(response); message != "" {
			return nil, fail(ErrTransport, "Invisible Folder download failed: %s", message)
		}
		return nil, invisibleTransportError("download", response)
	}
	return response.Body, nil
}

// DownloadToFile fetches a file and writes it to destination (unencrypted).
// Parent directories are not created.
func (f *InvisibleFolder) DownloadToFile(ctx context.Context, referenceID, destination string) error {
	if destination == "" {
		return fail(ErrConfiguration, "Invisible Folder download destination cannot be empty.")
	}
	bytes, err := f.Download(ctx, referenceID)
	if err != nil {
		return err
	}
	if writeErr := os.WriteFile(destination, bytes, 0o600); writeErr != nil {
		return fail(ErrLocalFailure, "Could not write Invisible Folder download destination.")
	}
	return nil
}

// Metadata fetches a file's description and metadata entries. keys selects
// specific entries; empty fetches all. The configured API key is sent when
// present, enabling metadata for API Available, Password Protected, and
// System Locker Simple files.
func (f *InvisibleFolder) Metadata(ctx context.Context, referenceID string, keys []string) (InvisibleFolderMetadata, error) {
	config := f.client.config
	if !strings.HasPrefix(config.InvisibleFolderBaseURL, "https://") {
		return InvisibleFolderMetadata{}, fail(ErrConfiguration, "Invisible Folder base URL must use HTTPS.")
	}
	if !validReferenceID(referenceID) {
		return InvisibleFolderMetadata{}, fail(ErrConfiguration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.")
	}

	headers := map[string]string{}
	if config.InvisibleFolderAPIKey != "" {
		headers["X-Api-Key"] = config.InvisibleFolderAPIKey
	}
	f.tokenMutex.Lock()
	if f.token != "" {
		headers["X-Invisiblefolder-Token"] = f.token
	}
	f.tokenMutex.Unlock()

	requestURL := f.client.endpoint(config.InvisibleFolderBaseURL, invisibleMetadataPrefix) + referenceID + invisibleMetadataSuffix
	for i, key := range keys {
		separator := "?"
		if i > 0 {
			separator = "&"
		}
		requestURL += separator + "keys[]=" + percentEncode(key)
	}

	response := f.client.transport().Get(ctx, requestURL, headers)
	if !response.OK() {
		if message := invisibleErrorMessage(response); message != "" {
			return InvisibleFolderMetadata{}, fail(ErrTransport, "Invisible Folder metadata request failed: %s", message)
		}
		return InvisibleFolderMetadata{}, invisibleTransportError("metadata request", response)
	}
	return parseInvisibleMetadata(response.Body)
}

// DownloadIfNew downloads only when the file's __revisions metadata differs
// from knownRevision. With a destination the file is written to disk;
// otherwise it is returned in memory.
func (f *InvisibleFolder) DownloadIfNew(ctx context.Context, referenceID string, knownRevision string, destination string) (DownloadIfNewResult, error) {
	currentMetadata, err := f.Metadata(ctx, referenceID, []string{revisionsMetadataKey})
	if err != nil {
		return DownloadIfNewResult{}, err
	}

	revision, ok := currentMetadata.Values[revisionsMetadataKey]
	if !ok {
		return DownloadIfNewResult{}, fail(ErrInvalidPayload, "Invisible Folder metadata did not contain __revisions.")
	}

	result := DownloadIfNewResult{Revision: revision.Value, Metadata: currentMetadata}
	if knownRevision != "" && knownRevision == result.Revision {
		return result, nil
	}

	result.Downloaded = true
	if destination != "" {
		if err := f.DownloadToFile(ctx, referenceID, destination); err != nil {
			return DownloadIfNewResult{}, err
		}
		result.Destination = destination
		return result, nil
	}
	bytes, err := f.Download(ctx, referenceID)
	if err != nil {
		return DownloadIfNewResult{}, err
	}
	result.Bytes = bytes
	return result, nil
}

func parseInvisibleMetadata(body []byte) (InvisibleFolderMetadata, error) {
	var envelope struct {
		Data struct {
			File     json.RawMessage `json:"file"`
			Metadata map[string]struct {
				Value     string  `json:"value"`
				CreatedAt *string `json:"created_at"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Data.File) == 0 || envelope.Data.Metadata == nil {
		return InvisibleFolderMetadata{}, fail(ErrInvalidPayload, "Invisible Folder metadata response has the wrong shape.")
	}
	var file struct {
		ID               string `json:"id"`
		ReferenceID      string `json:"reference_id"`
		Name             string `json:"name"`
		MimeType         string `json:"mime_type"`
		Size             uint64 `json:"size"`
		Downloads        uint64 `json:"downloads"`
		UploadedAt       string `json:"uploaded_at"`
		PermissionTypeID int64  `json:"permission_type_id"`
	}
	if err := json.Unmarshal(envelope.Data.File, &file); err != nil {
		return InvisibleFolderMetadata{}, fail(ErrInvalidPayload, "Invisible Folder file fields have the wrong type.")
	}
	for _, name := range []string{"id", "reference_id", "name", "mime_type", "uploaded_at"} {
		if !jsonFieldPresent(envelope.Data.File, name) {
			return InvisibleFolderMetadata{}, fail(ErrInvalidPayload, "Invisible Folder file field '%s' is missing.", name)
		}
	}

	metadata := InvisibleFolderMetadata{
		File: InvisibleFolderFile{
			ID:               file.ID,
			ReferenceID:      file.ReferenceID,
			Name:             file.Name,
			MimeType:         file.MimeType,
			Size:             file.Size,
			Downloads:        file.Downloads,
			UploadedAt:       file.UploadedAt,
			PermissionTypeID: file.PermissionTypeID,
		},
		Values: make(map[string]InvisibleFolderMetadataValue, len(envelope.Data.Metadata)),
	}
	for key, entry := range envelope.Data.Metadata {
		value := InvisibleFolderMetadataValue{Value: entry.Value}
		if entry.CreatedAt != nil {
			value.CreatedAt = *entry.CreatedAt
		}
		metadata.Values[key] = value
	}
	return metadata, nil
}

func jsonFieldPresent(raw json.RawMessage, name string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	_, ok := object[name]
	return ok
}
