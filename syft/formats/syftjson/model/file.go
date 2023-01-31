package model

import (
	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type File struct {
	ID       string             `json:"id"`
	Location source.Coordinates `json:"location"`
	Metadata *FileMetadataEntry `json:"metadata,omitempty"`
	Contents string             `json:"contents,omitempty"`
	Digests  []file.Digest      `json:"digests,omitempty"`
}

type FileMetadataEntry struct {
	Mode            int                  `json:"mode"`
	Type            stereoscopeFile.Type `json:"type"`
	LinkDestination string               `json:"linkDestination,omitempty"`
	UserID          int                  `json:"userID"`
	GroupID         int                  `json:"groupID"`
	MIMEType        string               `json:"mimeType"`
}
