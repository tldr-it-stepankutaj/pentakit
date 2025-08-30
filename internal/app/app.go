package app

import (
	"context"
	"time"
)

// Context carries app-wide dependencies and metadata.
type Context struct {
	Ctx       context.Context
	Config    Config
	Workspace WorkspaceHandle
	Now       time.Time
}

// WorkspaceHandle is a minimal contract the workspace package provides.
type WorkspaceHandle interface {
	Path(parts ...string) string
}
