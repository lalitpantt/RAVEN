package output

import (
	"context"
	"raven/internal/model"
)

// OutputSink represents a destination for normalized RAVEN events.
type OutputSink interface {
	Emit(ctx context.Context, event *model.NormalizedEvent) error
	Flush() error
	Close() error
}
