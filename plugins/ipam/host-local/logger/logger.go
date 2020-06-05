package logger

import (
	"context"
	"fmt"

	uuid "github.com/satori/go.uuid"
	"k8s.io/klog/v2"
)

const (
	RequestID string = "RequestID"
)

func Infof(ctx context.Context, format string, args ...interface{}) {
	format = buildFormat(ctx, format)
	klog.InfoDepth(1, fmt.Sprintf(format, args...))
}

func Warningf(ctx context.Context, format string, args ...interface{}) {
	format = buildFormat(ctx, format)
	klog.WarningDepth(1, fmt.Sprintf(format, args...))
}

func Errorf(ctx context.Context, format string, args ...interface{}) {
	format = buildFormat(ctx, format)
	klog.ErrorDepth(1, fmt.Sprintf(format, args...))
}

func buildFormat(ctx context.Context, format string) string {
	if ctx != nil {
		if requestID := ctx.Value(RequestID); requestID != nil {
			format = "[" + (string)(RequestID) + ": " + ctx.Value(RequestID).(string) + "] " + format
		}
	}
	return format
}

func NewContext() context.Context {
	requestID := GetUUID()
	ctx := context.WithValue(context.TODO(), RequestID, requestID)
	return ctx
}

// GetUUID generates a uuid V4 with error and context concern
func GetUUID() string {
	return uuid.NewV4().String()
}
