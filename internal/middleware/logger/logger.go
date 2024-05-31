package logger

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
)

type loggerKey string

const contextKey loggerKey = "logger"

var logger *logrus.Logger

func Initialize(loggingVerbosity string) {
	level, err := logrus.ParseLevel(loggingVerbosity)
	// Signal that we are about to enter the desired verbosity
	log.Printf("Setting logging verbosity level to: %s (%d)\n", loggingVerbosity, level)

	if err != nil {
		log.Fatalf("Invalid logging verbosity: %v", err)
	}

	logger = logrus.New()
	// Set logrus formatter
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Set log level to output all levels
	logger.SetLevel(level)

	// Set log output to stdout
	logger.SetOutput(os.Stdout)
}

// InjectLogger injects logger in the requests' context
func InjectLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loggerObj := logger.WithFields(logrus.Fields{
			"client-addr": r.RemoteAddr,
		})

		// Add the logger to the request's context for easy access in handlers
		ctx := context.WithValue(r.Context(), contextKey, loggerObj)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// FromContext fetches the logger from the context otherwise it generates a new one
func FromContext(ctx context.Context) *logrus.Entry {
	if logger, ok := ctx.Value(contextKey).(*logrus.Entry); ok {
		return logger
	}
	return logger.WithContext(ctx)
}

// CloneToNewIfPresent assigns the current logger to the returning ctx (useful when you want a different
// deadline but want to preserve the logger)
func CloneToNewIfPresent(originCtx context.Context, newCtx context.Context) context.Context {
	if logger, ok := originCtx.Value(contextKey).(*logrus.Entry); ok {
		return context.WithValue(newCtx, contextKey, logger)
	}
	return newCtx
}

func ContextWithField(ctx context.Context, keyValues ...interface{}) context.Context {
	var logWithField logrus.FieldLogger = FromContext(ctx)
	if len(keyValues)%2 != 0 {
		logWithField.Fatalf("Expected to have key-value pairs in log statement, got: %v", keyValues)
	}

	for i := 0; i < len(keyValues); i += 2 {
		logWithField = logWithField.WithField(keyValues[i].(string), keyValues[i+1])
	}

	return context.WithValue(ctx, contextKey, logWithField)
}
