// Package logging provides structured logging utilities for gRPC services.
package logging

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a gRPC interceptor that logs all requests.
func UnaryServerInterceptor(logger *log.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Get client address if available
		clientAddr := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			clientAddr = p.Addr.String()
		}

		// Call the handler
		resp, err := handler(ctx, req)

		// Log the request
		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			} else {
				code = codes.Unknown
			}
		}

		logger.Printf("method=%s client=%s code=%s duration=%v",
			info.FullMethod, clientAddr, code, duration)

		if err != nil {
			logger.Printf("error: %v", err)
		}

		return resp, err
	}
}

// PanicRecoveryInterceptor returns a gRPC interceptor that recovers from panics.
func PanicRecoveryInterceptor(logger *log.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Printf("PANIC recovered: method=%s panic=%v", info.FullMethod, r)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}
