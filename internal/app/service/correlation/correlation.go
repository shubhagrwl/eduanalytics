package correlation

import (
	"context"

	"eduanalytics/internal/app/constants"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// WithReqContext returns logger
func WithReqContext(c *gin.Context) context.Context {
	correlationId := c.GetHeader(constants.CORRELATION_KEY_ID.String())
	if len(correlationId) == 0 {
		correlationID, _ := uuid.NewUUID()
		correlationId = correlationID.String()
		c.Request.Header.Set(constants.CORRELATION_KEY_ID.String(), correlationId)
	}
	c.Writer.Header().Set(constants.CORRELATION_KEY_ID.String(), correlationId)

	requestCtx := context.WithValue(context.Background(), constants.CORRELATION_KEY_ID, correlationId)
	return requestCtx
}

func ContextCorrelationId(ctx context.Context) string {
	if ctxCorrelationID, ok := ctx.Value(constants.CORRELATION_KEY_ID).(string); ok {
		return ctxCorrelationID
	}
	return ""
}

func ContextFromCorrelation(correlationId string) context.Context {
	if len(correlationId) == 0 {
		correlationID, _ := uuid.NewUUID()
		correlationId = correlationID.String()
	}
	return context.WithValue(context.Background(), constants.CORRELATION_KEY_ID, correlationId)
}
