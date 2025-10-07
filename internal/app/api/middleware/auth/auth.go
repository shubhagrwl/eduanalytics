package auth

import (
	"eduanalytics/internal/app/api/middleware/jwt"
	"eduanalytics/internal/app/constants"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

// authentication is a middleware that verify JWT token headers
func Authentication(jwt jwt.IJwtService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, err := getHeaderToken(ctx)
		if err != nil {
			return
		}

		claims, valid := jwt.VerifyToken(ctx, token)
		if !valid {
			return
		}
		ctx.Set(constants.CTK_CLAIM_KEY.String(), claims)
		ctx.Next()
	}
}

func getHeaderToken(ctx *gin.Context) (string, error) {
	header := string(ctx.GetHeader(constants.AUTHORIZATION))
	return extractToken(header)
}

func extractToken(header string) (string, error) {
	if strings.HasPrefix(header, constants.BEARER) {
		return header[len(constants.BEARER):], nil
	}
	return "", errors.New("token not found")
}
