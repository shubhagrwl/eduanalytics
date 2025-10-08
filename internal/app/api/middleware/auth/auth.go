package auth

import (
	"eduanalytics/internal/app/api/middleware/jwt"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/service/logger"
	"errors"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

// Authentication is a middleware that verifies JWT token and enforces RBAC authorization
func Authentication(jwtService jwt.IJwtService, enforcer *casbin.Enforcer) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		log := logger.Logger(ctx.Request.Context())

		token, err := getHeaderToken(ctx)
		if err != nil {
			log.Warnf("No token found for path: %s", ctx.Request.URL.Path)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - No token provided"})
			ctx.Abort()
			return
		}

		claims, valid := jwtService.VerifyToken(ctx, token)
		if !valid {
			log.Warnf("Invalid token for path: %s", ctx.Request.URL.Path)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - Invalid token"})
			ctx.Abort()
			return
		}

		ctx.Set(constants.CTK_CLAIM_KEY.String(), claims)

		user := claims
		if user == nil {
			log.Error("User claims are nil")
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Invalid user claims"})
			ctx.Abort()
			return
		}

		allowed, err := enforcer.Enforce(user.Role, ctx.Request.URL.Path, ctx.Request.Method)
		if err != nil {
			log.Errorf("Casbin enforcement error: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			ctx.Abort()
			return
		}

		if !allowed {
			log.Warnf("Access denied for user: %s, role: %s, path: %s, method: %s",
				user.Email, user.Role, ctx.Request.URL.Path, ctx.Request.Method)
			ctx.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to access this resource"})
			ctx.Abort()
			return
		}

		log.Infof("Access granted for user: %s, role: %s, path: %s", user.Email, user.Role, ctx.Request.URL.Path)
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
