package casbin

import (
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/service/logger"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

func Authorizer(enforcer *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := logger.Logger(c.Request.Context())

		claims, exists := c.Get(constants.CTK_CLAIM_KEY.String())
		if !exists {
			if err := checkPermission(enforcer, constants.ROLE_PUBLIC, c.Request.URL.Path, c.Request.Method); err != nil {
				log.Warnf("Public access denied for path: %s", c.Request.URL.Path)
				c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		user, ok := claims.(*dto.User)
		if !ok {
			log.Error("Failed to get user from claims")
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid user claims"})
			c.Abort()
			return
		}

		if err := checkPermission(enforcer, user.Role, c.Request.URL.Path, c.Request.Method); err != nil {
			log.Warnf("Access denied for user: %s, role: %s, path: %s, method: %s",
				user.Email, user.Role, c.Request.URL.Path, c.Request.Method)
			c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to access this resource"})
			c.Abort()
			return
		}

		log.Infof("Access granted for user: %s, role: %s, path: %s", user.Email, user.Role, c.Request.URL.Path)
		c.Next()
	}
}

func checkPermission(enforcer *casbin.Enforcer, role, path, method string) error {
	allowed, err := enforcer.Enforce(role, path, method)
	if err != nil {
		return err
	}

	if !allowed {
		return gin.Error{
			Err:  http.ErrNotSupported,
			Type: gin.ErrorTypePublic,
			Meta: "permission denied",
		}
	}

	return nil
}

func InitEnforcer(modelPath, policyPath string) (*casbin.Enforcer, error) {
	enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, err
	}

	// Load policy from file
	err = enforcer.LoadPolicy()
	if err != nil {
		return nil, err
	}

	return enforcer, nil
}
