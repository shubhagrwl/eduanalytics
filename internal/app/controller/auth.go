package controller

import (
	"eduanalytics/internal/app/api/middleware/jwt"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	"eduanalytics/internal/app/service/logger"
	"eduanalytics/internal/app/service/util"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// IOAuthController represents the interface for OAuthController
type IOAuthController interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	RefreshToken(c *gin.Context)
	Logout(c *gin.Context)
}

// OAuthController is the implementation of the IOAuthController interface
type OAuthController struct {
	DBClient repository.IUsersRepository
	JWT      jwt.IJwtService
}

// NewOAuthController creates a new instance of OAuthController
func NewOAuthController(
	dbClient repository.IUsersRepository,
	jwt jwt.IJwtService,
) IOAuthController {
	return &OAuthController{
		DBClient: dbClient,
		JWT:      jwt,
	}
}

func (u *OAuthController) Register(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	var dataFromBody dto.User
	err := json.NewDecoder(c.Request.Body).Decode(&dataFromBody)
	if err != nil {
		log.Errorf(constants.BadRequest, err)
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	dataFromBody.Password, err = util.GenerateHash(dataFromBody.Password)
	if err != nil {
		log.Error("error while generating hash", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	if err := u.DBClient.CreateUser(ctx, &dataFromBody); err != nil {
		log.Error("error while updating user", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}
	dataFromBody.Password = ""

	RespondWithSuccess(c, http.StatusAccepted, "User Created Successfully", dataFromBody)
}

func (u *OAuthController) Login(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	var dataFromBody dto.User
	err := json.NewDecoder(c.Request.Body).Decode(&dataFromBody)
	if err != nil {
		log.Errorf(constants.BadRequest, err)
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	user, err := u.DBClient.GetUserByEmail(ctx, dataFromBody.Email)
	if err != nil {
		log.Error("error while fetching user", err)
		RespondWithError(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !util.ValidatePassword(dataFromBody.Password, user.Password) {
		log.Error("invalid password")
		RespondWithError(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Get user agent and IP address
	userAgent := c.Request.UserAgent()
	ipAddress := c.ClientIP()

	token, err := u.JWT.CreateNewTokens(ctx, user.Email, userAgent, ipAddress)
	if err != nil {
		log.Error("error while creating new tokens", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	RespondWithSuccess(c, http.StatusOK, "Login Successfully", token)
}

func (u *OAuthController) RefreshToken(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	refreshToken := c.GetHeader(constants.AUTHORIZATION)
	if refreshToken == "" {
		// Try to get from body
		var requestBody struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(c.Request.Body).Decode(&requestBody); err == nil {
			refreshToken = requestBody.RefreshToken
		}
	}

	if refreshToken == "" {
		log.Error("refresh token not provided")
		RespondWithError(c, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Remove "Bearer " prefix if present
	if len(refreshToken) > len(constants.BEARER) && refreshToken[:len(constants.BEARER)] == constants.BEARER {
		refreshToken = refreshToken[len(constants.BEARER):]
	}

	// Get user agent and IP address
	userAgent := c.Request.UserAgent()
	ipAddress := c.ClientIP()

	token, err := u.JWT.RefreshToken(ctx, refreshToken, userAgent, ipAddress)
	if err != nil {
		log.Error("error while refreshing token", err)
		RespondWithError(c, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}
	RespondWithSuccess(c, http.StatusOK, "Token Refreshed Successfully", token)
}

func (u *OAuthController) Logout(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	// Get access token from Authorization header
	accessToken := c.GetHeader(constants.AUTHORIZATION)
	if accessToken == "" {
		log.Error("access token not found in header")
		RespondWithError(c, http.StatusBadRequest, "Access token is required")
		return
	}

	// Remove "Bearer " prefix if present
	if len(accessToken) > len(constants.BEARER) && accessToken[:len(constants.BEARER)] == constants.BEARER {
		accessToken = accessToken[len(constants.BEARER):]
	}

	// Parse token to extract session ID
	var sessionID string

	// We need to parse the token to get the session ID
	// Using a simple token parser without validation since we just need the session ID
	if token, err := util.ParseTokenClaims(accessToken); err == nil {
		if sid, ok := token["session_id"].(string); ok {
			sessionID = sid
		}
	}

	if sessionID == "" {
		log.Error("session_id not found in token")
		RespondWithError(c, http.StatusBadRequest, "Invalid token format")
		return
	}

	// Invalidate the session
	if err := u.JWT.InvalidateSession(ctx, sessionID); err != nil {
		log.Error("error while invalidating session", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	RespondWithSuccess(c, http.StatusOK, "Logout Successfully", nil)
}
