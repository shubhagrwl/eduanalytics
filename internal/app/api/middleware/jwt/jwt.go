package jwt

import (
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/session"

	"context"
	"eduanalytics/internal/app/service/logger"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type IJwtService interface {
	CreateNewTokens(ctx context.Context, email, userAgent, ipAddress string) (*TokenDetails, error)
	VerifyToken(ctx context.Context, tokenString string) (*dto.User, bool)
	RefreshToken(ctx context.Context, tokenString, userAgent, ipAddress string) (*TokenDetails, error)
	InvalidateSession(ctx context.Context, sessionID string) error
	InvalidateAllUserSessions(ctx context.Context, email string) error
}

type JwtService struct {
	DBClient       repository.IUsersRepository
	SessionManager session.ISessionManager
}

func NewJwtService(dbClient repository.IUsersRepository, sessionManager session.ISessionManager) IJwtService {
	return &JwtService{
		DBClient:       dbClient,
		SessionManager: sessionManager,
	}
}

type TokenDetails struct {
	AccessToken  string `json:"access_token"`
	AtExpires    int64  `json:"at_expires"`
	RefreshToken string `json:"refresh_token"`
	RtExpires    int64  `json:"rt_expires"`
	SessionID    string `json:"session_id"`
}

func (j *JwtService) CreateNewTokens(ctx context.Context, email, userAgent, ipAddress string) (*TokenDetails, error) {
	log := logger.Logger(ctx)
	log.Infof("Creating token for ", email)

	var err error

	// Create a new session
	sess, err := j.SessionManager.CreateSession(ctx, email, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}

	td := &TokenDetails{}
	td.SessionID = sess.SessionID
	td.AtExpires = time.Now().Add(time.Minute * time.Duration(constants.Config.JwtConfig.JWT_ACCESS_EXP)).Unix()

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["email"] = email
	atClaims["session_id"] = sess.SessionID
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	td.AccessToken, err = at.SignedString([]byte(constants.Config.JwtConfig.JWT_ACCESS_SECRET))
	if err != nil {
		return nil, err
	}

	// Generate refresh token and set expiry
	td.RtExpires = time.Now().Add(time.Hour * 24 * time.Duration(constants.Config.JwtConfig.JWT_REFRESH_EXP)).Unix()

	rtClaims := jwt.MapClaims{}
	rtClaims["email"] = email
	rtClaims["session_id"] = sess.SessionID
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

	td.RefreshToken, err = rt.SignedString([]byte(constants.Config.JwtConfig.JWT_REFRESH_SECRET))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (j *JwtService) RefreshToken(ctx context.Context, tokenString, userAgent, ipAddress string) (*TokenDetails, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(constants.Config.JwtConfig.JWT_REFRESH_SECRET), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		// Check if session is still valid
		if sessionID, exists := claims["session_id"].(string); exists {
			if !j.SessionManager.IsSessionValid(ctx, sessionID) {
				return nil, fmt.Errorf("session expired or invalid")
			}
		}

		return j.CreateNewTokens(ctx, claims["email"].(string), userAgent, ipAddress)
	}
	return nil, fmt.Errorf("invalid token")
}

func (j *JwtService) VerifyToken(ctx context.Context, tokenString string) (*dto.User, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(constants.Config.JwtConfig.JWT_ACCESS_SECRET), nil
	})
	if err != nil {
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		// Verify session is still active
		if sessionID, exists := claims["session_id"].(string); exists {
			if !j.SessionManager.IsSessionValid(ctx, sessionID) {
				return nil, false
			}
		}

		email := claims["email"].(string)
		u, err := j.DBClient.GetUserByEmail(ctx, email)
		if err != nil {
			return nil, false
		}

		return u, true
	}
	return nil, false
}

func (j *JwtService) InvalidateSession(ctx context.Context, sessionID string) error {
	log := logger.Logger(ctx)

	if err := j.SessionManager.DeleteSession(ctx, sessionID); err != nil {
		log.Errorf("Failed to invalidate session: %v", err)
		return err
	}

	log.Infof("Successfully invalidated session: %s", sessionID)
	return nil
}

func (j *JwtService) InvalidateAllUserSessions(ctx context.Context, email string) error {
	log := logger.Logger(ctx)

	if err := j.SessionManager.DeleteAllUserSessions(ctx, email); err != nil {
		log.Errorf("Failed to invalidate all sessions for user: %v", err)
		return err
	}

	log.Infof("Successfully invalidated all sessions for user: %s", email)
	return nil
}
