package session

import (
	"context"
	"crypto/rand"
	"eduanalytics/internal/app/service/logger"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents a user session
type Session struct {
	SessionID string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UserAgent string
	IPAddress string
}

// ISessionManager defines the interface for session management
type ISessionManager interface {
	CreateSession(ctx context.Context, email, userAgent, ipAddress string) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteAllUserSessions(ctx context.Context, email string) error
	IsSessionValid(ctx context.Context, sessionID string) bool
	CleanupExpiredSessions(ctx context.Context)
	GetActiveSessions(ctx context.Context, email string) []*Session
}

// SessionManager manages user sessions in memory
type SessionManager struct {
	sessions      map[string]*Session
	userSessions  map[string][]string // email -> list of session IDs
	mu            sync.RWMutex
	sessionExpiry time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager(sessionExpiry time.Duration) ISessionManager {
	sm := &SessionManager{
		sessions:      make(map[string]*Session),
		userSessions:  make(map[string][]string),
		sessionExpiry: sessionExpiry,
	}

	// Start background cleanup goroutine
	go sm.startCleanupRoutine()

	return sm
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(ctx context.Context, email, userAgent, ipAddress string) (*Session, error) {
	log := logger.Logger(ctx)

	sessionID, err := generateSessionID()
	if err != nil {
		log.Errorf("Failed to generate session ID: %v", err)
		return nil, err
	}

	session := &Session{
		SessionID: sessionID,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(sm.sessionExpiry),
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Store session
	sm.sessions[sessionID] = session

	// Add to user sessions
	if _, exists := sm.userSessions[email]; !exists {
		sm.userSessions[email] = make([]string, 0)
	}
	sm.userSessions[email] = append(sm.userSessions[email], sessionID)

	log.Infof("Created session %s for user %s", sessionID, email)
	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, nil
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, nil
	}

	return session, nil
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	log := logger.Logger(ctx)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil
	}

	// Remove from sessions map
	delete(sm.sessions, sessionID)

	// Remove from user sessions
	if userSessionIDs, exists := sm.userSessions[session.Email]; exists {
		newSessions := make([]string, 0)
		for _, sid := range userSessionIDs {
			if sid != sessionID {
				newSessions = append(newSessions, sid)
			}
		}
		if len(newSessions) == 0 {
			delete(sm.userSessions, session.Email)
		} else {
			sm.userSessions[session.Email] = newSessions
		}
	}

	log.Infof("Deleted session %s for user %s", sessionID, session.Email)
	return nil
}

// DeleteAllUserSessions removes all sessions for a user
func (sm *SessionManager) DeleteAllUserSessions(ctx context.Context, email string) error {
	log := logger.Logger(ctx)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionIDs, exists := sm.userSessions[email]
	if !exists {
		return nil
	}

	// Delete all sessions
	for _, sessionID := range sessionIDs {
		delete(sm.sessions, sessionID)
	}

	// Remove user sessions entry
	delete(sm.userSessions, email)

	log.Infof("Deleted all sessions for user %s (count: %d)", email, len(sessionIDs))
	return nil
}

// IsSessionValid checks if a session is valid
func (sm *SessionManager) IsSessionValid(ctx context.Context, sessionID string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return false
	}

	// Check if session is expired
	return time.Now().Before(session.ExpiresAt)
}

// CleanupExpiredSessions removes all expired sessions
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) {
	log := logger.Logger(ctx)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	// Find and remove expired sessions
	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			// Remove from sessions
			delete(sm.sessions, sessionID)

			// Remove from user sessions
			if userSessionIDs, exists := sm.userSessions[session.Email]; exists {
				newSessions := make([]string, 0)
				for _, sid := range userSessionIDs {
					if sid != sessionID {
						newSessions = append(newSessions, sid)
					}
				}
				if len(newSessions) == 0 {
					delete(sm.userSessions, session.Email)
				} else {
					sm.userSessions[session.Email] = newSessions
				}
			}

			expiredCount++
		}
	}

	if expiredCount > 0 {
		log.Infof("Cleaned up %d expired sessions", expiredCount)
	}
}

// GetActiveSessions returns all active sessions for a user
func (sm *SessionManager) GetActiveSessions(ctx context.Context, email string) []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessionIDs, exists := sm.userSessions[email]
	if !exists {
		return []*Session{}
	}

	sessions := make([]*Session, 0)
	now := time.Now()

	for _, sessionID := range sessionIDs {
		if session, exists := sm.sessions[sessionID]; exists {
			if now.Before(session.ExpiresAt) {
				sessions = append(sessions, session)
			}
		}
	}

	return sessions
}

// startCleanupRoutine starts a background goroutine to cleanup expired sessions
func (sm *SessionManager) startCleanupRoutine() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		sm.CleanupExpiredSessions(ctx)
	}
}
