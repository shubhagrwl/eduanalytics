package server

import (
	"context"
	"eduanalytics/internal/app/api/middleware/auth"
	"eduanalytics/internal/app/api/middleware/jwt"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/controller"
	"eduanalytics/internal/app/controller/events"
	"eduanalytics/internal/app/controller/ws"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/logger"
	"eduanalytics/internal/app/service/session"
	"strings"
	"time"

	helmet "github.com/danielkov/gin-helmet"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func Init(ctx context.Context) *gin.Engine {
	if strings.EqualFold(constants.Config.Environment, "prod") {
		gin.SetMode(gin.ReleaseMode)
	}
	return NewRouter(ctx)

}
func addCSPHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

func addReferrerPolicyHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

func addPermissionsPolicyHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Permissions-Policy", "default-src 'none'")
		c.Next()
	}
}

func addFeaturePolicyHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Feature-Policy", "none")
		c.Next()
	}
}

func NewRouter(ctx context.Context) *gin.Engine {
	log := logger.Logger(ctx)

	log.Info("setting up service and controllers")

	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(helmet.Default())
	//Content-Security-Policy
	router.Use(addCSPHeader())
	//Referrer-Policy
	router.Use(addReferrerPolicyHeader())
	//Permissions-Policy
	router.Use(addPermissionsPolicyHeader())
	//Feature-Policy
	router.Use(addFeaturePolicyHeader())

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Accept", "Content-Type", constants.AUTHORIZATION, constants.CORRELATION_KEY_ID.String()},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.Use(uuidInjectionMiddleware())

	// Initialize Database
	dbConn, err := db.Init(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	dbService := db.New(dbConn)

	// Initialize Repository
	usersRepository := repository.NewUsersRepository(dbService)
	eventsRepository := repository.NewEventsRepository(dbService)
	quizRepository := repository.NewQuizzesRepository(dbService)
	responseRepository := repository.NewResponseRepository(dbService)
	reportsRepository := repository.NewReportsRepository(dbService)

	// Initialize Session Manager (24 hours session expiry)
	sessionManager := session.NewSessionManager(24 * time.Hour)

	// Initialize JWT Service
	jwtService := jwt.NewJwtService(usersRepository, sessionManager)

	// Initialize Controllers
	oAuthController := controller.NewOAuthController(usersRepository, jwtService)
	eventsController := events.NewEventsController(eventsRepository)
	quizController := controller.NewQuizController(quizRepository, eventsController)
	responseController := controller.NewResponseController(responseRepository, eventsController)
	reportController := controller.NewReportController(reportsRepository, eventsController)
	wsController := ws.NewWSController(responseRepository, eventsController)

	v1 := router.Group("/api/v1")
	{
		v1.POST(REGISTER, oAuthController.Register)
		v1.POST(LOGIN, oAuthController.Login)

		authenticated := v1.Group("/auth")
		{
			authenticated.Use(auth.Authentication(jwtService))
			authenticated.POST(REFRESH, oAuthController.RefreshToken)
			authenticated.POST(LOGOUT, oAuthController.Logout)
		}
		quiz := v1.Group("")
		{
			quiz.Use(auth.Authentication(jwtService))
			quiz.POST(QUIZZES, quizController.CreateQuiz)
			quiz.POST(RESPONSES, responseController.SubmitResponse)
			quiz.GET(REPORT_STUDENT_PERFORMANCE, reportController.StudentPerformanceReport)
			quiz.GET(REPORT_CLASSROOM_ENGAGEMENT, reportController.ClassroomEngagementReport)
			quiz.GET(REPORT_CONTENT_EFFECTIVENESS, reportController.ContentEffectivenessReport)

			quiz.GET(WS_QUIZ, wsController.QuizWebSocket)
		}
	}

	return router
}

// uuidInjectionMiddleware injects the request context with a correlation id of type uuid
func uuidInjectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationId := c.GetHeader(string(constants.CORRELATION_KEY_ID))
		if len(correlationId) == 0 {
			correlationID, _ := uuid.NewUUID()
			correlationId = correlationID.String()
			c.Request.Header.Set(constants.CORRELATION_KEY_ID.String(), correlationId)
		}
		c.Writer.Header().Set(constants.CORRELATION_KEY_ID.String(), correlationId)

		c.Next()
	}
}
