package controller

import (
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/controller/events"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	"eduanalytics/internal/app/service/logger"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

type IQuizController interface {
	CreateQuiz(c *gin.Context)
}

type QuizController struct {
	DBClient         repository.IQuizzesRepository
	EventsController events.IEventsController
}

func NewQuizController(
	dbClient repository.IQuizzesRepository,
	eventsController events.IEventsController,
) IQuizController {
	return &QuizController{
		DBClient:         dbClient,
		EventsController: eventsController,
	}
}

func (q *QuizController) CreateQuiz(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	var quiz dto.Quiz
	err := json.NewDecoder(c.Request.Body).Decode(&quiz)
	if err != nil {
		log.Errorf(constants.BadRequest, err)
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	if err := q.DBClient.CreateQuiz(ctx, &quiz); err != nil {
		log.Error("error while creating quiz", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	q.EventsController.PublishEvent(dto.Event{
		EventName:   "quiz_created",
		App:         "whiteboard",
		UserId:      quiz.CreatedBy,
		QuizId:      quiz.Id,
		ClassroomId: quiz.ClassroomId,
	})

	RespondWithSuccess(c, http.StatusOK, "Quiz created successfully", quiz)
}
