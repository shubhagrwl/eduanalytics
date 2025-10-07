package controller

import (
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/controller/events"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	"eduanalytics/internal/app/service/dto/response"
	"eduanalytics/internal/app/service/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

type IResponseController interface {
	SubmitResponse(c *gin.Context)
}

type ResponseController struct {
	DBClient         repository.IResponseRepository
	EventsController events.IEventsController
}

func NewResponseController(
	dbClient repository.IResponseRepository,
	eventsController events.IEventsController,
) IResponseController {
	return &ResponseController{
		DBClient:         dbClient,
		EventsController: eventsController,
	}
}

func (r *ResponseController) SubmitResponse(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	var response dto.Response
	if err := c.BindJSON(&response); err != nil {
		log.Error("error while binding response", err)
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	if err := r.DBClient.CreateResponse(ctx, &response); err != nil {
		log.Error("error while creating response", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	r.EventsController.PublishEvent(dto.Event{
		EventName: "question_submitted",
		App:       "notebook",
		UserId:    response.StudentId,
		Metadata: map[string]interface{}{
			"question_id": response.QuestionId,
			"answer":      response.Answer,
			"correct":     response.Correct,
			"time_spent":  response.TimeSpent,
		},
	})

	RespondWithSuccess(c, http.StatusOK, "Response recorded successfully", response)
}

func RespondWithError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, response.ResponseV2{Success: false, Message: message})
}

func RespondWithSuccess(c *gin.Context, code int, message string, data interface{}) {
	c.JSON(code, response.ResponseV2{Success: true, Message: message, Data: data})
}
