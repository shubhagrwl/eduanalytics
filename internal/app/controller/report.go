package controller

import (
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/controller/events"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	"eduanalytics/internal/app/service/logger"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type IReportController interface {
	StudentPerformanceReport(c *gin.Context)
	ClassroomEngagementReport(c *gin.Context)
	ContentEffectivenessReport(c *gin.Context)
}

type ReportController struct {
	DBClient         repository.IReportsRepository
	EventsController events.IEventsController
}

func NewReportController(
	dbClient repository.IReportsRepository,
	eventsController events.IEventsController,
) IReportController {
	return &ReportController{
		DBClient:         dbClient,
		EventsController: eventsController,
	}
}

// GET /api/v1/reports/student-performance?student_id=1
func (r *ReportController) StudentPerformanceReport(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	id, err := strconv.Atoi(c.Query("student_id"))
	if err != nil {
		log.Error("error while converting student id")
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	name, attempts, correct, accuracy, err := r.DBClient.GetStudentPerformanceReport(ctx, id)
	if err != nil {
		log.Error("error while getting student performance report", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	var response = make(map[string]interface{})
	response["student"] = name
	response["attempts"] = attempts
	response["correct"] = correct
	response["accuracy"] = accuracy

	RespondWithSuccess(c, http.StatusOK, "Student performance report", response)
}

// GET /api/v1/reports/classroom-engagement?classroom_id=10
func (r *ReportController) ClassroomEngagementReport(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	id, err := strconv.Atoi(c.Query("classroom_id"))
	if err != nil {
		log.Error("error while converting classroom_id")
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	name, participants, avgTime, err := r.DBClient.GetClassroomEngagementReport(ctx, id)
	if err != nil {
		log.Error("error while getting classroom engagement report", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	var response = make(map[string]interface{})
	response["classroom"] = name
	response["participants"] = participants
	response["avg_time"] = avgTime

	RespondWithSuccess(c, http.StatusOK, "Classroom Engagement Report", response)
}

// GET /api/v1/reports/content-effectiveness?quiz_id=15
func (r *ReportController) ContentEffectivenessReport(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	id, err := strconv.Atoi(c.Query("quiz_id"))
	if err != nil {
		log.Error("error while converting quiz_id")
		RespondWithError(c, http.StatusBadRequest, constants.BadRequest)
		return
	}

	reports, err := r.DBClient.GetContentEffectivenessReport(ctx, id)
	if err != nil {
		log.Error("error while getting content effectiveness report", err)
		RespondWithError(c, http.StatusInternalServerError, constants.InternalServerError)
		return
	}

	var response = make(map[string]interface{})
	response["reports"] = reports
	RespondWithSuccess(c, http.StatusOK, "Content Effectiveness Report", response)
}
