package server

const (
	HEALTH_CHECK = "/health-check"

	REGISTER = "/auth/register"
	LOGIN    = "/auth/login"
	REFRESH  = "/refresh"
	LOGOUT   = "/logout"

	QUIZZES            = "/quizzes"
	REPORT_STUDENT_PERFORMANCE   = "/student-performance"
	REPORT_CLASSROOM_ENGAGEMENT  = "/classroom-engagement"
	REPORT_CONTENT_EFFECTIVENESS = "/content-effectiveness"

	RESPONSES = "/responses"

	WS_QUIZ = "/ws/quiz"


	START_QUIZ         = "/quizzes/:id/start"
	ADD_QUIZ_QUESTION  = "/quizzes/:id/questions"
	GET_QUIZ_QUESTION  = "/quizzes/:id/questions/:qid"
	SUBMIT_QUIZ_ANSWER = "/quizzes/:id/submit"
	GET_QUIZ_RESULTS   = "/quizzes/:id/results"
	END_QUIZ           = "/quizzes/:id/end"

	WEB_SOCKET_QUIZ_STARTED       = "quiz_started"
	WEB_SOCKET_QUESTION_DISPLAYED = "question_displayed"
	WEB_SOCKET_ANSWER_SUBMITTED   = "answer_submitted"
	WEB_SOCKET_QUIZ_ENDED         = "quiz_ended"

	CAPTURE_EVENT       = "/events"
	CAPTURE_BATCH_EVENT = "/batch"

	CLASSROOMS             = "/classrooms"
	CLASSROOM_LIST_STUDENT = "/:id/students"
	CLASSROOM_DETAILS      = "/:id"
)
