package ws

import (
	"eduanalytics/internal/app/controller/events"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	"eduanalytics/internal/app/service/logger"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type Client struct {
	Conn      *websocket.Conn
	UserID    int
	Classroom int
	IsTeacher bool
}

var mu sync.Mutex
var classroomClients = make(map[int][]*Client)

type WSMessage struct {
	Event        string                 `json:"event"`
	UserID       int                    `json:"user_id"`
	ClassroomID  int                    `json:"classroom_id"`
	QuizID       int                    `json:"quiz_id"`
	QuestionID   int                    `json:"question_id"`
	QuestionText string                 `json:"question_text,omitempty"`
	Answer       string                 `json:"answer,omitempty"`
	Correct      bool                   `json:"correct,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type IWSController interface {
	QuizWebSocket(c *gin.Context)
}

type WSController struct {
	DBClient         repository.IResponseRepository
	EventsController events.IEventsController
}

func NewWSController(
	dbClient repository.IResponseRepository,
	eventsController events.IEventsController,
) IWSController {
	return &WSController{
		DBClient:         dbClient,
		EventsController: eventsController,
	}
}

func (q *WSController) QuizWebSocket(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error("WebSocket error:", err)
		return
	}
	defer conn.Close()

	var initMsg WSMessage
	if err := conn.ReadJSON(&initMsg); err != nil {
		log.Error("WebSocket error:", err)
		return
	}

	client := &Client{Conn: conn, UserID: initMsg.UserID, Classroom: initMsg.ClassroomID}
	mu.Lock()
	classroomClients[client.Classroom] = append(classroomClients[client.Classroom], client)
	mu.Unlock()

	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			removeClient(client)
			return
		}

		switch msg.Event {
		case "quiz_started", "question_displayed", "quiz_ended":
			q.EventsController.PublishEvent(dto.Event{
				EventName:   msg.Event,
				App:         "whiteboard",
				UserId:      msg.UserID,
				QuizId:      msg.QuizID,
				ClassroomId: msg.ClassroomID,
				Metadata:    msg.Metadata,
			})
			broadcastToClassroom(client.Classroom, msg)

		case "answer_submitted":

			var timeSpent float64
			if t, ok := msg.Metadata["time_spent"].(float64); ok {
				timeSpent = t
			}

			if err := q.DBClient.CreateResponse(ctx, &dto.Response{
				StudentId:  msg.UserID,
				QuestionId: msg.QuestionID,
				Answer:     msg.Answer,
				Correct:    msg.Correct,
				TimeSpent:  timeSpent,
			}); err != nil {
				log.Error("WebSocket error:", err)
			}

			q.EventsController.PublishEvent(dto.Event{
				EventName:   "answer_submitted",
				App:         "notebook",
				UserId:      msg.UserID,
				QuizId:      msg.QuizID,
				ClassroomId: msg.ClassroomID,
				Metadata:    msg.Metadata,
			})

			msg.Event = "answer_received"
			broadcastToClassroom(msg.ClassroomID, msg)
		}
	}
}

func broadcastToClassroom(classroomID int, msg WSMessage) {
	mu.Lock()
	defer mu.Unlock()
	for _, cl := range classroomClients[classroomID] {
		cl.Conn.WriteJSON(msg)
	}
}

func removeClient(c *Client) {
	mu.Lock()
	defer mu.Unlock()
	clients := classroomClients[c.Classroom]
	for i, cl := range clients {
		if cl == c {
			classroomClients[c.Classroom] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
}
