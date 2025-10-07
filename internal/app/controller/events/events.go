package events

import (
	"context"
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/logger"
	"encoding/json"
	"time"
)

var EventQueue = make(chan dto.Event, 5000)

type IEventsController interface {
	StartWorkerPool(ctx context.Context, workers int)
	PublishEvent(e dto.Event)
}

type EventsController struct {
	DBClient repository.IEventsRepository
}

func NewEventsController(
	dbClient repository.IEventsRepository,
) IEventsController {
	return &EventsController{
		DBClient: dbClient,
	}
}

// PublishEvent adds new event to queue
func (e *EventsController) PublishEvent(event dto.Event) {
	EventQueue <- event
}

// StartWorkerPool runs concurrent consumers
func (e *EventsController) StartWorkerPool(ctx context.Context, workers int) {
	log := logger.Logger(ctx)
	for i := 0; i < workers; i++ {
		go func(id int) {
			for event := range EventQueue {
				event.Timestamp = time.Now()
				event.Metadata, _ = json.Marshal(event.Metadata)

				if err := e.DBClient.CreateEvent(ctx, &event); err != nil {
					log.Errorf("Worker %d failed: %v\n", id, err)
					return
				}
			}
		}(i)
	}
}
