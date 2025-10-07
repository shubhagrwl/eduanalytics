package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
)

type IEventsRepository interface {
	CreateEvent(ctx context.Context, event *dto.Event) error
	GetEvent(ctx context.Context, where string) (*dto.Event, error)
}

type EventsRepository struct {
	DBService *db.DBService
}

func NewEventsRepository(dbService *db.DBService) IEventsRepository {
	return &EventsRepository{
		DBService: dbService,
	}
}

func (r *EventsRepository) CreateEvent(ctx context.Context, event *dto.Event) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.EVENT_TABLE).Create(event).Error; err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (r *EventsRepository) GetEvent(ctx context.Context, where string) (*dto.Event, error) {
	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)
	var event dto.Event

	if err := tx.Table(dto.EVENT_TABLE).Where(where).First(&event).Error; err != nil {
		return &event, err
	}
	return &event, nil
}
