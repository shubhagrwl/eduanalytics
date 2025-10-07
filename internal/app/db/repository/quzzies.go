package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
)

type IQuizzesRepository interface {
	CreateQuiz(ctx context.Context, quiz *dto.Quiz) error
	GetQuiz(ctx context.Context, where string) (*dto.Quiz, error)
}

type QuizzesRepository struct {
	DBService *db.DBService
}

func NewQuizzesRepository(dbService *db.DBService) IQuizzesRepository {
	return &QuizzesRepository{
		DBService: dbService,
	}
}

func (r *QuizzesRepository) CreateQuiz(ctx context.Context, quiz *dto.Quiz) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.QUIZ_TABLE).Create(quiz).Error; err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (r *QuizzesRepository) GetQuiz(ctx context.Context, where string) (*dto.Quiz, error) {
	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)
	var quiz dto.Quiz

	if err := tx.Table(dto.QUIZ_TABLE).Where(where).First(&quiz).Error; err != nil {
		return &quiz, err
	}
	return &quiz, nil
}
