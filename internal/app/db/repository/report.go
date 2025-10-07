package repository

import (
	"context"
	"eduanalytics/internal/app/db"
)

type IReportsRepository interface {
	GetStudentPerformanceReport(ctx context.Context, studentID int) (name string, attempts int, correct int, accuracy float64, err error)
	GetClassroomEngagementReport(ctx context.Context, classroomID int) (name string, participants int, avgTime float64, err error)
	GetContentEffectivenessReport(ctx context.Context, quizID int) ([]map[string]interface{}, error)
}

type ReportsRepository struct {
	DBService *db.DBService
}

func NewReportsRepository(dbService *db.DBService) IReportsRepository {
	return &ReportsRepository{
		DBService: dbService,
	}
}

func (r *ReportsRepository) GetStudentPerformanceReport(ctx context.Context, studentID int) (name string, attempts int, correct int, accuracy float64, err error) {
	query := `
        SELECT u.name, COUNT(r.id), SUM(CASE WHEN r.correct THEN 1 ELSE 0 END),
        ROUND(SUM(CASE WHEN r.correct THEN 1 ELSE 0 END)::decimal / COUNT(r.id), 2)
        FROM responses r JOIN users u ON u.id = r.student_id
        WHERE r.student_id = ? GROUP BY u.name;
    `
	row := r.DBService.GetDB().Raw(query, studentID).Row()
	err = row.Scan(&name, &attempts, &correct, &accuracy)
	return
}

func (r *ReportsRepository) GetClassroomEngagementReport(ctx context.Context, classroomID int) (name string, participants int, avgTime float64, err error) {
	query := `
        SELECT c.name, COUNT(DISTINCT r.student_id), AVG(r.time_spent)
        FROM responses r
        JOIN questions q ON q.id = r.question_id
        JOIN quizzes z ON q.quiz_id = z.id
        JOIN classrooms c ON z.classroom_id = c.id
        WHERE c.id = ? GROUP BY c.name;
    `
	row := r.DBService.GetDB().Raw(query, classroomID).Row()
	err = row.Scan(&name, &participants, &avgTime)
	return
}

func (r *ReportsRepository) GetContentEffectivenessReport(ctx context.Context, quizID int) ([]map[string]interface{}, error) {
	query := `
        SELECT q.question_text, COUNT(r.id),
        ROUND(SUM(CASE WHEN r.correct THEN 1 ELSE 0 END)::decimal / COUNT(r.id), 2)
        FROM responses r JOIN questions q ON q.id = r.question_id
        WHERE q.quiz_id = ? GROUP BY q.question_text;
    `
	rows, err := r.DBService.GetDB().Raw(query, quizID).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []map[string]interface{}
	for rows.Next() {
		var text string
		var attempts int
		var rate float64
		if err := rows.Scan(&text, &attempts, &rate); err != nil {
			return nil, err
		}
		reports = append(reports, map[string]interface{}{
			"question":         text,
			"attempts":         attempts,
			"correctness_rate": rate,
		})
	}
	return reports, nil
}
