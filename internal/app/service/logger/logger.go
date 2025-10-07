package logger

import (
	"context"
	"os"
	"path"

	"eduanalytics/internal/app/constants"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var SugarLogger *zap.SugaredLogger

func InitLogger() {
	writerSyncer := getLogWriter()
	var core zapcore.Core
	if constants.Config.Environment == "dev" {
		core = zapcore.NewTee(
			zapcore.NewCore(getConsoleEncoder(), zapcore.AddSync(os.Stdout), zapcore.InfoLevel),
			zapcore.NewCore(getFileEncoder(), writerSyncer, zapcore.InfoLevel),
		)
	} else {
		core = zapcore.NewTee(
			zapcore.NewCore(getConsoleEncoder(), zapcore.AddSync(os.Stdout), zapcore.InfoLevel),
			zapcore.NewCore(getFileEncoder(), writerSyncer, zapcore.InfoLevel),
		)
	}
	logger := zap.New(core, zap.AddCaller())
	SugarLogger = logger.Sugar()
}

func getConsoleEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}

func getFileEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}

func getLogWriter() zapcore.WriteSyncer {
	logFilePath := constants.Config.LogConfig.LOG_FILE_PATH
	logFileName := constants.Config.LogConfig.LOG_FILE_NAME
	logFileMaxSize := constants.Config.LogConfig.LOG_FILE_MAXSIZE
	logFileMaxBackups := constants.Config.LogConfig.LOG_FILE_MAXBACKUP
	logFileMaxAge := constants.Config.LogConfig.LOG_FILE_MAXAGE
	logFile := path.Join(logFilePath, logFileName)
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    logFileMaxSize,
		MaxBackups: logFileMaxBackups,
		MaxAge:     logFileMaxAge,
		Compress:   true,
		LocalTime:  true,
	}
	return zapcore.AddSync(lumberJackLogger)
}

// Logger returns a zap logger with as much context as possible
func Logger(ctx context.Context) *zap.SugaredLogger {
	newLogger := SugarLogger
	if ctxCorrelationID, ok := ctx.Value(constants.CORRELATION_KEY_ID).(string); ok {
		newLogger = newLogger.With(zap.String(constants.CORRELATION_KEY_ID.String(), ctxCorrelationID))
	}

	return newLogger
}
