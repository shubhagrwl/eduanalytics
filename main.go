package main

import (
	"context"
	"eduanalytics/internal/app/api/server"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/service/logger"
	"eduanalytics/internal/config"
	"fmt"
)

func main() {
	var err error
	// Returns a struct with values from env variables
	constants.Config, err = config.LoadConfig()
	if err != nil {
		panic(err.Error())
	}
	// Creates an empty context that can be passed around
	ctx := context.Background()

	// Initialize the logger
	logger.InitLogger()
	log := logger.Logger(ctx)

	r := server.Init(ctx)
	if err := r.Run(fmt.Sprintf("%s:%s", constants.Config.HTTPServerConfig.HTTPSERVER_LISTEN, constants.Config.HTTPServerConfig.HTTPSERVER_PORT)); err != nil {
		log.Fatal("Server not able to startup with error: ", err)
	}
}
