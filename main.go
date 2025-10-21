package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"github.com/Nativu5/terasu-proxy/internal/proxy"
	"github.com/Nativu5/terasu-proxy/internal/utils"
)

func main() {
	logger := logrus.New()
	logger.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"component", "peer", "dst"},
	})
	logger.SetLevel(logrus.InfoLevel)

	cmd := utils.NewRootCommand(func(config utils.Config) error {
		level, err := logrus.ParseLevel(config.LogLevel)
		if err != nil {
			return fmt.Errorf("invalid log level: %w", err)
		}
		logger.SetLevel(level)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		server := proxy.NewServer(config, logrus.NewEntry(logger))
		return server.Run(ctx)
	})

	if err := cmd.Execute(); err != nil {
		logger.WithError(err).Fatal("command failed")
	}
}
