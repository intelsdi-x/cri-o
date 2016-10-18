package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/containers/storage/pkg/reexec"
	"github.com/kubernetes-incubator/cri-o/server"
	"github.com/opencontainers/runc/libcontainer/selinux"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

const ociConfigPath = "/etc/ocid.conf"

func mergeConfig(config *server.Config, ctx *cli.Context) error {
	// Don't parse the config if the user explicitly set it to "".
	if path := ctx.GlobalString("config"); path != "" {
		if err := config.FromFile(path); err != nil {
			if ctx.GlobalIsSet("config") || !os.IsNotExist(err) {
				return err
			}

			// We don't error out if --config wasn't explicitly set and the
			// default doesn't exist. But we will log a warning about it, so
			// the user doesn't miss it.
			logrus.Warnf("default configuration file does not exist: %s", ociConfigPath)
		}
	}

	// Override options set with the CLI.
	if ctx.GlobalIsSet("conmon") {
		config.Conmon = ctx.GlobalString("conmon")
	}
	if ctx.GlobalIsSet("pause_command") {
		config.PauseCommand = ctx.GlobalString("pause_command")
	}
	if ctx.GlobalIsSet("pause_image") {
		config.PauseImage = ctx.GlobalString("pause_image")
	}
	if ctx.GlobalIsSet("root") {
		config.Root = ctx.GlobalString("root")
	}
	if ctx.GlobalIsSet("runroot") {
		config.RunRoot = ctx.GlobalString("runroot")
	}
	if ctx.GlobalIsSet("storage_driver") {
		config.Storage = ctx.GlobalString("storage_driver")
	}
	if ctx.GlobalIsSet("storage_option") {
		config.StorageOption = ctx.GlobalStringSlice("storage_option")
	}
	if ctx.GlobalIsSet("default_transport") {
		config.StorageOption = ctx.GlobalStringSlice("default_transport")
	}
	if ctx.GlobalIsSet("listen") {
		config.Listen = ctx.GlobalString("listen")
	}
	if ctx.GlobalIsSet("runtime") {
		config.Runtime = ctx.GlobalString("runtime")
	}
	if ctx.GlobalIsSet("selinux") {
		config.SELinux = ctx.GlobalBool("selinux")
	}
	return nil
}

type byName []cli.Flag

func (f byName) Len() int {
	return len(f)
}
func (f byName) Less(i, j int) bool {
	return f[i].GetName() < f[j].GetName()
}
func (f byName) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func catchShutdown(gserver *grpc.Server, sserver *server.Server, signalled *bool) {
	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			switch s {
			case syscall.SIGINT:
				logrus.Debugf("Caught SIGINT")
			case syscall.SIGTERM:
				logrus.Debugf("Caught SIGTERM")
			default:
				continue
			}
			*signalled = true
			gserver.GracefulStop()
			return
		}
	}()
}

func main() {
	if reexec.Init() {
		return
	}
	app := cli.NewApp()
	app.Name = "ocid"
	app.Usage = "ocid server"
	app.Version = "0.0.1"
	app.Metadata = map[string]interface{}{
		"config": DefaultConfig(),
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: ociConfigPath,
			Usage: "path to configuration file",
		},
		cli.StringFlag{
			Name:  "conmon",
			Usage: "path to the conmon executable",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output for logging",
		},
		cli.StringFlag{
			Name:  "listen",
			Usage: "path to ocid socket",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "set the log file path where internal debug information is written",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "set the format used by logs ('text' (default), or 'json')",
		},
		cli.StringFlag{
			Name:  "pause_command",
			Usage: "name of the pause command in the pause image",
		},
		cli.StringFlag{
			Name:  "pause_image",
			Usage: "name of the pause image",
		},
		cli.StringFlag{
			Name:  "root",
			Usage: "ocid root dir",
		},
		cli.StringFlag{
			Name:  "runroot",
			Usage: "ocid state dir",
		},
		cli.StringFlag{
			Name:  "storage_driver",
			Usage: "storage driver",
		},
		cli.StringSliceFlag{
			Name:  "storage_option",
			Usage: "storage driver option",
		},
		cli.StringFlag{
			Name:  "default_transport",
			Usage: "default transport",
		},
		cli.StringFlag{
			Name:  "runtime",
			Usage: "OCI runtime path",
		},
		cli.BoolFlag{
			Name:  "selinux",
			Usage: "enable selinux support",
		},
	}

	// remove once https://github.com/urfave/cli/pull/544 lands
	sort.Sort(byName(app.Flags))
	sort.Sort(byName(configCommand.Flags))

	app.Commands = []cli.Command{
		configCommand,
	}

	app.Before = func(c *cli.Context) error {
		// Load the configuration file.
		config := c.App.Metadata["config"].(*server.Config)
		if err := mergeConfig(config, c); err != nil {
			return err
		}

		cf := &logrus.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05.000000000Z07:00",
			FullTimestamp:   true,
		}

		logrus.SetFormatter(cf)

		if c.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if path := c.GlobalString("log"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
			if err != nil {
				return err
			}
			logrus.SetOutput(f)
		}

		switch c.GlobalString("log-format") {
		case "text":
			// retain logrus's default.
		case "json":
			logrus.SetFormatter(new(logrus.JSONFormatter))
		default:
			return fmt.Errorf("unknown log-format %q", c.GlobalString("log-format"))
		}

		return nil
	}

	app.Action = func(c *cli.Context) error {
		config := c.App.Metadata["config"].(*server.Config)

		if !config.SELinux {
			selinux.SetDisabled()
		}

		if _, err := os.Stat(config.Runtime); os.IsNotExist(err) {
			// path to runtime does not exist
			return fmt.Errorf("invalid --runtime value %q", err)
		}

		// Remove the socket if it already exists
		if _, err := os.Stat(config.Listen); err == nil {
			if err := os.Remove(config.Listen); err != nil {
				logrus.Fatal(err)
			}
		}
		lis, err := net.Listen("unix", config.Listen)
		if err != nil {
			logrus.Fatalf("failed to listen: %v", err)
		}

		s := grpc.NewServer()

		service, err := server.New(config)
		if err != nil {
			logrus.Fatal(err)
		}

		graceful := false
		catchShutdown(s, service, &graceful)
		runtime.RegisterRuntimeServiceServer(s, service)
		runtime.RegisterImageServiceServer(s, service)

		// after the daemon is done setting up we can notify systemd api
		notifySystem()

		err = s.Serve(lis)
		if graceful && strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") {
			err = nil
		}

		if err2 := service.Shutdown(); err2 != nil {
			logrus.Infof("error shutting down layer storage: %v", err2)
		}

		if err != nil {
			logrus.Fatal(err)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
