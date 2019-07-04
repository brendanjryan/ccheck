package main

import (
	"context"
	"log"
	"os"

	"github.com/brendanjryan/ccheck/pkg"
	"github.com/fatih/color"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Name = "ccheck"
	app.Usage = "ccheck <files>"
	app.Author = "Brendan Ryan"
	app.Description = "A command line utility for validating structured config files"

	as := args{}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "p",
			Value:       "policies",
			Usage:       "directory which policy definitions live in",
			Destination: &as.policyDir,
		},
		cli.StringFlag{
			Name:        "n",
			Value:       "main",
			Usage:       "namespace of rules",
			Destination: &as.namespace,
		},
		cli.BoolFlag{
			Name:        "s",
			Usage:       "whether or not strict mode is enabled",
			Destination: &as.strict,
		},
	}

	app.Action = func(c *cli.Context) error {
		as.configs = c.Args()
		err := confCheck(as)
		if err != nil {
			log.Fatal(cli.NewExitError("error: "+err.Error(), 1))
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("error creating CLI application: ", err)
	}

	return
}

func confCheck(as args) error {
	ctx := context.Background()

	cc := pkg.NewConfChecker(as.namespace, as.policyDir, as.configs)

	cr, err := cc.Run(ctx)
	if err != nil {
		log.Println("error running checker: ", err)
		return err
	}

	p := printer{}
	for f, res := range cr {
		if len(res.Warnings) == 0 && len(res.Failures) == 0 {
			p.ok(f)
		}

		for _, w := range res.Warnings {
			if as.strict {
				p.err(f, w)
				continue
			}

			p.warning(f, w)
		}

		for _, fa := range res.Failures {
			// trap an error just so we exit with the right code
			err = fa
			p.err(f, fa)
		}
	}

	return nil
}

// args represents all command line arguments supported by this script
type args struct {
	// the directory which policy files live in
	policyDir string

	// the namespace rules live in:
	// https://www.openpolicyagent.org/docs/latest/how-do-i-write-policies#packages
	namespace string

	// whether or not strict mode is enabled
	strict bool

	// a list of config files we will check
	configs []string
}

// printer controlls printing the results of this script in a formatted manner.
type printer struct{}

func (p printer) err(file string, err error) {
	color.Red("Failure: %s - %s", file, err)
}

func (p printer) warning(file string, err error) {
	color.Yellow("Warning: %s - %s", file, err)
}

func (p printer) ok(file string) {
	color.Green("Passed: %s", file)
}
