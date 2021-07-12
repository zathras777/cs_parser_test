package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func main() {
	var (
		fileToParse string
		cfgType     string
		confFile    string
		confDir     string
		showAll     bool
		nShow       int
	)
	flag.StringVar(&cfgType, "type", "syslog", "type to assign")
	flag.StringVar(&confFile, "c", "/etc/crowdsec/config.yaml", "configuration file to use")
	flag.BoolVar(&showAll, "all", false, "show all line results (verbose)")
	flag.IntVar(&nShow, "n", 0, "how many lines to show (default: 0, unlimited)")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("Expected a filename to process.")
		log.Fatal("Nothing to do. Exiting.")
	}

	fileToParse = flag.Arg(0)
	confDir = filepath.Dir(confFile)

	fmt.Printf("Processing file %s\n", fileToParse)
	fmt.Printf("Configuration from %s\n\n", confFile)

	file, err := os.Open(fileToParse)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	labels := map[string]string{"type": cfgType}

	config, err := csconfig.NewConfig(confFile, false, false)
	if err != nil {
		log.Fatal(err)
	}
	config.Crowdsec.ConfigDir = confDir
	config.Crowdsec.DataDir = "/var/lib/crowdsec/data/"

	config.Hub = &csconfig.Hub{
		HubIndexFile: confDir + "/hub/.index.json",
		ConfigDir:    confDir,
		HubDir:       confDir + "/hub",
		DataDir:      "/var/lib/crowdsec/data/",
	}

	err = exprhelpers.Init()
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to init expr helpers : %s", err))
	}

	if err := cwhub.GetHubIdx(config.Hub); err != nil {
		log.Fatal(fmt.Sprintf("Failed to load hub index : %s", err))
	}

	csParsers := &parser.Parsers{
		Ctx:             &parser.UnixParserCtx{},
		Povfwctx:        &parser.UnixParserCtx{},
		StageFiles:      make([]parser.Stagefile, 0),
		PovfwStageFiles: make([]parser.Stagefile, 0),
	}

	for _, hubParserItem := range cwhub.GetItemMap(cwhub.PARSERS) {
		if hubParserItem.Installed {
			stagefile := parser.Stagefile{
				Filename: hubParserItem.LocalPath,
				Stage:    hubParserItem.Stage,
			}
			csParsers.StageFiles = append(csParsers.StageFiles, stagefile)
		}
	}

	if csParsers, err = parser.LoadParsers(config, csParsers); err != nil {
		log.Fatal(fmt.Sprintf("Unable to laod parsers. %s", err))
	}

	fmt.Print("\nScanning file until ")
	if nShow > 0 {
		fmt.Printf("%d match", nShow)
		if nShow > 1 {
			fmt.Print("es are")
		} else {
			fmt.Print(" is")
		}
	}
	fmt.Print(" found...\n\n")

	scanner := bufio.NewScanner(file)
	l := types.Line{Labels: labels, Src: fileToParse, Process: true, Module: "file"}
	ev := types.Event{Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}

	nScanned := 0
	nParsed := 0
	for scanner.Scan() {
		l.Raw = scanner.Text()
		nScanned++
		ev.Line = l
		parsed, err := parser.Parse(*csParsers.Ctx, ev, csParsers.Nodes)
		if err != nil {
			fmt.Printf("failed parsing : %v\n", err)
			continue
		}
		if !parsed.Process && !showAll {
			continue
		}
		if !showAll || (showAll && parsed.Process) {
			nParsed++
		}
		fmt.Printf("Line %d:\n  Processed? %t\n", nScanned, parsed.Process)
		fmt.Printf("  Final Stage: %s\n", parsed.Stage)
		fmt.Println("  Parsed Entries [evt.Parsed]:")
		for k, v := range parsed.Parsed {
			fmt.Printf("    %-20s: %s\n", k, v)
		}
		if parsed.Process {
			fmt.Println("Metadata [evt.Meta]:")
			for k, v := range parsed.Meta {
				fmt.Printf("    %-20s: %s\n", k, v)
			}
		}
		fmt.Println()
		if nShow > 0 && nParsed >= nShow {
			fmt.Printf("\n\nScanned a total of %d lines to find %d matches\n", nScanned, nShow)
			break
		}
	}
	if nShow == 0 || nParsed == 0 {
		fmt.Printf("Scanned a total of %d lines, finding %d match", nScanned, nParsed)
		if nParsed != 0 {
			fmt.Printf("es")
		}
		fmt.Print("\n\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
