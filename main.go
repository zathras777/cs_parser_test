package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"gopkg.in/yaml.v2"
)

func main() {
	var (
		fileToParse string
		cfgType     string
		confFile    string
		confDir     string
		showAll     bool
		parseOnly   bool
		nShow       int

		buckets []leaky.BucketFactory
	)

	flag.StringVar(&cfgType, "type", "syslog", "type to assign")
	flag.StringVar(&confFile, "c", "/etc/crowdsec/config.yaml", "configuration file to use")
	flag.BoolVar(&showAll, "all", false, "show all line results (verbose)")
	flag.BoolVar(&parseOnly, "parse", false, "parse ONLY. no scenarios loaded")
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
	if csParsers.StageFiles != nil {
		sort.Slice(csParsers.StageFiles, func(i, j int) bool {
			return csParsers.StageFiles[i].Filename < csParsers.StageFiles[j].Filename
		})
	}
	if !parseOnly {
		// Load the overflow parsers if we are considering scenarios
		for _, hubParserItem := range cwhub.GetItemMap(cwhub.PARSERS_OVFLW) {
			if hubParserItem.Installed {
				stagefile := parser.Stagefile{
					Filename: hubParserItem.LocalPath,
					Stage:    hubParserItem.Stage,
				}
				csParsers.PovfwStageFiles = append(csParsers.PovfwStageFiles, stagefile)
			}
		}
		if csParsers.PovfwStageFiles != nil {
			sort.Slice(csParsers.PovfwStageFiles, func(i, j int) bool {
				return csParsers.PovfwStageFiles[i].Filename < csParsers.PovfwStageFiles[j].Filename
			})
		}
	}

	if csParsers, err = parser.LoadParsers(config, csParsers); err != nil {
		log.Fatal(fmt.Sprintf("Unable to laod parsers. %s", err))
	}

	if !parseOnly {
		// Load scenarios
		for _, hubScenarioItem := range cwhub.GetItemMap(cwhub.SCENARIOS) {
			if hubScenarioItem.Installed {
				buckets = append(buckets, loadScenario(config.Crowdsec, hubScenarioItem.LocalPath)...)
			}
		}
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
	fmt.Print(" found...\n")
	if parseOnly {
		fmt.Println("Scenarios will NOT be tested due to -parse option.")
	}
	fmt.Println()

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

		if !parseOnly && parsed.Process {
			checkScenarios(parsed, buckets)
		}

		if (nShow > 0 && nParsed >= nShow) || (showAll && nShow != 0 && nScanned >= nShow) {
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

func loadScenario(cscfg *csconfig.CrowdsecServiceCfg, bucketFilename string) []leaky.BucketFactory {
	var factories []leaky.BucketFactory
	if !strings.HasSuffix(bucketFilename, ".yaml") {
		fmt.Printf("Skipping scenario '%s' : not a yaml file", bucketFilename)
		return factories
	}

	//process the yaml
	bucketConfigurationFile, err := os.Open(bucketFilename)
	if err != nil {
		fmt.Printf("Can't access leaky configuration file %s\n", bucketFilename)
		return factories
	}
	dec := yaml.NewDecoder(bucketConfigurationFile)
	dec.SetStrict(true)
	for {
		bucketFactory := leaky.BucketFactory{}
		err = dec.Decode(&bucketFactory)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				fmt.Printf("Bad yaml in %s : %v\n", bucketFilename, err)
				return factories
			}
		}
		bucketFactory.DataDir = cscfg.DataDir

		if bucketFactory.Name == "" {
			fmt.Printf("  Scenario in %s lacks Name. Won't be loaded.\n", bucketFilename)
			return factories
		}
		fmt.Printf("  Scenario: %s\n", bucketFactory.Name)

		bucketFactory.Filename = filepath.Clean(bucketFilename)
		err = leaky.LoadBucket(&bucketFactory, nil)
		if err != nil {
			fmt.Printf("    Failed to load bucket %s : %v\n", bucketFactory.Name, err)
			return factories
		}

		fmt.Println("    loaded OK")
		factories = append(factories, bucketFactory)
	}
	return factories
}

func checkScenarios(parsed types.Event, holders []leaky.BucketFactory) {
	var matched []string

	for _, holder := range holders {
		if holder.RunTimeFilter != nil {
			output, err := expr.Run(holder.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			if err != nil {
				fmt.Printf("Error parsing filter for %s: %v\n", holder.Name, err)
				continue
			}

			var condition, ok bool
			if condition, ok = output.(bool); !ok {
				fmt.Printf("Error with filter for %s: non-bool return from %T\n", holder.Name, output)
				fmt.Println("Skipping...")
				continue
			}
			if condition {
				matched = append(matched, holder.Name)
			}
		}
	}
	if len(matched) == 0 {
		fmt.Println("NO scenarios matched this event")
	} else {
		fmt.Printf("Processed by %d ", len(matched))
		if len(matched) == 1 {
			fmt.Println("scenario")
		} else {
			fmt.Println("scenarios")
		}
		for _, scen := range matched {
			fmt.Printf("    - %s\n", scen)
		}
	}
	fmt.Println()
}
