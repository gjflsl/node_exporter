// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"
	_ "net/http/pprof"
	"strings"

	"github.com/gjflsl/node_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"net"
)

func init() {
	prometheus.MustRegister(version.NewCollector("node_exporter"))
}

func main() {
	var (
		listenAddress     = kingpin.Flag("web.listen-address", "Address on which to expose metrics and web interface.").Default(":9100").String()
		metricsPath       = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		ipWhitelistString = kingpin.Flag("web.ip-whitelist", "Set the whitelist of IP. Example: \"127.0.0.1,172.17.2.1/24,1080:0:0:0:8:800:200C:417A/128\"").Default("0.0.0.0/0,::/0").String()
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("node_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	var ipWhitelist []*net.IPNet
	for _, netIpString := range strings.Split(*ipWhitelistString, ",") {
		ipAdd := net.ParseIP(netIpString)
		if ipAdd != nil {
			if ipAdd.To4() != nil {
				netIpString += "/32"
			} else {
				netIpString += "/128"
			}
		}
		_, netIp, err := net.ParseCIDR(netIpString)
		if err != nil {
			log.Fatalf("Add netip error: %s", err)
		} else {
			ipWhitelist = append(ipWhitelist, netIp)
		}
	}

	log.Infoln("Starting node_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	// This instance is only used to check collector creation and logging.
	nc, err := collector.NewNodeCollector()
	if err != nil {
		log.Fatalf("Couldn't create collector: %s", err)
	}
	log.Infof("Enabled collectors:")
	for n := range nc.Collectors {
		log.Infof(" - %s", n)
	}

	if err := prometheus.Register(nc); err != nil {
		log.Fatalf("Couldn't register collector: %s", err)
	}

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			ErrorLog:      log.NewErrorLogger(),
			ErrorHandling: promhttp.ContinueOnError,
		}, ipWhitelist)

	// TODO(ts): Remove deprecated and problematic InstrumentHandlerFunc usage.
	http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if promhttp.CheckInIpWhitelist(w, r, ipWhitelist) == false {
			return
		}
		w.Write([]byte(`<html>
			<head><title>Node Exporter</title></head>
			<body>
			<h1>Node Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
