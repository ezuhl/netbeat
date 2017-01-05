package conntrack

import (
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/metricbeat/mb"
	"io/ioutil"
	"strconv"
	"strings"
)

var maxConnectionsPath = "/proc/sys/net/netfilter/nf_conntrack_max"
var currentConnectionsPath = "/proc/sys/net/netfilter/nf_conntrack_count"

// init registers the MetricSet with the central registry.
// The New method will be called after the setup of the module and before starting to fetch data
func init() {
	if err := mb.Registry.AddMetricSet("conntrack", "conntrack", New); err != nil {
		panic(err)
	}
}

// MetricSet type defines all fields of the MetricSet
// As a minimum it must inherit the mb.BaseMetricSet fields, but can be extended with
// additional entries. These variables can be used to persist data or configuration between
// multiple fetch calls.
type MetricSet struct {
	mb.BaseMetricSet
	connTrackCount int
	connTrackMax   int
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {

	config := struct{}{}

	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	return &MetricSet{
		BaseMetricSet:  base,
		connTrackCount: 1,
		connTrackMax:   65536,
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right format
// It returns the event which is then forward to the output. In case of an error, a
// descriptive error must be returned.
func (m *MetricSet) Fetch() (common.MapStr, error) {

	connTrackMax, err 	:= m.getIntContent(maxConnectionsPath); if err != nil {
		return nil, err
	}
	connTrackCount, err 	:= m.getIntContent(currentConnectionsPath); if err != nil {
		return nil, err
	}

	m.connTrackMax = connTrackMax
	m. connTrackCount = connTrackCount

	event := common.MapStr{
		"conntrackcount": m.connTrackCount,
		"conntrackmax": m.connTrackMax,
	}

	return event, nil
}


// get the int value from netfilter file paths.  Probably could go further with regex, but this works
func (m *MetricSet) getIntContent(filePath string) (int, error){


	b, err := ioutil.ReadFile(filePath) // just pass the file name
	if err != nil {
		return 0,err
	}

	fileNumber, err := strconv.Atoi(strings.Trim(string(b),"\n"))
	if err != nil {
		return 0,err
	}

	return fileNumber,nil

}