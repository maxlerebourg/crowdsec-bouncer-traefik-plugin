package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sendTicks(ticks chan time.Time, count int) {
	for i := 0; i < count; i++ { //nolint:intrange
		ticks <- time.Time{}
	}
}

func Test_runTicker_keepsEachTickerOnItsOwnChannel(t *testing.T) {
	const count = 20000
	var streamRuns, metricsRuns int64
	var runs sync.WaitGroup
	runs.Add(2 * count)
	streamTicks := make(chan time.Time)
	metricsTicks := make(chan time.Time)
	go runTicker(streamTicks, func() {
		atomic.AddInt64(&streamRuns, 1)
		runs.Done()
	})
	go runTicker(metricsTicks, func() {
		atomic.AddInt64(&metricsRuns, 1)
		runs.Done()
	})
	go sendTicks(streamTicks, count)
	go sendTicks(metricsTicks, count)
	runs.Wait()
	if streamRuns != count || metricsRuns != count {
		t.Errorf("runTicker ran stream %d and metrics %d times, want %d each", streamRuns, metricsRuns, count)
	}
}
