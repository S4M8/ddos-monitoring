package main

import (
	"fmt"
	"net/http"
	"sync"
)

type MetricsCollector struct {
	mu      sync.RWMutex
	metrics map[string]interface{}
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]interface{}),
	}
}

func (m *MetricsCollector) Set(name string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics[name] = value
}

func (m *MetricsCollector) Get(name string) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics[name]
}

func (m *MetricsCollector) GetAll() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]interface{})
	for k, v := range m.metrics {
		result[k] = v
	}
	return result
}

func (m *MetricsCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	metrics := m.GetAll()

	// Write metrics in Prometheus format
	for name, value := range metrics {
		switch v := value.(type) {
		case float64:
			fmt.Fprintf(w, "%s %.2f\n", name, v)
		case int64:
			fmt.Fprintf(w, "%s %d\n", name, v)
		case map[string]float64:
			for label, val := range v {
				fmt.Fprintf(w, "%s{ip=\"%s\"} %.2f\n", name, label, val)
			}
		case map[string]int64:
			for label, val := range v {
				fmt.Fprintf(w, "%s{ip=\"%s\"} %d\n", name, label, val)
			}
		}
	}
}
