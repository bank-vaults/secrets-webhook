// Copyright © 2025 Bank-Vaults Maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "request_duration_seconds",
			Help:      "Duration of provider requests in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider"},
	)
	RequestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "request_size_bytes",
			Help:      "Size of provider requests in bytes.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider"},
	)
	InFlightRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "in_flight_requests",
			Help:      "Gauge of provider in-flight requests.",
		},
		[]string{"provider"},
	)
	Requests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "requests_total",
			Help:      "Count of provider requests.",
		}, []string{"provider", "code", "method"},
	)
	RequestsErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "requests_errors_total",
			Help:      "Count of provider requests errors.",
		},
		[]string{"provider", "reason"},
	)
	AuthAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "auth_attempts_total",
			Help:      "Count of provider authentication attempts.",
		},
		[]string{"provider"},
	)
	AuthAttemptsErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "secrets_webhook",
			Subsystem: "provider",
			Name:      "auth_attempts_errors_total",
			Help:      "Count of provider authentication errors.",
		},
		[]string{"provider", "reason"},
	)
)

func RegisterMetrics(register prometheus.Registerer) {
	register.MustRegister(
		RequestDurationSeconds,
		RequestSize,
		InFlightRequests,
		Requests,
		RequestsErrors,
		AuthAttempts,
		AuthAttemptsErrors,
	)
}

// instrumentErrorsAndSizeRoundTripper instruments RoundTripper to track request errors and size
func instrumentErrorsAndSizeRoundTripper(errCounter *prometheus.CounterVec, size prometheus.ObserverVec, next http.RoundTripper) promhttp.RoundTripperFunc {
	return func(req *http.Request) (*http.Response, error) {
		size.WithLabelValues().Observe(float64(req.ContentLength))
		resp, err := next.RoundTrip(req)
		if err != nil {
			errCounter.WithLabelValues(mapErrorToLabel(err)).Inc()
			return nil, err
		}
		return resp, nil
	}
}

func InstrumentRoundTripper(rt http.RoundTripper, provider string) http.RoundTripper {
	labels := prometheus.Labels{"provider": provider}
	return promhttp.InstrumentRoundTripperInFlight(
		InFlightRequests.With(labels),
		promhttp.InstrumentRoundTripperCounter(
			Requests.MustCurryWith(labels),
			instrumentErrorsAndSizeRoundTripper(
				RequestsErrors.MustCurryWith(labels),
				RequestSize.MustCurryWith(labels),
				promhttp.InstrumentRoundTripperDuration(
					RequestDurationSeconds.MustCurryWith(labels),
					rt,
				),
			),
		),
	)
}

func mapErrorToLabel(err error) string {
	if strings.Contains(err.Error(), "no route to host") {
		return "no-route-to-host"
	}
	if strings.Contains(err.Error(), "i/o timeout") {
		return "io-timeout"
	}
	if strings.Contains(err.Error(), "TLS handshake timeout") {
		return "tls-handshake-timeout"
	}
	if strings.Contains(err.Error(), "TLS handshake error") {
		return "tls-handshake-error"
	}
	if strings.Contains(err.Error(), "unexpected EOF") {
		return "unexpected-eof"
	}

	return "unknown"
}
