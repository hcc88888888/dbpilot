package database

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJMXClientFetchDecodesOnlyAllowlistedBeanProperties(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/jmx" {
			t.Fatalf("request path = %q, want /jmx", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"beans":[{"name":"Hadoop:service=HBase,name=Master","numRegions":7,"unsafe":99},{"name":"Hadoop:service=HBase,name=Other","count":1}]}`))
	}))
	defer server.Close()

	client := NewJMXClient(StaticSecretResolver{"secret://runtime/jmx": []byte("top-secret")}, JMXClientConfig{
		SecretRef: "secret://runtime/jmx", Timeout: time.Second,
	})
	beans, err := client.Fetch(context.Background(), Endpoint{URL: server.URL + "/jmx", Role: "master"}, BeanAllowlist{
		"Hadoop:service=HBase,name=Master": {"numRegions": {MetricName: "dbpilot.hbase.regions", Unit: "count"}},
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(beans) != 1 || beans[0].Name != "Hadoop:service=HBase,name=Master" {
		t.Fatalf("Fetch() beans = %#v, want one Master bean", beans)
	}
	if got := string(beans[0].Attributes["numRegions"]); got != "7" {
		t.Fatalf("Fetch() numRegions = %s, want 7", got)
	}
	if _, found := beans[0].Attributes["unsafe"]; found {
		t.Fatal("Fetch() retained a non-allowlisted property")
	}
}

func TestNormalizeJMXBeansConvertsUnitsAndReportsMissingAttributes(t *testing.T) {
	beans := []JMXBean{{
		Name: "Hadoop:service=HBase,name=Master",
		Attributes: map[string]JSONValue{
			"heapBytes": JSONValue(`1048576`),
		},
	}}
	samples, issues, err := NormalizeJMXBeans(beans, BeanAllowlist{
		"Hadoop:service=HBase,name=Master": {
			"heapBytes": {MetricName: "dbpilot.jvm.heap", Unit: "MiB", Multiplier: 1.0 / (1024 * 1024)},
			"missing":   {MetricName: "dbpilot.hbase.missing", Unit: "count"},
		},
	}, JMXMetricLabels{Cluster: "prod", Component: "hbase", Role: "master", Host: "master-1", Instance: "hbase-prod", Timestamp: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatalf("NormalizeJMXBeans() error = %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("NormalizeJMXBeans() samples = %#v, want one sample", samples)
	}
	if sample := samples[0]; sample.Value != 1 || sample.Unit != "MiB" || sample.Cluster != "prod" || sample.Role != "master" {
		t.Fatalf("NormalizeJMXBeans() sample = %#v, want converted, labeled metric", sample)
	}
	if len(issues) != 1 || issues[0].Property != "missing" || issues[0].Status != JMXParseMissingAttribute {
		t.Fatalf("NormalizeJMXBeans() issues = %#v, want missing attribute issue", issues)
	}
}

func TestNormalizeJMXBeansSkipsUnknownBeanWithStatus(t *testing.T) {
	samples, issues, err := NormalizeJMXBeans([]JMXBean{{Name: "Hadoop:service=HBase,name=Unknown", Attributes: map[string]JSONValue{"count": JSONValue(`2`)}}}, BeanAllowlist{}, JMXMetricLabels{})
	if err != nil {
		t.Fatalf("NormalizeJMXBeans() error = %v", err)
	}
	if len(samples) != 0 || len(issues) != 1 || issues[0].Status != JMXParseUnknownBean {
		t.Fatalf("NormalizeJMXBeans() = (%#v, %#v), want unknown bean status", samples, issues)
	}
}

func TestJMXClientFetchHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-time.After(time.Second)
	}))
	defer server.Close()

	client := NewJMXClient(StaticSecretResolver{"secret://runtime/jmx": []byte("top-secret")}, JMXClientConfig{SecretRef: "secret://runtime/jmx", Timeout: time.Second})
	requestContext, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Fetch(requestContext, Endpoint{URL: server.URL + "/jmx"}, BeanAllowlist{})
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch() error = %v, want context cancellation", err)
	}
}

func TestJMXClientFetchRedactsCredentialsAndResponseBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("password=top-secret"))
	}))
	defer server.Close()

	client := NewJMXClient(StaticSecretResolver{"secret://runtime/jmx": []byte("top-secret")}, JMXClientConfig{SecretRef: "secret://runtime/jmx", Timeout: time.Second})
	_, err := client.Fetch(context.Background(), Endpoint{URL: server.URL + "/jmx"}, BeanAllowlist{})
	if err == nil {
		t.Fatal("Fetch() error = nil, want HTTP status failure")
	}
	if strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), "password=") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("Fetch() error = %q, leaked protected detail", err)
	}
}
