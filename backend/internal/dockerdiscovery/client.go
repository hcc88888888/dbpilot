package dockerdiscovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maximumEngineResponseBytes = 4 << 20
	maximumContainers          = 1024
	maximumEventBytes          = 1 << 20
	maximumCgroupFileBytes     = 16 << 10
	engineRequestTimeout       = 5 * time.Second
)

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var networkNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var ErrContainerNotFound = errors.New("Docker container disappeared")

type responseStatusError struct{ code int }

func (err responseStatusError) Error() string {
	return fmt.Sprintf("Docker API returned status %d", err.code)
}

type Engine interface {
	Info(context.Context) (EngineInfo, error)
	ListContainers(context.Context) ([]ContainerObservation, error)
	InspectContainer(context.Context, string) (ContainerObservation, error)
	Events(context.Context, time.Time) (<-chan ContainerEvent, <-chan error)
}

type EngineInfo struct{ ID string }

type PortMapping struct {
	HostAddress   string
	HostPort      uint16
	ContainerPort uint16
	Protocol      string
}

type InternalEndpoint struct {
	NetworkName string
	Address     string
	Port        uint16
	Protocol    string
}

type ContainerObservation struct {
	ContainerID       string
	Name              string
	Image             string
	State             string
	Ports             []PortMapping
	InternalEndpoints []InternalEndpoint
	Labels            map[string]string
	CommandSummary    string
	HostProcessID     uint32
	Cgroup            string
	ObservedAt        time.Time
}

type ContainerEvent struct {
	ContainerID string
	Name        string
	Image       string
	Action      string
	OccurredAt  time.Time
}

type Client struct {
	http *http.Client
	base string
}

func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" || !strings.HasPrefix(socketPath, "/") || strings.ContainsAny(socketPath, "\x00\r\n") {
		return nil, errors.New("invalid Docker socket path")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "docker:80" {
				return nil, errors.New("unexpected Docker transport target")
			}
			return (&net.Dialer{Timeout: engineRequestTimeout}).DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:    true,
		MaxIdleConns:          2,
		MaxConnsPerHost:       2,
		ResponseHeaderTimeout: engineRequestTimeout,
	}
	return newHTTPClient(&http.Client{Transport: transport}, "http://docker"), nil
}

func newHTTPClient(client *http.Client, base string) *Client {
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: &clone, base: strings.TrimRight(base, "/")}
}

func (client *Client) Info(ctx context.Context) (EngineInfo, error) {
	var raw struct {
		ID string `json:"ID"`
	}
	if err := client.getJSON(ctx, "/info", nil, &raw); err != nil {
		return EngineInfo{}, err
	}
	if raw.ID == "" || len(raw.ID) > 128 || strings.ContainsAny(raw.ID, "\x00\r\n") {
		return EngineInfo{}, errors.New("invalid Docker engine identity")
	}
	return EngineInfo{ID: raw.ID}, nil
}

func (client *Client) ListContainers(ctx context.Context) ([]ContainerObservation, error) {
	var raw []struct {
		ID string `json:"Id"`
	}
	if err := client.getJSON(ctx, "/containers/json", url.Values{"all": []string{"1"}}, &raw); err != nil {
		return nil, err
	}
	if len(raw) > maximumContainers {
		return nil, errors.New("Docker container list exceeds bound")
	}
	result := make([]ContainerObservation, 0, len(raw))
	for _, item := range raw {
		if !containerIDPattern.MatchString(item.ID) {
			return nil, errors.New("invalid Docker container identity")
		}
		result = append(result, ContainerObservation{ContainerID: item.ID})
	}
	return result, nil
}

func (client *Client) InspectContainer(ctx context.Context, id string) (ContainerObservation, error) {
	if !containerIDPattern.MatchString(id) {
		return ContainerObservation{}, errors.New("invalid Docker container identity")
	}
	var raw struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image        string              `json:"Image"`
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			Labels       map[string]string   `json:"Labels"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"Config"`
		State struct {
			Status string `json:"Status"`
			Pid    uint32 `json:"Pid"`
		} `json:"State"`
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := client.getJSON(ctx, "/containers/"+id+"/json", nil, &raw); err != nil {
		var statusError responseStatusError
		if errors.As(err, &statusError) && statusError.code == http.StatusNotFound {
			return ContainerObservation{}, ErrContainerNotFound
		}
		return ContainerObservation{}, err
	}
	if raw.ID != id || len(raw.Name) > 256 || len(raw.Config.Image) > 512 {
		return ContainerObservation{}, errors.New("invalid Docker inspect identity")
	}
	ports, err := normalizePorts(raw.NetworkSettings.Ports)
	if err != nil {
		return ContainerObservation{}, err
	}
	internalEndpoints, err := normalizeInternalEndpoints(raw.State.Status, raw.Config.ExposedPorts, raw.NetworkSettings.Ports, raw.NetworkSettings.Networks)
	if err != nil {
		return ContainerObservation{}, err
	}
	arguments := append(append([]string(nil), raw.Config.Entrypoint...), raw.Config.Cmd...)
	cgroup := optionalCgroupAt("/proc", raw.State.Pid)
	return ContainerObservation{ContainerID: id, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Config.Image, State: raw.State.Status, Ports: ports, InternalEndpoints: internalEndpoints, Labels: raw.Config.Labels, CommandSummary: RedactCommand(arguments), HostProcessID: raw.State.Pid, Cgroup: cgroup, ObservedAt: time.Now().UTC()}, nil
}

func normalizeInternalEndpoints(containerState string, exposed map[string]struct{}, mapped map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}, networks map[string]struct {
	IPAddress string `json:"IPAddress"`
}) ([]InternalEndpoint, error) {
	if containerState != "running" {
		return nil, nil
	}
	ports := make(map[string]struct{}, len(exposed)+len(mapped))
	for value := range exposed {
		ports[value] = struct{}{}
	}
	for value := range mapped {
		ports[value] = struct{}{}
	}
	type exposedPort struct {
		port     uint16
		protocol string
	}
	parsedPorts := make([]exposedPort, 0, len(ports))
	for value := range ports {
		rawPort, protocol, ok := strings.Cut(value, "/")
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if !ok || err != nil || port == 0 || protocol != "tcp" && protocol != "udp" {
			return nil, errors.New("invalid Docker exposed port")
		}
		parsedPorts = append(parsedPorts, exposedPort{port: uint16(port), protocol: protocol})
	}
	sort.Slice(parsedPorts, func(left, right int) bool {
		if parsedPorts[left].port != parsedPorts[right].port {
			return parsedPorts[left].port < parsedPorts[right].port
		}
		return parsedPorts[left].protocol < parsedPorts[right].protocol
	})
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 32 || len(parsedPorts) > 32 || len(names)*len(parsedPorts) > 256 {
		return nil, errors.New("Docker internal endpoint exceeds bound")
	}
	result := make([]InternalEndpoint, 0, len(names)*len(parsedPorts))
	for _, name := range names {
		address := networks[name].IPAddress
		if !networkNamePattern.MatchString(name) {
			return nil, errors.New("invalid Docker internal endpoint")
		}
		parsedAddress := net.ParseIP(address)
		if !IsSafeInternalIP(parsedAddress) {
			return nil, errors.New("invalid Docker internal endpoint")
		}
		for _, port := range parsedPorts {
			result = append(result, InternalEndpoint{NetworkName: name, Address: parsedAddress.String(), Port: port.port, Protocol: port.protocol})
		}
	}
	return result, nil
}

func optionalCgroupAt(root string, pid uint32) string {
	value, _ := readCgroupAt(root, pid)
	return value
}

func readCgroupAt(root string, pid uint32) (string, error) {
	if pid == 0 {
		return "", nil
	}
	file, err := os.Open(filepath.Join(root, strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximumCgroupFileBytes+1))
	if err != nil || len(body) > maximumCgroupFileBytes {
		return "", errors.New("Docker cgroup association exceeds bound")
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "/") {
			continue
		}
		value := filepath.ToSlash(filepath.Clean(parts[2]))
		if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("invalid Docker cgroup association")
		}
		return value, nil
	}
	return "", nil
}

func normalizePorts(raw map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}) ([]PortMapping, error) {
	result := make([]PortMapping, 0)
	for containerRaw, bindings := range raw {
		containerPortRaw, protocol, ok := strings.Cut(containerRaw, "/")
		containerPort, err := strconv.ParseUint(containerPortRaw, 10, 16)
		if !ok || err != nil || containerPort == 0 || (protocol != "tcp" && protocol != "udp") {
			return nil, errors.New("invalid Docker port mapping")
		}
		for _, binding := range bindings {
			hostPort, err := strconv.ParseUint(binding.HostPort, 10, 16)
			if err != nil || hostPort == 0 || net.ParseIP(binding.HostIP) == nil {
				return nil, errors.New("invalid Docker host port mapping")
			}
			result = append(result, PortMapping{HostAddress: binding.HostIP, HostPort: uint16(hostPort), ContainerPort: uint16(containerPort), Protocol: protocol})
			if len(result) > 256 {
				return nil, errors.New("Docker port mapping exceeds bound")
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ContainerPort != result[j].ContainerPort {
			return result[i].ContainerPort < result[j].ContainerPort
		}
		if result[i].HostAddress != result[j].HostAddress {
			return result[i].HostAddress < result[j].HostAddress
		}
		return result[i].HostPort < result[j].HostPort
	})
	return result, nil
}

func (client *Client) Events(ctx context.Context, since time.Time) (<-chan ContainerEvent, <-chan error) {
	events := make(chan ContainerEvent)
	errorsChannel := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errorsChannel)
		filters, _ := json.Marshal(map[string][]string{"event": {"destroy", "die", "start", "stop"}, "type": {"container"}})
		query := url.Values{"filters": []string{string(filters)}, "since": []string{strconv.FormatInt(since.UTC().Unix(), 10)}}
		request, err := client.request(ctx, "/events", query)
		if err != nil {
			errorsChannel <- err
			return
		}
		response, err := client.http.Do(request)
		if err != nil {
			errorsChannel <- err
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			errorsChannel <- fmt.Errorf("Docker events returned status %d", response.StatusCode)
			return
		}
		reader := bufio.NewReader(io.LimitReader(response.Body, maximumEngineResponseBytes+1))
		for {
			line, readErr := reader.ReadBytes('\n')
			if len(line) > maximumEventBytes {
				errorsChannel <- errors.New("Docker event exceeds bound")
				return
			}
			if len(strings.TrimSpace(string(line))) > 0 {
				var raw struct {
					Type     string `json:"Type"`
					Action   string `json:"Action"`
					Status   string `json:"status"`
					ID       string `json:"id"`
					From     string `json:"from"`
					Time     int64  `json:"time"`
					TimeNano int64  `json:"timeNano"`
					Actor    struct {
						ID         string            `json:"ID"`
						Attributes map[string]string `json:"Attributes"`
					} `json:"Actor"`
				}
				if err := json.Unmarshal(line, &raw); err != nil {
					errorsChannel <- errors.New("invalid Docker event JSON")
					return
				}
				containerID := raw.ID
				if containerID == "" {
					containerID = raw.Actor.ID
				}
				if !containerIDPattern.MatchString(containerID) {
					errorsChannel <- fmt.Errorf("invalid Docker event identity length %d", len(containerID))
					return
				}
				action := raw.Status
				if action == "" {
					action = raw.Action
				}
				if (raw.Type != "" && raw.Type != "container") || !allowedEvent(action) {
					errorsChannel <- errors.New("invalid Docker event action")
					return
				}
				name := raw.Actor.Attributes["name"]
				if len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
					name = ""
				}
				image := raw.From
				if image == "" {
					image = raw.Actor.Attributes["image"]
				}
				occurredAt := time.Unix(raw.Time, 0).UTC()
				if raw.TimeNano > 0 {
					occurredAt = time.Unix(0, raw.TimeNano).UTC()
				}
				select {
				case events <- ContainerEvent{ContainerID: containerID, Name: name, Image: image, Action: action, OccurredAt: occurredAt}:
				case <-ctx.Done():
					errorsChannel <- ctx.Err()
					return
				}
			}
			if readErr == io.EOF {
				errorsChannel <- nil
				return
			}
			if readErr != nil {
				errorsChannel <- readErr
				return
			}
		}
	}()
	return events, errorsChannel
}

func allowedEvent(action string) bool {
	return action == "start" || action == "stop" || action == "die" || action == "destroy"
}

func (client *Client) getJSON(ctx context.Context, path string, query url.Values, output any) error {
	requestContext, cancel := context.WithTimeout(ctx, engineRequestTimeout)
	defer cancel()
	request, err := client.request(requestContext, path, query)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseStatusError{code: response.StatusCode}
	}
	reader := io.LimitReader(response.Body, maximumEngineResponseBytes+1)
	body, err := io.ReadAll(reader)
	if err != nil || len(body) > maximumEngineResponseBytes {
		return errors.New("Docker API response exceeds bound")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid Docker API response")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid trailing Docker API response")
	}
	return nil
}

func (client *Client) request(ctx context.Context, path string, query url.Values) (*http.Request, error) {
	if ctx == nil || !allowedPath(path, query) {
		return nil, errors.New("Docker endpoint is not allowlisted")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.base+path, nil)
	if err != nil {
		return nil, err
	}
	request.URL.RawQuery = query.Encode()
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func allowedPath(path string, query url.Values) bool {
	switch {
	case path == "/info":
		return len(query) == 0
	case path == "/containers/json":
		return len(query) == 1 && len(query["all"]) == 1 && query.Get("all") == "1"
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		return containerIDPattern.MatchString(id) && len(query) == 0
	case path == "/events":
		if len(query) != 2 || len(query["since"]) != 1 || len(query["filters"]) != 1 {
			return false
		}
		if _, err := strconv.ParseInt(query.Get("since"), 10, 64); err != nil {
			return false
		}
		var filters map[string][]string
		if json.Unmarshal([]byte(query.Get("filters")), &filters) != nil || len(filters) != 2 {
			return false
		}
		return strings.Join(filters["event"], ",") == "destroy,die,start,stop" && strings.Join(filters["type"], ",") == "container"
	default:
		return false
	}
}
