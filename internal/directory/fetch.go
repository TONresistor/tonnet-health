package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TONresistor/tonnet-health/internal/types"
)

const (
	DefaultDirectoryURL = "https://raw.githubusercontent.com/TONresistor/tonnet-directory/main/relays.json"
	DefaultTimeout      = 10 * time.Second
)

// Client fetches relay directory from GitHub
type Client struct {
	url        string
	httpClient *http.Client
}

// NewClient creates a new directory client
func NewClient(url string) *Client {
	if url == "" {
		url = DefaultDirectoryURL
	}
	return &Client{
		url: url,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// Fetch retrieves the relay directory
func (c *Client) Fetch(ctx context.Context) (*types.Directory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var dir types.Directory
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, fmt.Errorf("parse directory: %w", err)
	}

	return &dir, nil
}
