package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// NotificationConfig holds the configuration for all notification providers
type NotificationConfig struct {
	Enabled                       bool              `json:"enabled"`
	NotificationCooldown          time.Duration     `json:"-"`                            // Internal field, set from NotificationCooldownStr
	NotificationCooldownStr       string            `json:"notification_cooldown"`        // JSON field e.g. "1h", "24h"
	ListenNotificationCooldown    time.Duration     `json:"-"`                            // Internal field, set from ListenNotificationCooldownStr
	ListenNotificationCooldownStr string            `json:"listen_notification_cooldown"` // LISTEN-specific cooldown; "0s" disables cooldown
	Pushover                      *PushoverConfig   `json:"pushover,omitempty"`
	Ntfy                          *NtfyConfig       `json:"ntfy,omitempty"`
	Pushbullet                    *PushbulletConfig `json:"pushbullet,omitempty"`
	Telegram                      *TelegramConfig   `json:"telegram,omitempty"`
	Webhook                       *WebhookConfig    `json:"webhook,omitempty"`
	TitleTemplate                 string            `json:"title_template"`
	MessageTemplate               string            `json:"message_template"`
}

// PushoverConfig holds Pushover API configuration
type PushoverConfig struct {
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"api_key"`
	UserKey string `json:"user_key"`
	Device  string `json:"device,omitempty"`
	Sound   string `json:"sound,omitempty"`
	Title   string `json:"title,omitempty"`
}

// NtfyConfig holds ntfy.sh configuration
type NtfyConfig struct {
	Enabled bool   `json:"enabled"`
	Topic   string `json:"topic"`
	BaseURL string `json:"base_url"`
	Title   string `json:"title,omitempty"`
}

// PushbulletConfig holds Pushbullet API configuration
type PushbulletConfig struct {
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"api_key"`
	Title   string `json:"title,omitempty"`
}

// TelegramConfig holds Telegram bot configuration
type TelegramConfig struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// WebhookConfig holds generic webhook configuration
type WebhookConfig struct {
	Enabled bool              `json:"enabled"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Notifier sends notifications
type Notifier interface {
	Send(title, message string) error
	Enabled() bool
}

// NotificationManager manages all notifiers
type NotificationManager struct {
	notifiers []Notifier
	config    *NotificationConfig
	titleTpl  string
	msgTpl    string
}

// NewNotificationManager creates a notification manager
func NewNotificationManager(config *NotificationConfig) *NotificationManager {
	if config == nil || !config.Enabled {
		return nil
	}

	// Set default notification cooldown if not specified
	if config.NotificationCooldown == 0 {
		if config.NotificationCooldownStr != "" {
			if d, err := time.ParseDuration(config.NotificationCooldownStr); err == nil {
				config.NotificationCooldown = d
			} else {
				config.NotificationCooldown = 24 * time.Hour // Default fallback
				fmt.Printf("[notification] Warning: Failed to parse cooldown duration '%s', using default 24h\n", config.NotificationCooldownStr)
			}
		} else {
			config.NotificationCooldown = 24 * time.Hour // Default if not specified
		}
	}

	if config.ListenNotificationCooldownStr != "" {
		if d, err := time.ParseDuration(config.ListenNotificationCooldownStr); err == nil {
			config.ListenNotificationCooldown = d
		} else {
			config.ListenNotificationCooldown = 0
			fmt.Printf("[notification] Warning: Failed to parse LISTEN notification cooldown '%s', using 0s (disabled)\n", config.ListenNotificationCooldownStr)
		}
	}

	nm := &NotificationManager{
		notifiers: []Notifier{},
		config:    config,
		titleTpl:  config.TitleTemplate,
		msgTpl:    config.MessageTemplate,
	}

	// Initialize enabled notifiers
	if config.Pushover != nil && config.Pushover.Enabled {
		notifier := &PushoverNotifier{config: config.Pushover}
		if notifier.Enabled() {
			nm.notifiers = append(nm.notifiers, notifier)
			fmt.Printf("[notification] Pushover notifier enabled\n")
		} else {
			fmt.Printf("[notification] Warning: Pushover enabled but missing required configuration\n")
		}
	}
	if config.Ntfy != nil && config.Ntfy.Enabled {
		notifier := &NtfyNotifier{config: config.Ntfy}
		if notifier.Enabled() {
			nm.notifiers = append(nm.notifiers, notifier)
			fmt.Printf("[notification] Ntfy notifier enabled\n")
		} else {
			fmt.Printf("[notification] Warning: Ntfy enabled but missing required configuration\n")
		}
	}
	if config.Pushbullet != nil && config.Pushbullet.Enabled {
		notifier := &PushbulletNotifier{config: config.Pushbullet}
		if notifier.Enabled() {
			nm.notifiers = append(nm.notifiers, notifier)
			fmt.Printf("[notification] Pushbullet notifier enabled\n")
		} else {
			fmt.Printf("[notification] Warning: Pushbullet enabled but missing required configuration\n")
		}
	}
	if config.Telegram != nil && config.Telegram.Enabled {
		notifier := &TelegramNotifier{config: config.Telegram}
		if notifier.Enabled() {
			nm.notifiers = append(nm.notifiers, notifier)
			fmt.Printf("[notification] Telegram notifier enabled (bot token: %s..., chat ID: %s)\n",
				maskToken(config.Telegram.BotToken), config.Telegram.ChatID)
		} else {
			fmt.Printf("[notification] Warning: Telegram enabled but missing required configuration (bot_token or chat_id)\n")
		}
	}
	if config.Webhook != nil && config.Webhook.Enabled {
		notifier := &WebhookNotifier{config: config.Webhook}
		if notifier.Enabled() {
			nm.notifiers = append(nm.notifiers, notifier)
			fmt.Printf("[notification] Webhook notifier enabled (URL: %s)\n", config.Webhook.URL)
		} else {
			fmt.Printf("[notification] Warning: Webhook enabled but missing required configuration\n")
		}
	}

	if len(nm.notifiers) == 0 {
		fmt.Printf("[notification] Warning: Notifications enabled but no valid notifiers configured\n")
	}

	return nm
}

// SendAlert sends an alert through all enabled notifiers
func (nm *NotificationManager) SendAlert(conn *Connection) error {
	if nm == nil || len(nm.notifiers) == 0 {
		return nil
	}

	// Get hostname for the notification
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Build variable map
	vars := map[string]string{
		"hostname":   hostname,
		"ip":         conn.RemoteIP,
		"port":       fmt.Sprintf("%d", conn.RemotePort),
		"service":    conn.ProcessName,
		"protocol":   conn.Protocol,
		"local_ip":   conn.LocalIP,
		"local_port": fmt.Sprintf("%d", conn.LocalPort),
		"timestamp":  time.Now().Format(time.RFC3339),
		"reason":     strings.Join(conn.AnomalousReasons, ", "),
		"pid":        fmt.Sprintf("%d", conn.PID),
	}

	// Format title and message
	title := nm.formatTemplate(nm.titleTpl, vars)
	if title == "" {
		title = "🚨 NetMon Security Alert"
	}

	message := nm.formatTemplate(nm.msgTpl, vars)
	if message == "" {
		message = conn.DetailedString()
	}

	message = sanitizeNotificationMessage(conn, message)

	fmt.Printf("[notification] Sending alert to %d notifier(s)\n", len(nm.notifiers))
	fmt.Printf("[notification] Title: %s\n", title)
	fmt.Printf("[notification] Message: %s\n", message)

	// Send through all notifiers
	for _, notifier := range nm.notifiers {
		if notifier.Enabled() {
			if err := notifier.Send(title, message); err != nil {
				// Log error but continue sending to other notifiers
				fmt.Printf("[notification] Error sending alert: %v\n", err)
			} else {
				fmt.Printf("[notification] Alert sent successfully\n")
			}
		}
	}

	return nil
}

// formatTemplate replaces variables in a template string
func (nm *NotificationManager) formatTemplate(template string, vars map[string]string) string {
	result := template
	for key, value := range vars {
		placeholder := "{" + key + "}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func sanitizeNotificationMessage(conn *Connection, message string) string {
	if conn == nil {
		return message
	}

	if conn.State != "LISTEN" || !isUnspecifiedRemoteEndpoint(conn.RemoteIP, conn.RemotePort) {
		return message
	}

	lines := strings.Split(message, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Remote IP:") {
			continue
		}
		filtered = append(filtered, line)
	}

	return strings.Join(filtered, "\n")
}

func isUnspecifiedRemoteEndpoint(ip string, port int) bool {
	if strings.TrimSpace(ip) == "" {
		return true
	}

	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}

	if parsed.IsUnspecified() {
		return true
	}

	return port == 0 && (parsed.String() == "0.0.0.0" || parsed.String() == "::")
}

// maskToken masks sensitive tokens for logging
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8]
}

// escapeHTML escapes HTML special characters for Telegram HTML mode
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// PushoverNotifier sends notifications via Pushover
type PushoverNotifier struct {
	config *PushoverConfig
}

func (pn *PushoverNotifier) Enabled() bool {
	return pn.config != nil && pn.config.Enabled && pn.config.APIKey != "" && pn.config.UserKey != ""
}

func (pn *PushoverNotifier) Send(title, message string) error {
	if !pn.Enabled() {
		return fmt.Errorf("pushover not configured")
	}

	data := map[string]string{
		"token":   pn.config.APIKey,
		"user":    pn.config.UserKey,
		"title":   title,
		"message": message,
		"html":    "1",
	}

	if pn.config.Device != "" {
		data["device"] = pn.config.Device
	}
	if pn.config.Sound != "" {
		data["sound"] = pn.config.Sound
	}

	body := encodeForm(data)
	resp, err := http.Post(
		"https://api.pushover.net/1/messages.json",
		"application/x-www-form-urlencoded",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}

	return nil
}

// NtfyNotifier sends notifications via ntfy.sh
type NtfyNotifier struct {
	config *NtfyConfig
}

func (nn *NtfyNotifier) Enabled() bool {
	return nn.config != nil && nn.config.Enabled && nn.config.Topic != ""
}

func (nn *NtfyNotifier) Send(title, message string) error {
	if !nn.Enabled() {
		return fmt.Errorf("ntfy not configured")
	}

	baseURL := nn.config.BaseURL
	if baseURL == "" {
		baseURL = "https://ntfy.sh"
	}

	url := fmt.Sprintf("%s/%s", baseURL, nn.config.Topic)
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(message)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/plain")
	if title != "" {
		req.Header.Set("Title", title)
	}
	req.Header.Set("Tags", "rotating_light,warning")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}

	return nil
}

// PushbulletNotifier sends notifications via Pushbullet
type PushbulletNotifier struct {
	config *PushbulletConfig
}

func (pbn *PushbulletNotifier) Enabled() bool {
	return pbn.config != nil && pbn.config.Enabled && pbn.config.APIKey != ""
}

func (pbn *PushbulletNotifier) Send(title, message string) error {
	if !pbn.Enabled() {
		return fmt.Errorf("pushbullet not configured")
	}

	data := map[string]string{
		"type":  "note",
		"title": title,
		"body":  message,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.pushbullet.com/v2/pushes", bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(pbn.config.APIKey, "")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pushbullet returned status %d", resp.StatusCode)
	}

	return nil
}

// TelegramNotifier sends notifications via Telegram
type TelegramNotifier struct {
	config *TelegramConfig
}

func (tn *TelegramNotifier) Enabled() bool {
	return tn.config != nil && tn.config.Enabled && tn.config.BotToken != "" && tn.config.ChatID != ""
}

func (tn *TelegramNotifier) Send(title, message string) error {
	if !tn.Enabled() {
		return fmt.Errorf("telegram not configured")
	}

	// Use HTML mode instead of Markdown to avoid issues with underscores and other special characters
	// Escape HTML special characters in the message content
	escapedMessage := escapeHTML(message)
	fullMessage := fmt.Sprintf("<b>%s</b>\n\n%s", escapeHTML(title), escapedMessage)

	data := map[string]string{
		"chat_id":    tn.config.ChatID,
		"text":       fullMessage,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tn.config.BotToken)
	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	return nil
}

// WebhookNotifier sends notifications via generic webhook
type WebhookNotifier struct {
	config *WebhookConfig
}

func (wn *WebhookNotifier) Enabled() bool {
	return wn.config != nil && wn.config.Enabled && wn.config.URL != ""
}

func (wn *WebhookNotifier) Send(title, message string) error {
	if !wn.Enabled() {
		return fmt.Errorf("webhook not configured")
	}

	method := wn.config.Method
	if method == "" {
		method = "POST"
	}

	data := map[string]string{
		"title":     title,
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, wn.config.URL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range wn.config.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// encodeForm encodes a map as URL form data
func encodeForm(data map[string]string) []byte {
	var buf bytes.Buffer
	for key, value := range data {
		if buf.Len() > 0 {
			buf.WriteString("&")
		}
		buf.WriteString(fmt.Sprintf("%s=%s", key, value))
	}
	return buf.Bytes()
}
