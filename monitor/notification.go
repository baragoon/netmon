package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NotificationConfig holds the configuration for all notification providers
type NotificationConfig struct {
	Enabled             bool                   `json:"enabled"`
	NotificationCooldown time.Duration         `json:"-"` // Internal field, set from NotificationCooldownStr
	NotificationCooldownStr string             `json:"notification_cooldown"` // JSON field e.g. "1h", "24h"
	Pushover            *PushoverConfig        `json:"pushover,omitempty"`
	Ntfy                *NtfyConfig            `json:"ntfy,omitempty"`
	Pushbullet          *PushbulletConfig      `json:"pushbullet,omitempty"`
	Telegram            *TelegramConfig        `json:"telegram,omitempty"`
	Webhook             *WebhookConfig         `json:"webhook,omitempty"`
	TitleTemplate       string                 `json:"title_template"`
	MessageTemplate     string                 `json:"message_template"`
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
	Enabled bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
	ChatID  string `json:"chat_id"`
}

// WebhookConfig holds generic webhook configuration
type WebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Method  string `json:"method"`
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
			}
		} else {
			config.NotificationCooldown = 24 * time.Hour // Default if not specified
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
		nm.notifiers = append(nm.notifiers, &PushoverNotifier{config: config.Pushover})
	}
	if config.Ntfy != nil && config.Ntfy.Enabled {
		nm.notifiers = append(nm.notifiers, &NtfyNotifier{config: config.Ntfy})
	}
	if config.Pushbullet != nil && config.Pushbullet.Enabled {
		nm.notifiers = append(nm.notifiers, &PushbulletNotifier{config: config.Pushbullet})
	}
	if config.Telegram != nil && config.Telegram.Enabled {
		nm.notifiers = append(nm.notifiers, &TelegramNotifier{config: config.Telegram})
	}
	if config.Webhook != nil && config.Webhook.Enabled {
		nm.notifiers = append(nm.notifiers, &WebhookNotifier{config: config.Webhook})
	}

	return nm
}

// SendAlert sends an alert through all enabled notifiers
func (nm *NotificationManager) SendAlert(conn *Connection) error {
	if nm == nil || len(nm.notifiers) == 0 {
		return nil
	}

	// Build variable map
	vars := map[string]string{
		"ip":        conn.RemoteIP,
		"port":      fmt.Sprintf("%d", conn.RemotePort),
		"service":   conn.ProcessName,
		"protocol":  conn.Protocol,
		"local_ip":  conn.LocalIP,
		"local_port": fmt.Sprintf("%d", conn.LocalPort),
		"timestamp": time.Now().Format(time.RFC3339),
		"reason":    strings.Join(conn.AnomalousReasons, ", "),
		"pid":       fmt.Sprintf("%d", conn.PID),
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

	// Send through all notifiers
	for _, notifier := range nm.notifiers {
		if notifier.Enabled() {
			if err := notifier.Send(title, message); err != nil {
				// Log error but continue sending to other notifiers
				fmt.Printf("[notification] Error sending alert: %v\n", err)
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

	fullMessage := fmt.Sprintf("*%s*\n\n%s", title, message)

	data := map[string]string{
		"chat_id":    tn.config.ChatID,
		"text":       fullMessage,
		"parse_mode": "Markdown",
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
		"title":   title,
		"message": message,
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
