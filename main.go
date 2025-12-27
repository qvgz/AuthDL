package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mojocn/base64Captcha"
	"github.com/qiniu/go-sdk/v7/cdn"
)

//go:embed index.html
var staticFiles embed.FS

// === 1. 核心配置与全局状态 ===

type AppConfig struct {
	BaseURL       string `json:"baseURL"`
	EncryptKey    string `json:"encryptKey"`
	Deadline      int64  `json:"deadline"`
	EnableCaptcha bool   `json:"enableCaptcha"`
}

var (
	Version     = "dev"
	config      AppConfig
	configMutex sync.RWMutex

	// 强化点: 显式定义内存存储参数，防止内存无限制增长
	// CollectNum: 10240 (最大存储条目), Expiration: 3m (3分钟过期)
	store = base64Captcha.NewMemoryStore(10240, 3*time.Minute)

	// 验证码参数: 数字模式, 宽80, 高200 (注意: 库参数顺序是 Height, Width), 长度5, 噪点0.6
	captchaDriver = base64Captcha.NewDriverDigit(80, 200, 5, 0.6, 60)
)

// === 2. 配置管理 (原子性与安全性) ===

// Validate 执行深度校验
func (c *AppConfig) Validate() error {
	if strings.TrimSpace(c.EncryptKey) == "" {
		return errors.New("validate: encryptKey cannot be empty")
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("validate: baseURL cannot be empty")
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("validate: baseURL format error: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("validate: baseURL scheme must be http or https, got: %s", u.Scheme)
	}

	// 修正逻辑放在校验之后，确保配置的确定性
	if c.Deadline <= 0 {
		c.Deadline = 3600 // 默认 1 小时
	}
	if c.Deadline > 86400 {
		c.Deadline = 86400 // 最大 24 小时
	}
	return nil
}

func loadConfigFromSource() (*AppConfig, error) {
	// 默认配置
	cfg := AppConfig{
		Deadline: 3600,
	}

	// 1. 文件加载 (如果存在)
	if f, err := os.Open("config.json"); err == nil {
		defer f.Close()
		decoder := json.NewDecoder(f)
		if err := decoder.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("config file parse error: %v", err)
		}
	} else if !os.IsNotExist(err) {
		// 文件存在但无法打开，视为严重错误
		return nil, fmt.Errorf("config file read error: %v", err)
	}

	// 2. 环境变量覆盖 (优先级更高)
	if v := os.Getenv("APP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("APP_ENCRYPT_KEY"); v != "" {
		cfg.EncryptKey = v
	}
	if v := os.Getenv("APP_ENABLE_CAPTCHA"); v != "" {
		cfg.EnableCaptcha = (strings.ToLower(v) == "true")
	}

	// 3. 执行校验
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func refreshGlobalConfig() error {
	newCfg, err := loadConfigFromSource()
	if err != nil {
		return err
	}

	// 原子替换
	configMutex.Lock()
	config = *newCfg
	configMutex.Unlock()

	// 敏感信息打码日志
	maskedKey := "******"
	if len(newCfg.EncryptKey) > 4 {
		maskedKey = newCfg.EncryptKey[:2] + "****" + newCfg.EncryptKey[len(newCfg.EncryptKey)-2:]
	}

	slog.Info("Config loaded successfully",
		"baseURL", newCfg.BaseURL,
		"captcha", newCfg.EnableCaptcha,
		"deadline", newCfg.Deadline,
		"key_mask", maskedKey,
	)
	return nil
}

// === 3. 辅助工具 ===

func managePID() func() {
	pid := os.Getpid()
	pidFile := "/tmp/authdl.pid"
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		slog.Warn("Could not write PID file", "err", err)
		return func() {}
	}
	return func() {
		_ = os.Remove(pidFile)
	}
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to write JSON response", "err", err)
	}
}

// === 4. 健壮的中间件 ===

// RecoveryMiddleware: 确保单个请求的 Panic 不会搞挂整个服务
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 获取 Stack Trace 有助于排错，但在日志中要小心长度
				slog.Error("PANIC RECOVERED", "error", err, "path", r.URL.Path, "method", r.Method)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecurityMiddleware: 注入安全头
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// LoggerMiddleware: 记录请求，排除健康检查以减少噪音
func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r)

		duration := time.Since(start)

		// 记录结构化日志
		slog.Info("Request handled",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.statusCode,
			"duration_ms", duration.Milliseconds(),
			"ip", getClientIP(r),
			"user_agent", r.UserAgent(),
		)
	})
}

// 封装 ResponseWriter 以捕获状态码
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getClientIP(r *http.Request) string {
	// 信任 Nginx 传递的 X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// === 5. 业务逻辑 Handlers ===

func handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	configMutex.RLock()
	enabled := config.EnableCaptcha
	configMutex.RUnlock()

	if !enabled {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}

	id, b64s, _, err := base64Captcha.NewCaptcha(captchaDriver, store).Generate()
	if err != nil {
		slog.Error("Captcha generation failed", "err", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"msg": "System Error"})
		return
	}

	// 返回 id 和 base64 图片数据
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"id":      id,
		"image":   b64s,
	})
}

func handleVerifyDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"msg": "Method Not Allowed"})
		return
	}

	// 限制请求体大小 (4KB 足够容纳 JSON)，防止大包 DOS
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req struct {
		CaptchaId  string `json:"captchaId"`
		VerifyCode string `json:"verifyCode"`
		Filename   string `json:"filename"`
	}

	// 强化点: 严格 JSON 解析，不允许未知字段
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		slog.Warn("Invalid JSON request", "err", err, "ip", getClientIP(r))
		jsonResponse(w, http.StatusBadRequest, map[string]string{"msg": "Invalid Request Body"})
		return
	}

	configMutex.RLock()
	cfg := config
	configMutex.RUnlock()

	// 校验验证码
	if cfg.EnableCaptcha {
		// Verify 最后一个参数 true 表示验证后立即删除，防止重放
		if !store.Verify(req.CaptchaId, req.VerifyCode, true) {
			jsonResponse(w, http.StatusForbidden, map[string]string{"msg": "验证码错误或已过期"})
			return
		}
	}

	// 校验文件名
	// path.Clean 处理 "./../" 等路径穿越
	cleanName := path.Base(path.Clean(req.Filename))
	if cleanName == "." || cleanName == "/" || cleanName == "" || strings.Contains(cleanName, "\\") {
		slog.Warn("Suspicious filename detected", "filename", req.Filename, "ip", getClientIP(r))
		jsonResponse(w, http.StatusBadRequest, map[string]string{"msg": "非法文件名"})
		return
	}

	// 生成完整 URL
	fullURL, err := url.JoinPath(cfg.BaseURL, cleanName)
	if err != nil {
		slog.Error("URL construction failed", "base", cfg.BaseURL, "file", cleanName, "err", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"msg": "Internal Error"})
		return
	}

	// 七牛云时间戳防盗链签名
	expiryTime := time.Now().Add(time.Duration(cfg.Deadline) * time.Second).Unix()
	signedURL, err := cdn.CreateTimestampAntileechURL(fullURL, cfg.EncryptKey, expiryTime)

	if err != nil {
		slog.Error("CDN signature generation failed", "err", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"msg": "Sign Error"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "url": signedURL})
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	// 防止 API 路径落入静态文件处理
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	f, err := staticFiles.Open("index.html")
	if err != nil {
		slog.Error("Static file missing", "err", err)
		http.Error(w, "System Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 浏览器缓存控制: index.html 这种入口文件通常不缓存或短缓存
	w.Header().Set("Cache-Control", "no-cache")
	io.Copy(w, f)
}

// === 6. 主程序入口 ===

func main() {
	// 初始化结构化日志
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo, // 生产环境通常使用 Info
	}))
	slog.SetDefault(logger)

	// CLI 参数处理
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("AuthDL Version: %s\n", Version)
			os.Exit(0)
		case "check":
			if _, err := loadConfigFromSource(); err != nil {
				fmt.Printf("[\033[31mFAIL\033[0m] Config check failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[\033[32mOK\033[0m] Config is valid.")
			os.Exit(0)
		case "reload":
			// 发送信号给运行中的进程
			pidBytes, err := os.ReadFile("/tmp/authdl.pid")
			if err != nil {
				fmt.Println("Error: Service not running (PID file missing)")
				os.Exit(1)
			}
			pid, _ := strconv.Atoi(string(pidBytes))
			proc, err := os.FindProcess(pid)
			if err != nil {
				fmt.Printf("Error: Process %d not found\n", pid)
				os.Exit(1)
			}
			if err := proc.Signal(syscall.SIGHUP); err != nil {
				fmt.Printf("Error sending signal: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Reload signal (SIGHUP) sent to PID %d\n", pid)
			os.Exit(0)
		}
	}

	flag.Parse()

	// 启动时首次加载配置
	if err := refreshGlobalConfig(); err != nil {
		slog.Error("Fatal: Initial config load failed", "err", err)
		os.Exit(1)
	}

	cleanupPID := managePID()
	defer cleanupPID()

	// 监听配置热重载信号
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	go func() {
		for range hupChan {
			slog.Info("Received SIGHUP, reloading config...")
			if err := refreshGlobalConfig(); err != nil {
				slog.Error("Config reload failed, keeping previous config", "err", err)
			}
		}
	}()

	// 路由注册
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/captcha", handleCaptcha)
	mux.HandleFunc("/api/verify-download", handleVerifyDownload)
	mux.HandleFunc("/", handleStatic)

	// 组装中间件 (执行顺序: Recovery -> Logger -> Security -> Mux)
	handler := securityMiddleware(mux)
	handler = loggerMiddleware(handler)
	handler = recoveryMiddleware(handler)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,   // 防止客户端读慢
		WriteTimeout: 10 * time.Second,  // 防止响应写慢
		IdleTimeout:  120 * time.Second, // 复用连接超时
		// 关键安全设置: 防止 Slowloris 攻击 (客户端发送 Header 极慢)
		ReadHeaderTimeout: 2 * time.Second,
	}

	// 启动服务器协程
	go func() {
		configMutex.RLock()
		slog.Info("Server starting", "port", 8080, "target_url", config.BaseURL)
		configMutex.RUnlock()

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server listen error", "err", err)
			os.Exit(1)
		}
	}()

	// 优雅退出处理
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	slog.Info("Shutting down server...", "signal", sig)

	// 给予 10 秒时间处理在途请求
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced shutdown", "err", err)
	}
	slog.Info("Server exited cleanly")
}
