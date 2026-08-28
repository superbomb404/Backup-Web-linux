package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dchest/captcha"
	_ "modernc.org/sqlite"
)

const (
	appName               = "PVE Backup Web"
	defaultAddr           = ":60000"
	sessionCookie         = "pve_backup_session"
	defaultCaptchaAfter   = 2
	defaultMaxLoginFails  = 10
	mailEventJobNASDone   = "job_nas_done"
	mailEventJobCloudDone = "job_cloud_done"
	mailEventJobFailed    = "job_failed"
	mailEventLoginBan     = "login_ban"
)

var (
	appDir        string
	statePath     string
	stateDBPath   string
	configPath    string
	appKeyPath    string
	certPath      string
	keyPath       string
	bootstrapPath string
	workRootPath  string
)

type App struct {
	mu          sync.Mutex
	db          *sql.DB
	state       State
	config      Config
	cryptoKey   []byte
	tlsCert     tls.Certificate
	sessions    map[string]int64
	loginFails  map[string]*LoginAttempt
	events      map[chan Event]bool
	jobQueue    chan int64
	jobCancels  map[int64]context.CancelFunc
	httpClient  *http.Client
	cloudCancel context.CancelFunc
}

type Config struct {
	ListenAddr             string `json:"listen_addr"`
	PublicBaseURL          string `json:"public_base_url"`
	SynologyBaseURL        string `json:"synology_base_url"`
	SynologyUsername       string `json:"synology_username"`
	SynologyPassword       string `json:"synology_password"`
	SynologyStagingDir     string `json:"synology_staging_dir"`
	SynologyCloudTargetDir string `json:"synology_cloud_target_dir"`
	VerifyTLS              bool   `json:"verify_tls"`
	SMTPEnabled            bool   `json:"smtp_enabled"`
	SMTPHost               string `json:"smtp_host"`
	SMTPPort               int    `json:"smtp_port"`
	SMTPSecure             string `json:"smtp_secure"`
	SMTPUsername           string `json:"smtp_username"`
	SMTPPassword           string `json:"smtp_password"`
	SMTPFromEmail          string `json:"smtp_from_email"`
	SMTPFromName           string `json:"smtp_from_name"`
	MailEventJobNASDone    bool   `json:"mail_event_job_nas_done"`
	MailEventJobCloudDone  bool   `json:"mail_event_job_cloud_done"`
	MailEventJobFailed     bool   `json:"mail_event_job_failed"`
	MailEventLoginBan      bool   `json:"mail_event_login_ban"`
	CaptchaAfterFailures   int    `json:"captcha_after_failures"`
	MaxLoginFailures       int    `json:"max_login_failures"`
	BanDurationMinutes     int    `json:"ban_duration_minutes"`
	PermanentBan           bool   `json:"permanent_ban"`
}

type State struct {
	NextUserID   int64        `json:"next_user_id"`
	NextRootID   int64        `json:"next_root_id"`
	NextJobID    int64        `json:"next_job_id"`
	NextBanID    int64        `json:"next_ban_id"`
	Users        []User       `json:"users"`
	Roots        []Root       `json:"roots"`
	Jobs         []Job        `json:"jobs"`
	JobEvents    []JobEvent   `json:"job_events"`
	Audit        []AuditLog   `json:"audit"`
	LoginBans    []LoginBan   `json:"login_bans"`
	Announcement Announcement `json:"announcement"`
}

type User struct {
	ID              int64    `json:"id"`
	Username        string   `json:"username"`
	Salt            string   `json:"salt"`
	PasswordHash    string   `json:"password_hash"`
	IsAdmin         bool     `json:"is_admin"`
	AllowedRoots    []int64  `json:"allowed_roots"`
	UploadDir       string   `json:"upload_dir"`
	Emails          []string `json:"emails"`
	NotifyJobDone   bool     `json:"notify_job_done"`
	NotifyAdminLogs bool     `json:"notify_admin_logs"`
	CreatedAt       string   `json:"created_at"`
}

type Root struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
}

type Job struct {
	ID             int64    `json:"id"`
	UserID         int64    `json:"user_id"`
	RootID         int64    `json:"root_id"`
	SourceRelPath  string   `json:"source_rel_path"`
	SourceAbsPath  string   `json:"source_abs_path"`
	SourceIsDir    bool     `json:"source_is_dir"`
	SourceSize     int64    `json:"source_size"`
	SourceMtime    string   `json:"source_mtime"`
	Stage          string   `json:"stage"`
	TransferBytes  int64    `json:"transfer_bytes"`
	TransferTotal  int64    `json:"transfer_total"`
	TransferSpeed  int64    `json:"transfer_speed"`
	CloudBytes     int64    `json:"cloud_bytes"`
	CloudTotal     int64    `json:"cloud_total"`
	CloudSpeed     int64    `json:"cloud_speed"`
	NASPath        string   `json:"nas_path"`
	StagingPath    string   `json:"staging_path"`
	Error          string   `json:"error"`
	CreatedAt      string   `json:"created_at"`
	StartedAt      string   `json:"started_at"`
	CompletedAt    string   `json:"completed_at"`
	CloudUpdatedAt string   `json:"cloud_updated_at"`
	NotifiedEvents []string `json:"notified_events"`
}

type AuditLog struct {
	Time    string `json:"time"`
	UserID  int64  `json:"user_id"`
	Action  string `json:"action"`
	Details string `json:"details"`
	IP      string `json:"ip"`
}

type JobEvent struct {
	Time          string `json:"time"`
	JobID         int64  `json:"job_id"`
	UserID        int64  `json:"user_id"`
	Stage         string `json:"stage"`
	TransferBytes int64  `json:"transfer_bytes"`
	TransferTotal int64  `json:"transfer_total"`
	CloudBytes    int64  `json:"cloud_bytes"`
	CloudTotal    int64  `json:"cloud_total"`
	Message       string `json:"message"`
}

type Announcement struct {
	Content   string `json:"content"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy int64  `json:"updated_by"`
}

type LoginBan struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	UserID    int64  `json:"user_id"`
	IP        string `json:"ip"`
	Permanent bool   `json:"permanent"`
	Until     string `json:"until"`
	CreatedAt string `json:"created_at"`
	CreatedBy int64  `json:"created_by"`
	Reason    string `json:"reason"`
}

type LoginAttempt struct {
	Count  int
	LastAt time.Time
}

type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

var errJobCanceled = errors.New("job canceled")

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	app, err := NewApp()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[startup] app_dir=%s", appDir)
	log.Printf("[startup] database=%s config=%s key=%s work_dir=%s", stateDBPath, configPath, appKeyPath, workRootPath)
	go app.worker()
	ctx, cancel := context.WithCancel(context.Background())
	app.cloudCancel = cancel
	go app.cloudMonitor(ctx)

	mux := http.NewServeMux()
	app.routes(mux)
	handler := securityHeaders(mux)
	addr := app.config.ListenAddr
	if addr == "" {
		addr = defaultAddr
	}

	if err := app.loadTLSCertificate(); err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: &tls.Config{GetCertificate: app.getTLSCertificate, MinVersion: tls.VersionTLS12},
	}
	log.Printf("[startup] %s listening on https://0.0.0.0%s", appName, addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func NewApp() (*App, error) {
	if err := initAppPaths(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(appDir, 0700); err != nil {
		return nil, err
	}
	key, err := loadAppKey()
	if err != nil {
		return nil, err
	}
	db, err := openStateDB()
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	st, err := loadState(db)
	if err != nil {
		return nil, err
	}
	app := &App{
		db:         db,
		state:      st,
		config:     cfg,
		cryptoKey:  key,
		sessions:   map[string]int64{},
		loginFails: map[string]*LoginAttempt{},
		events:     map[chan Event]bool{},
		jobQueue:   make(chan int64, 100),
		jobCancels: map[int64]context.CancelFunc{},
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS},
			Proxy:           http.ProxyFromEnvironment,
		}},
	}
	if err := app.loadSecureConfig(); err != nil {
		return nil, err
	}
	app.httpClient = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !app.config.VerifyTLS},
		Proxy:           http.ProxyFromEnvironment,
	}}
	app.requeueUnfinished()
	return app, nil
}

func loadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:             defaultAddr,
		PublicBaseURL:          "https://202.189.4.217:60000",
		SynologyStagingDir:     "/NVME/.pve-backup-incoming",
		SynologyCloudTargetDir: "/NVME/百度云测试/PVEBackup",
		VerifyTLS:              false,
		SMTPPort:               587,
		SMTPSecure:             "starttls",
		SMTPFromName:           appName,
		MailEventJobNASDone:    true,
		MailEventJobCloudDone:  true,
		MailEventJobFailed:     true,
		MailEventLoginBan:      true,
		CaptchaAfterFailures:   defaultCaptchaAfter,
		MaxLoginFailures:       defaultMaxLoginFails,
		BanDurationMinutes:     0,
		PermanentBan:           true,
	}
	b, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("[config] creating default config at %s", configPath)
		return cfg, writeConfigFile(cfg)
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	normalizeConfig(&cfg)
	log.Printf("[config] loaded config from %s listen=%s public_url=%s", configPath, cfg.ListenAddr, cfg.PublicBaseURL)
	return cfg, nil
}

func initAppPaths() error {
	dir := os.Getenv("PVE_BACKUP_HOME")
	if strings.TrimSpace(dir) == "" {
		exe, err := os.Executable()
		if err != nil {
			wd, wdErr := os.Getwd()
			if wdErr != nil {
				return err
			}
			dir = wd
		} else {
			dir = filepath.Dir(exe)
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	appDir = abs
	statePath = filepath.Join(appDir, "state.json")
	stateDBPath = filepath.Join(appDir, "state.db")
	configPath = filepath.Join(appDir, "config.json")
	appKeyPath = filepath.Join(appDir, "app.key")
	certPath = filepath.Join(appDir, "server.crt")
	keyPath = filepath.Join(appDir, "server.key")
	bootstrapPath = filepath.Join(appDir, "bootstrap-admin-password")
	workRootPath = filepath.Join(appDir, "work")
	log.Printf("[startup] resolved runtime paths under %s", appDir)
	return nil
}

func normalizeConfig(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultAddr
	}
	if listen, _, err := normalizeListenAddr(cfg.ListenAddr); err == nil {
		cfg.ListenAddr = listen
	} else {
		cfg.ListenAddr = defaultAddr
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "https://202.189.4.217:60000"
	}
	cfg.SynologyStagingDir = synoClean(cfg.SynologyStagingDir)
	cfg.SynologyCloudTargetDir = synoClean(cfg.SynologyCloudTargetDir)
	if cfg.SynologyStagingDir == "/" {
		cfg.SynologyStagingDir = "/NVME/.pve-backup-incoming"
	}
	if cfg.SynologyCloudTargetDir == "/" {
		cfg.SynologyCloudTargetDir = "/NVME/百度云测试/PVEBackup"
	}
	if cfg.CaptchaAfterFailures <= 0 {
		cfg.CaptchaAfterFailures = defaultCaptchaAfter
	}
	if cfg.MaxLoginFailures <= 0 {
		cfg.MaxLoginFailures = defaultMaxLoginFails
	}
	if cfg.MaxLoginFailures <= cfg.CaptchaAfterFailures {
		cfg.MaxLoginFailures = cfg.CaptchaAfterFailures + 1
	}
	if cfg.BanDurationMinutes < 0 {
		cfg.BanDurationMinutes = 0
	}
	cfg.SMTPHost = strings.TrimSpace(cfg.SMTPHost)
	cfg.SMTPUsername = strings.TrimSpace(cfg.SMTPUsername)
	cfg.SMTPFromEmail = strings.TrimSpace(cfg.SMTPFromEmail)
	cfg.SMTPFromName = strings.TrimSpace(cfg.SMTPFromName)
	if cfg.SMTPPort == 0 {
		cfg.SMTPPort = 587
	}
	if cfg.SMTPPort < 0 || cfg.SMTPPort > 65535 {
		cfg.SMTPPort = 587
	}
	cfg.SMTPSecure = normalizeSMTPSecure(cfg.SMTPSecure)
	if cfg.SMTPFromName == "" {
		cfg.SMTPFromName = appName
	}
}

func writeConfigFile(cfg Config) error {
	cfg.SynologyBaseURL = ""
	cfg.SynologyUsername = ""
	cfg.SynologyPassword = ""
	cfg.SMTPUsername = ""
	cfg.SMTPPassword = ""
	return writeJSON(configPath, cfg, 0600)
}

func loadAppKey() ([]byte, error) {
	b, err := os.ReadFile(appKeyPath)
	if err == nil {
		raw := strings.TrimSpace(string(b))
		key, decErr := base64.RawURLEncoding.DecodeString(raw)
		if decErr != nil {
			key, decErr = base64.StdEncoding.DecodeString(raw)
		}
		if decErr != nil || len(key) != 32 {
			return nil, errors.New("invalid app.key; expected a base64-encoded 32-byte key")
		}
		log.Printf("[crypto] loaded application encryption key from %s", appKeyPath)
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(appKeyPath, []byte(base64.RawURLEncoding.EncodeToString(key)+"\n"), 0600); err != nil {
		return nil, err
	}
	log.Printf("[crypto] generated new application encryption key at %s", appKeyPath)
	return key, nil
}

func openStateDB() (*sql.DB, error) {
	if err := os.MkdirAll(appDir, 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", stateDBPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			salt TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL,
			allowed_roots TEXT NOT NULL,
			upload_dir TEXT NOT NULL DEFAULT '',
			emails TEXT NOT NULL DEFAULT '[]',
			notify_job_done INTEGER NOT NULL DEFAULT 0,
			notify_admin_logs INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS roots (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			root_id INTEGER NOT NULL,
			source_rel_path TEXT NOT NULL,
			source_abs_path TEXT NOT NULL,
			source_is_dir INTEGER NOT NULL DEFAULT 0,
			source_size INTEGER NOT NULL,
			source_mtime TEXT NOT NULL,
			stage TEXT NOT NULL,
			transfer_bytes INTEGER NOT NULL,
			transfer_total INTEGER NOT NULL DEFAULT 0,
			transfer_speed INTEGER NOT NULL,
			cloud_bytes INTEGER NOT NULL,
			cloud_total INTEGER NOT NULL,
			cloud_speed INTEGER NOT NULL,
			nas_path TEXT NOT NULL,
			staging_path TEXT NOT NULL,
			error TEXT NOT NULL,
			created_at TEXT NOT NULL,
			started_at TEXT NOT NULL,
			completed_at TEXT NOT NULL,
			cloud_updated_at TEXT NOT NULL,
			notified_events TEXT NOT NULL DEFAULT '[]'
		)`,
		`CREATE TABLE IF NOT EXISTS audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			action TEXT NOT NULL,
			details TEXT NOT NULL,
			ip TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS job_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time TEXT NOT NULL,
			job_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			stage TEXT NOT NULL,
			transfer_bytes INTEGER NOT NULL,
			transfer_total INTEGER NOT NULL,
			cloud_bytes INTEGER NOT NULL,
			cloud_total INTEGER NOT NULL,
			message TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS secure_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS login_bans (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			permanent INTEGER NOT NULL,
			until TEXT NOT NULL,
			created_at TEXT NOT NULL,
			created_by INTEGER NOT NULL,
			reason TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN upload_dir TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN emails TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE users ADD COLUMN notify_job_done INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN notify_admin_logs INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE jobs ADD COLUMN source_is_dir INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE jobs ADD COLUMN transfer_total INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE jobs ADD COLUMN notified_events TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE audit ADD COLUMN ip TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			_ = db.Close()
			return nil, err
		}
	}
	log.Printf("[db] sqlite ready at %s", stateDBPath)
	return db, nil
}

func loadState(db *sql.DB) (State, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return State{}, err
	}
	if count > 0 {
		return readStateDB(db)
	}
	st, imported, err := loadJSONState()
	if err != nil {
		return st, err
	}
	if err := writeStateDB(db, st); err != nil {
		return st, err
	}
	if imported {
		log.Printf("imported existing JSON state into %s", stateDBPath)
	} else {
		log.Printf("initialized SQLite state at %s", stateDBPath)
	}
	return st, nil
}

func loadJSONState() (State, bool, error) {
	var st State
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		st.NextUserID = 2
		st.NextRootID = 1
		st.NextJobID = 1
		adminPW, err := initialAdminPassword()
		if err != nil {
			return st, false, err
		}
		salt, hash := hashPassword(adminPW)
		st.Users = []User{{
			ID:           1,
			Username:     "admin",
			Salt:         salt,
			PasswordHash: hash,
			IsAdmin:      true,
			AllowedRoots: []int64{},
			CreatedAt:    now(),
		}}
		for _, p := range []string{"/var/lib/vz/dump", "/etc/pve", "/root", "/tmp"} {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				st.Roots = append(st.Roots, Root{ID: st.NextRootID, Name: filepath.Base(p), Path: p, CreatedAt: now()})
				st.NextRootID++
			}
		}
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, false, err
	}
	normalizeState(&st)
	return st, true, nil
}

func normalizeState(st *State) {
	if st.NextUserID == 0 {
		st.NextUserID = 1
	}
	if st.NextRootID == 0 {
		st.NextRootID = 1
	}
	if st.NextJobID == 0 {
		st.NextJobID = 1
	}
	if st.NextBanID == 0 {
		st.NextBanID = 1
	}
	for _, u := range st.Users {
		if u.ID >= st.NextUserID {
			st.NextUserID = u.ID + 1
		}
	}
	for i := range st.Users {
		st.Users[i].Emails = normalizeEmailList(st.Users[i].Emails)
		if !st.Users[i].IsAdmin {
			st.Users[i].NotifyAdminLogs = false
		}
	}
	for _, r := range st.Roots {
		if r.ID >= st.NextRootID {
			st.NextRootID = r.ID + 1
		}
	}
	for _, j := range st.Jobs {
		if j.ID >= st.NextJobID {
			st.NextJobID = j.ID + 1
		}
	}
	for _, ban := range st.LoginBans {
		if ban.ID >= st.NextBanID {
			st.NextBanID = ban.ID + 1
		}
	}
}

func (a *App) requeueUnfinished() {
	for i := range a.state.Jobs {
		switch a.state.Jobs[i].Stage {
		case "CopyingToNAS", "Pending":
			a.state.Jobs[i].Stage = "Pending"
			a.jobQueue <- a.state.Jobs[i].ID
		case "MovingToCloudDir":
			a.state.Jobs[i].Stage = "NASCompleted"
			a.jobQueue <- a.state.Jobs[i].ID
		}
	}
}

func (a *App) saveLocked() error {
	return writeStateDB(a.db, a.state)
}

func readStateDB(db *sql.DB) (State, error) {
	st := State{}
	rows, err := db.Query(`SELECT id, username, salt, password_hash, is_admin, allowed_roots, upload_dir, emails, notify_job_done, notify_admin_logs, created_at FROM users ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var u User
		var isAdmin int
		var allowed string
		var emails string
		var notifyJobDone int
		var notifyAdminLogs int
		if err := rows.Scan(&u.ID, &u.Username, &u.Salt, &u.PasswordHash, &isAdmin, &allowed, &u.UploadDir, &emails, &notifyJobDone, &notifyAdminLogs, &u.CreatedAt); err != nil {
			rows.Close()
			return st, err
		}
		u.IsAdmin = isAdmin != 0
		_ = json.Unmarshal([]byte(allowed), &u.AllowedRoots)
		_ = json.Unmarshal([]byte(emails), &u.Emails)
		u.Emails = normalizeEmailList(u.Emails)
		u.NotifyJobDone = notifyJobDone != 0
		u.NotifyAdminLogs = notifyAdminLogs != 0 && u.IsAdmin
		st.Users = append(st.Users, u)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	rows, err = db.Query(`SELECT id, name, path, created_at FROM roots ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var r Root
		if err := rows.Scan(&r.ID, &r.Name, &r.Path, &r.CreatedAt); err != nil {
			rows.Close()
			return st, err
		}
		st.Roots = append(st.Roots, r)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	rows, err = db.Query(`SELECT id, user_id, root_id, source_rel_path, source_abs_path, source_is_dir, source_size, source_mtime, stage, transfer_bytes, transfer_total, transfer_speed, cloud_bytes, cloud_total, cloud_speed, nas_path, staging_path, error, created_at, started_at, completed_at, cloud_updated_at, notified_events FROM jobs ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var j Job
		var sourceIsDir int
		var notified string
		if err := rows.Scan(&j.ID, &j.UserID, &j.RootID, &j.SourceRelPath, &j.SourceAbsPath, &sourceIsDir, &j.SourceSize, &j.SourceMtime, &j.Stage, &j.TransferBytes, &j.TransferTotal, &j.TransferSpeed, &j.CloudBytes, &j.CloudTotal, &j.CloudSpeed, &j.NASPath, &j.StagingPath, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.CloudUpdatedAt, &notified); err != nil {
			rows.Close()
			return st, err
		}
		j.SourceIsDir = sourceIsDir != 0
		_ = json.Unmarshal([]byte(notified), &j.NotifiedEvents)
		st.Jobs = append(st.Jobs, j)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	rows, err = db.Query(`SELECT time, user_id, action, details, ip FROM audit ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.Time, &l.UserID, &l.Action, &l.Details, &l.IP); err != nil {
			rows.Close()
			return st, err
		}
		st.Audit = append(st.Audit, l)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	rows, err = db.Query(`SELECT time, job_id, user_id, stage, transfer_bytes, transfer_total, cloud_bytes, cloud_total, message FROM job_events ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var ev JobEvent
		if err := rows.Scan(&ev.Time, &ev.JobID, &ev.UserID, &ev.Stage, &ev.TransferBytes, &ev.TransferTotal, &ev.CloudBytes, &ev.CloudTotal, &ev.Message); err != nil {
			rows.Close()
			return st, err
		}
		st.JobEvents = append(st.JobEvents, ev)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	rows, err = db.Query(`SELECT id, username, user_id, ip, permanent, until, created_at, created_by, reason FROM login_bans ORDER BY id`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var ban LoginBan
		var permanent int
		if err := rows.Scan(&ban.ID, &ban.Username, &ban.UserID, &ban.IP, &permanent, &ban.Until, &ban.CreatedAt, &ban.CreatedBy, &ban.Reason); err != nil {
			rows.Close()
			return st, err
		}
		ban.Permanent = permanent != 0
		st.LoginBans = append(st.LoginBans, ban)
	}
	if err := rows.Close(); err != nil {
		return st, err
	}

	var announcementRaw string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, "announcement").Scan(&announcementRaw); err == nil {
		_ = json.Unmarshal([]byte(announcementRaw), &st.Announcement)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}

	st.NextUserID = readMetaInt(db, "next_user_id")
	st.NextRootID = readMetaInt(db, "next_root_id")
	st.NextJobID = readMetaInt(db, "next_job_id")
	st.NextBanID = readMetaInt(db, "next_ban_id")
	normalizeState(&st)
	return st, nil
}

func writeStateDB(db *sql.DB, st State) error {
	normalizeState(&st)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"meta", "users", "roots", "jobs", "audit", "job_events", "settings", "login_bans"} {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return err
		}
	}
	for k, v := range map[string]int64{"next_user_id": st.NextUserID, "next_root_id": st.NextRootID, "next_job_id": st.NextJobID, "next_ban_id": st.NextBanID} {
		if _, err := tx.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)`, k, v); err != nil {
			return err
		}
	}
	for _, u := range st.Users {
		allowed, _ := json.Marshal(u.AllowedRoots)
		emails, _ := json.Marshal(normalizeEmailList(u.Emails))
		if _, err := tx.Exec(`INSERT INTO users(id, username, salt, password_hash, is_admin, allowed_roots, upload_dir, emails, notify_job_done, notify_admin_logs, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Username, u.Salt, u.PasswordHash, boolInt(u.IsAdmin), string(allowed), u.UploadDir, string(emails), boolInt(u.NotifyJobDone), boolInt(u.NotifyAdminLogs && u.IsAdmin), u.CreatedAt); err != nil {
			return err
		}
	}
	for _, r := range st.Roots {
		if _, err := tx.Exec(`INSERT INTO roots(id, name, path, created_at) VALUES(?, ?, ?, ?)`, r.ID, r.Name, r.Path, r.CreatedAt); err != nil {
			return err
		}
	}
	for _, j := range st.Jobs {
		notified, _ := json.Marshal(j.NotifiedEvents)
		if _, err := tx.Exec(`INSERT INTO jobs(id, user_id, root_id, source_rel_path, source_abs_path, source_is_dir, source_size, source_mtime, stage, transfer_bytes, transfer_total, transfer_speed, cloud_bytes, cloud_total, cloud_speed, nas_path, staging_path, error, created_at, started_at, completed_at, cloud_updated_at, notified_events) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			j.ID, j.UserID, j.RootID, j.SourceRelPath, j.SourceAbsPath, boolInt(j.SourceIsDir), j.SourceSize, j.SourceMtime, j.Stage, j.TransferBytes, j.TransferTotal, j.TransferSpeed, j.CloudBytes, j.CloudTotal, j.CloudSpeed, j.NASPath, j.StagingPath, j.Error, j.CreatedAt, j.StartedAt, j.CompletedAt, j.CloudUpdatedAt, string(notified)); err != nil {
			return err
		}
	}
	auditStart := 0
	if len(st.Audit) > 10000 {
		auditStart = len(st.Audit) - 10000
	}
	for _, l := range st.Audit[auditStart:] {
		if _, err := tx.Exec(`INSERT INTO audit(time, user_id, action, details, ip) VALUES(?, ?, ?, ?, ?)`, l.Time, l.UserID, l.Action, l.Details, l.IP); err != nil {
			return err
		}
	}
	eventStart := 0
	if len(st.JobEvents) > 10000 {
		eventStart = len(st.JobEvents) - 10000
	}
	for _, ev := range st.JobEvents[eventStart:] {
		if _, err := tx.Exec(`INSERT INTO job_events(time, job_id, user_id, stage, transfer_bytes, transfer_total, cloud_bytes, cloud_total, message) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ev.Time, ev.JobID, ev.UserID, ev.Stage, ev.TransferBytes, ev.TransferTotal, ev.CloudBytes, ev.CloudTotal, ev.Message); err != nil {
			return err
		}
	}
	announcementRaw, _ := json.Marshal(st.Announcement)
	if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)`, "announcement", string(announcementRaw)); err != nil {
		return err
	}
	for _, ban := range st.LoginBans {
		if _, err := tx.Exec(`INSERT INTO login_bans(id, username, user_id, ip, permanent, until, created_at, created_by, reason) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ban.ID, ban.Username, ban.UserID, ban.IP, boolInt(ban.Permanent), ban.Until, ban.CreatedAt, ban.CreatedBy, ban.Reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func readMetaInt(db *sql.DB, key string) int64 {
	var v int64
	_ = db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (a *App) loadSecureConfig() error {
	keys := map[string]*string{
		"synology_base_url": &a.config.SynologyBaseURL,
		"synology_username": &a.config.SynologyUsername,
		"synology_password": &a.config.SynologyPassword,
		"smtp_username":     &a.config.SMTPUsername,
		"smtp_password":     &a.config.SMTPPassword,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	loaded := []string{}
	migrated := []string{}
	for key, target := range keys {
		value, ok, err := a.readSecureStringLocked(key)
		if err != nil {
			return err
		}
		if ok {
			*target = value
			loaded = append(loaded, key)
			continue
		}
		if strings.TrimSpace(*target) != "" {
			if err := a.writeSecureStringLocked(key, *target); err != nil {
				return err
			}
			migrated = append(migrated, key)
		}
	}
	normalizeConfig(&a.config)
	log.Printf("[crypto] secure config loaded=%v migrated_from_plain_config=%v", loaded, migrated)
	return a.saveConfigLocked()
}

func (a *App) saveConfigLocked() error {
	for key, value := range map[string]string{
		"synology_base_url": a.config.SynologyBaseURL,
		"synology_username": a.config.SynologyUsername,
		"synology_password": a.config.SynologyPassword,
		"smtp_username":     a.config.SMTPUsername,
		"smtp_password":     a.config.SMTPPassword,
	} {
		if err := a.writeSecureStringLocked(key, value); err != nil {
			return err
		}
	}
	return writeConfigFile(a.config)
}

func (a *App) readSecureStringLocked(key string) (string, bool, error) {
	var encoded string
	err := a.db.QueryRow(`SELECT value FROM secure_settings WHERE key = ?`, key).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := a.decryptString(encoded)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

func (a *App) writeSecureStringLocked(key, value string) error {
	encoded, err := a.encryptString(value)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`INSERT INTO secure_settings(key, value, updated_at) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, encoded, now())
	return err
}

func (a *App) encryptString(plain string) (string, error) {
	block, err := aes.NewCipher(a.cryptoKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	raw := append(nonce, ciphertext...)
	return "v1:" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func (a *App) decryptString(encoded string) (string, error) {
	encoded = strings.TrimSpace(encoded)
	if !strings.HasPrefix(encoded, "v1:") {
		return "", errors.New("unsupported encrypted value format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.cryptoKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value is too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func writeJSON(file string, v interface{}, mode os.FileMode) error {
	tmp := file + ".tmp"
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, append(b, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func initialAdminPassword() (string, error) {
	if b, err := os.ReadFile(bootstrapPath); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	pw := randomToken(18)
	if err := os.WriteFile(bootstrapPath, []byte(pw+"\n"), 0600); err != nil {
		return "", err
	}
	return pw, nil
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/favicon.svg", a.handleFavicon)
	mux.HandleFunc("/favicon.ico", a.handleFavicon)
	mux.HandleFunc("/api/captcha/new", a.handleCaptchaNew)
	mux.HandleFunc("/api/captcha/", a.handleCaptchaImage)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.handleLogout)
	mux.HandleFunc("/api/me", a.auth(a.handleMe))
	mux.HandleFunc("/api/change-password", a.auth(a.handleChangePassword))
	mux.HandleFunc("/api/account/notifications", a.auth(a.handleAccountNotifications))
	mux.HandleFunc("/api/announcement", a.auth(a.handleAnnouncement))
	mux.HandleFunc("/api/events", a.auth(a.handleEvents))
	mux.HandleFunc("/api/roots", a.auth(a.handleRoots))
	mux.HandleFunc("/api/files", a.auth(a.handleFiles))
	mux.HandleFunc("/api/jobs", a.auth(a.handleJobs))
	mux.HandleFunc("/api/jobs/action", a.auth(a.handleJobAction))
	mux.HandleFunc("/api/admin/users", a.auth(a.admin(a.handleAdminUsers)))
	mux.HandleFunc("/api/admin/user-password", a.auth(a.admin(a.handleAdminUserPassword)))
	mux.HandleFunc("/api/admin/user-delete", a.auth(a.admin(a.handleAdminUserDelete)))
	mux.HandleFunc("/api/admin/user-roots", a.auth(a.admin(a.handleAdminUserRoots)))
	mux.HandleFunc("/api/admin/user-upload-dir", a.auth(a.admin(a.handleAdminUserUploadDir)))
	mux.HandleFunc("/api/admin/roots", a.auth(a.admin(a.handleAdminRoots)))
	mux.HandleFunc("/api/admin/root-delete", a.auth(a.admin(a.handleAdminRootDelete)))
	mux.HandleFunc("/api/admin/site", a.auth(a.admin(a.handleAdminSite)))
	mux.HandleFunc("/api/admin/synology", a.auth(a.admin(a.handleAdminSynology)))
	mux.HandleFunc("/api/admin/mail", a.auth(a.admin(a.handleAdminMail)))
	mux.HandleFunc("/api/admin/mail/test", a.auth(a.admin(a.handleAdminMailTest)))
	mux.HandleFunc("/api/admin/announcement", a.auth(a.admin(a.handleAdminAnnouncement)))
	mux.HandleFunc("/api/admin/logs", a.auth(a.admin(a.handleAdminLogs)))
	mux.HandleFunc("/api/admin/logs/clear", a.auth(a.admin(a.handleAdminClearLogs)))
	mux.HandleFunc("/api/admin/certificate", a.auth(a.admin(a.handleAdminCertificate)))
	mux.HandleFunc("/api/admin/security", a.auth(a.admin(a.handleAdminSecurity)))
	mux.HandleFunc("/api/admin/security/unban", a.auth(a.admin(a.handleAdminUnban)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (a *App) auth(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.currentUser(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		next(w, r, u)
	}
}

func (a *App) admin(next func(http.ResponseWriter, *http.Request, User)) func(http.ResponseWriter, *http.Request, User) {
	return func(w http.ResponseWriter, r *http.Request, u User) {
		if !u.IsAdmin {
			jsonError(w, http.StatusForbidden, "admin required")
			return
		}
		next(w, r, u)
	}
}

func (a *App) currentUser(r *http.Request) (User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return User{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	uid, ok := a.sessions[c.Value]
	if !ok {
		return User{}, false
	}
	for _, u := range a.state.Users {
		if u.ID == uid {
			return u, true
		}
	}
	return User{}, false
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func (a *App) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	_, _ = io.WriteString(w, faviconSVG)
}

func (a *App) handleCaptchaNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSONResponse(w, map[string]interface{}{"captcha": newCaptchaChallenge()})
}

func (a *App) handleCaptchaImage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/captcha/")
	id = strings.TrimSuffix(id, ".png")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/png")
	if err := captcha.WriteImage(w, id, 180, 64); err != nil {
		http.NotFound(w, r)
		return
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	ip := clientIP(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	if ban, ok := a.activeLoginBanLocked(req.Username, ip); ok {
		log.Printf("[security] login blocked username=%q ip=%s ban_id=%d permanent=%t until=%s", req.Username, ip, ban.ID, ban.Permanent, ban.Until)
		a.auditWithIPLocked(0, "login_blocked", "username="+req.Username+" ban="+strconv.FormatInt(ban.ID, 10), ip)
		_ = a.saveLocked()
		jsonErrorWith(w, http.StatusForbidden, "login is banned", banPayload(ban))
		return
	}
	if a.captchaRequiredLocked(req.Username, ip) {
		if !a.validateCaptchaLocked(req.CaptchaID, req.CaptchaAnswer) {
			challenge := a.newCaptchaLocked()
			log.Printf("[security] captcha required username=%q ip=%s captcha_id=%s", req.Username, ip, challenge["id"])
			jsonErrorWith(w, http.StatusUnauthorized, "captcha required", map[string]interface{}{
				"captcha_required": true,
				"captcha":          challenge,
			})
			return
		}
	}
	for _, u := range a.state.Users {
		if u.Username == req.Username && verifyPassword(req.Password, u.Salt, u.PasswordHash) {
			token := randomToken(32)
			a.sessions[token] = u.ID
			a.clearLoginFailuresLocked(req.Username, ip)
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
			a.auditWithIPLocked(u.ID, "login", "success", ip)
			_ = a.saveLocked()
			log.Printf("[auth] login success username=%q user_id=%d ip=%s", u.Username, u.ID, ip)
			writeJSONResponse(w, map[string]interface{}{"success": true, "user": publicUser(u)})
			return
		}
	}
	count, banned, ban := a.registerFailedLoginLocked(req.Username, ip)
	details := fmt.Sprintf("username=%s failures=%d", req.Username, count)
	if banned {
		details += " banned=true"
	}
	a.auditWithIPLocked(0, "login_failed", details, ip)
	_ = a.saveLocked()
	log.Printf("[auth] login failed username=%q ip=%s failures=%d banned=%t", req.Username, ip, count, banned)
	if banned {
		log.Printf("[security] created login ban username=%q ip=%s ban_id=%d permanent=%t until=%s", req.Username, ip, ban.ID, ban.Permanent, ban.Until)
		go a.notifyLoginBan(ban)
		jsonErrorWith(w, http.StatusForbidden, "too many failed attempts; login is banned", banPayload(ban))
		return
	}
	if a.captchaRequiredLocked(req.Username, ip) {
		challenge := a.newCaptchaLocked()
		log.Printf("[security] captcha issued after failed login username=%q ip=%s captcha_id=%s", req.Username, ip, challenge["id"])
		jsonErrorWith(w, http.StatusUnauthorized, "invalid username or password", map[string]interface{}{
			"captcha_required": true,
			"captcha":          challenge,
		})
		return
	}
	jsonError(w, http.StatusUnauthorized, "invalid username or password")
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	writeJSONResponse(w, map[string]interface{}{"success": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request, u User) {
	a.mu.Lock()
	announcement := a.state.Announcement
	var config map[string]interface{}
	if u.IsAdmin {
		config = a.publicConfigLocked()
	} else {
		config = map[string]interface{}{}
	}
	a.mu.Unlock()
	writeJSONResponse(w, map[string]interface{}{"user": publicUser(u), "config": config, "announcement": announcement})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request, u User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Users {
		if a.state.Users[i].ID == u.ID {
			if !verifyPassword(req.CurrentPassword, a.state.Users[i].Salt, a.state.Users[i].PasswordHash) {
				jsonError(w, http.StatusUnauthorized, "current password is incorrect")
				return
			}
			salt, hash := hashPassword(req.NewPassword)
			a.state.Users[i].Salt = salt
			a.state.Users[i].PasswordHash = hash
			a.auditLocked(u.ID, "change_password", "")
			_ = a.saveLocked()
			writeJSONResponse(w, map[string]interface{}{"success": true})
			return
		}
	}
	jsonError(w, http.StatusNotFound, "user not found")
}

func (a *App) handleAccountNotifications(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, current := range a.state.Users {
			if current.ID == u.ID {
				writeJSONResponse(w, map[string]interface{}{"user": publicUser(current)})
				return
			}
		}
		jsonError(w, http.StatusNotFound, "user not found")
	case http.MethodPost:
		var req struct {
			Emails          []string `json:"emails"`
			NotifyJobDone   bool     `json:"notify_job_done"`
			NotifyAdminLogs bool     `json:"notify_admin_logs"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		emails, err := validateEmailList(req.Emails)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		for i := range a.state.Users {
			if a.state.Users[i].ID == u.ID {
				a.state.Users[i].Emails = emails
				a.state.Users[i].NotifyJobDone = req.NotifyJobDone
				a.state.Users[i].NotifyAdminLogs = req.NotifyAdminLogs && a.state.Users[i].IsAdmin
				a.auditWithIPLocked(u.ID, "update_email_settings", fmt.Sprintf("emails=%d job_done=%t admin_logs=%t", len(emails), a.state.Users[i].NotifyJobDone, a.state.Users[i].NotifyAdminLogs), clientIP(r))
				_ = a.saveLocked()
				log.Printf("[account] email settings updated user=%q emails=%d job_done=%t admin_logs=%t ip=%s", a.state.Users[i].Username, len(emails), a.state.Users[i].NotifyJobDone, a.state.Users[i].NotifyAdminLogs, clientIP(r))
				writeJSONResponse(w, map[string]interface{}{"success": true, "user": publicUser(a.state.Users[i])})
				return
			}
		}
		jsonError(w, http.StatusNotFound, "user not found")
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAnnouncement(w http.ResponseWriter, r *http.Request, u User) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.mu.Lock()
	announcement := a.state.Announcement
	a.mu.Unlock()
	writeJSONResponse(w, map[string]interface{}{"announcement": announcement})
}

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request, u User) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, http.StatusInternalServerError, "stream unsupported")
		return
	}
	ch := make(chan Event, 32)
	a.mu.Lock()
	a.events[ch] = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.events, ch)
		a.mu.Unlock()
		close(ch)
	}()
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case ev := <-ch:
			data, ok := a.eventDataForUser(ev, u)
			if !ok {
				continue
			}
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
			flusher.Flush()
		case <-t.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (a *App) handleRoots(w http.ResponseWriter, r *http.Request, u User) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var roots []Root
	for _, root := range a.state.Roots {
		if u.IsAdmin || containsID(u.AllowedRoots, root.ID) {
			roots = append(roots, publicRoot(root, u))
		}
	}
	writeJSONResponse(w, map[string]interface{}{"roots": roots})
}

func (a *App) handleFiles(w http.ResponseWriter, r *http.Request, u User) {
	rootID, _ := strconv.ParseInt(r.URL.Query().Get("root_id"), 10, 64)
	rel := r.URL.Query().Get("path")
	root, err := a.rootForUser(rootID, u)
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	full, err := safeResolve(root.Path, rel)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	type FileItem struct {
		Name    string `json:"name"`
		Path    string `json:"path"`
		IsDir   bool   `json:"is_dir"`
		Size    int64  `json:"size"`
		ModTime string `json:"mod_time"`
	}
	var items []FileItem
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, FileItem{
			Name:    e.Name(),
			Path:    cleanRel(path.Join(rel, e.Name())),
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	writeJSONResponse(w, map[string]interface{}{"items": items, "path": cleanRel(rel), "root": publicRoot(root, u)})
}

func (a *App) handleJobs(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		defer a.mu.Unlock()
		rows := []Job{}
		for _, j := range a.state.Jobs {
			if u.IsAdmin || j.UserID == u.ID {
				rows = append(rows, j)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
		jobs := make([]map[string]interface{}, 0, len(rows))
		for _, j := range rows {
			jobs = append(jobs, a.publicJobLocked(j, u))
		}
		writeJSONResponse(w, map[string]interface{}{"jobs": jobs})
	case http.MethodPost:
		var req struct {
			RootID int64  `json:"root_id"`
			Path   string `json:"path"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		root, err := a.rootForUser(req.RootID, u)
		if err != nil {
			jsonError(w, http.StatusForbidden, err.Error())
			return
		}
		full, err := safeResolve(root.Path, req.Path)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		info, err := os.Stat(full)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		sourceIsDir := info.IsDir()
		sourceSize := info.Size()
		if sourceIsDir {
			sourceSize, err = directorySize(full)
			if err != nil {
				jsonError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		a.mu.Lock()
		jobID := a.state.NextJobID
		a.state.NextJobID++
		targetDir := a.targetDirForUserLocked(u)
		rel := cleanRel(req.Path)
		remoteRel := rel
		if sourceIsDir {
			name := safeRemoteName(rel)
			if rel == "" {
				name = root.Name
			}
			remoteRel = name + ".tar.gz"
		}
		job := Job{
			ID:            jobID,
			UserID:        u.ID,
			RootID:        root.ID,
			SourceRelPath: rel,
			SourceAbsPath: full,
			SourceIsDir:   sourceIsDir,
			SourceSize:    sourceSize,
			SourceMtime:   info.ModTime().Format(time.RFC3339),
			Stage:         "Pending",
			TransferTotal: sourceSize,
			NASPath:       synoJoin(targetDir, safeRemoteName(root.Name+"_"+remoteRel)),
			CreatedAt:     now(),
		}
		a.state.Jobs = append(a.state.Jobs, job)
		a.appendJobEventLocked(job, "创建任务")
		a.auditLocked(u.ID, "create_job", fmt.Sprintf("%s -> %s", full, job.NASPath))
		_ = a.saveLocked()
		responseJob := a.publicJobLocked(job, u)
		a.mu.Unlock()
		log.Printf("[job] created id=%d user=%q root=%s rel=%s dir=%t size=%d nas=%s", job.ID, u.Username, root.Path, rel, sourceIsDir, sourceSize, job.NASPath)
		a.jobQueue <- jobID
		a.broadcast("job", job)
		writeJSONResponse(w, map[string]interface{}{"job": responseJob})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleJobAction(w http.ResponseWriter, r *http.Request, u User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		JobID  int64  `json:"job_id"`
		Action string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Action = strings.TrimSpace(req.Action)
	var updated Job
	deleted := false
	enqueue := false

	a.mu.Lock()
	idx := -1
	for i := range a.state.Jobs {
		if a.state.Jobs[i].ID == req.JobID {
			idx = i
			break
		}
	}
	if idx == -1 {
		a.mu.Unlock()
		jsonError(w, http.StatusNotFound, "job not found")
		return
	}
	job := a.state.Jobs[idx]
	if !u.IsAdmin && job.UserID != u.ID {
		a.mu.Unlock()
		jsonError(w, http.StatusForbidden, "job not allowed")
		return
	}
	switch req.Action {
	case "cancel":
		if job.Stage == "Pending" {
			job.Stage = "Canceled"
			job.Error = ""
			job.CompletedAt = now()
			a.state.Jobs[idx] = job
			updated = job
			a.auditLocked(u.ID, "cancel_job", fmt.Sprintf("job=%d", job.ID))
			break
		}
		if !isRunningJob(job.Stage) {
			a.mu.Unlock()
			jsonError(w, http.StatusConflict, "job is not running")
			return
		}
		job.Stage = "Canceling"
		job.Error = ""
		a.state.Jobs[idx] = job
		updated = job
		a.auditLocked(u.ID, "cancel_job", fmt.Sprintf("job=%d", job.ID))
		go a.cancelJob(job.ID)
	case "delete":
		if isRunningJob(job.Stage) {
			a.mu.Unlock()
			jsonError(w, http.StatusConflict, "running jobs cannot be deleted")
			return
		}
		a.state.Jobs = append(a.state.Jobs[:idx], a.state.Jobs[idx+1:]...)
		deleted = true
		a.auditLocked(u.ID, "delete_job", fmt.Sprintf("job=%d", job.ID))
	case "retry":
		if isRunningJob(job.Stage) {
			a.mu.Unlock()
			jsonError(w, http.StatusConflict, "running jobs cannot be retried")
			return
		}
		if _, err := os.Stat(job.SourceAbsPath); err != nil {
			a.mu.Unlock()
			jsonError(w, http.StatusBadRequest, "source file is no longer readable: "+err.Error())
			return
		}
		job.Stage = "Pending"
		job.TransferBytes = 0
		job.TransferSpeed = 0
		job.CloudBytes = 0
		job.CloudTotal = 0
		job.CloudSpeed = 0
		job.StagingPath = ""
		job.Error = ""
		job.StartedAt = ""
		job.CompletedAt = ""
		job.CloudUpdatedAt = ""
		job.NotifiedEvents = nil
		a.state.Jobs[idx] = job
		updated = job
		enqueue = true
		a.auditLocked(u.ID, "retry_job", fmt.Sprintf("job=%d", job.ID))
	case "refresh_cloud":
		if isRunningJob(job.Stage) {
			a.mu.Unlock()
			jsonError(w, http.StatusConflict, "running jobs cannot refresh cloud state")
			return
		}
		job.Stage = "NASCompleted"
		job.CloudSpeed = 0
		job.Error = ""
		job.CloudUpdatedAt = now()
		a.state.Jobs[idx] = job
		updated = job
		a.auditLocked(u.ID, "refresh_cloud_job", fmt.Sprintf("job=%d", job.ID))
	case "mark_cloud_completed":
		if !u.IsAdmin {
			a.mu.Unlock()
			jsonError(w, http.StatusForbidden, "admin required")
			return
		}
		job.Stage = "CloudCompleted"
		job.CloudBytes = job.SourceSize
		if job.CloudTotal == 0 {
			job.CloudTotal = job.SourceSize
		}
		job.CloudSpeed = 0
		job.Error = ""
		job.CloudUpdatedAt = now()
		a.state.Jobs[idx] = job
		updated = job
		a.auditLocked(u.ID, "mark_cloud_completed", fmt.Sprintf("job=%d", job.ID))
	default:
		a.mu.Unlock()
		jsonError(w, http.StatusBadRequest, "unknown action")
		return
	}
	if updated.ID != 0 {
		a.appendJobEventLocked(updated, jobActionMessage(req.Action))
	}
	_ = a.saveLocked()
	responseJob := a.publicJobLocked(updated, u)
	a.mu.Unlock()

	if enqueue {
		a.jobQueue <- req.JobID
	}
	if deleted {
		a.broadcast("job_deleted", map[string]int64{"id": req.JobID})
		writeJSONResponse(w, map[string]interface{}{"success": true, "deleted": req.JobID})
		return
	}
	if req.Action == "mark_cloud_completed" && updated.Stage == "CloudCompleted" {
		go a.notifyJobMail(updated.ID, mailEventJobCloudDone)
	}
	a.broadcast("job", updated)
	writeJSONResponse(w, map[string]interface{}{"success": true, "job": responseJob})
}

func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		defer a.mu.Unlock()
		var users []map[string]interface{}
		for _, u := range a.state.Users {
			users = append(users, publicUser(u))
		}
		writeJSONResponse(w, map[string]interface{}{"users": users})
	case http.MethodPost:
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			IsAdmin   bool   `json:"is_admin"`
			UploadDir string `json:"upload_dir"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		req.UploadDir = normalizeUserUploadDir(req.UploadDir)
		if req.Username == "" || len(req.Password) < 8 {
			jsonError(w, http.StatusBadRequest, "username is required and password must be at least 8 characters")
			return
		}
		if req.UploadDir == "/" {
			jsonError(w, http.StatusBadRequest, "upload folder cannot be root")
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, u := range a.state.Users {
			if u.Username == req.Username {
				jsonError(w, http.StatusConflict, "username exists")
				return
			}
		}
		salt, hash := hashPassword(req.Password)
		u := User{ID: a.state.NextUserID, Username: req.Username, Salt: salt, PasswordHash: hash, IsAdmin: req.IsAdmin, UploadDir: req.UploadDir, CreatedAt: now()}
		a.state.NextUserID++
		a.state.Users = append(a.state.Users, u)
		a.auditLocked(admin.ID, "create_user", req.Username)
		_ = a.saveLocked()
		writeJSONResponse(w, map[string]interface{}{"user": publicUser(u)})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminUserPassword(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		UserID      int64  `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Users {
		if a.state.Users[i].ID == req.UserID {
			salt, hash := hashPassword(req.NewPassword)
			a.state.Users[i].Salt = salt
			a.state.Users[i].PasswordHash = hash
			a.auditLocked(admin.ID, "reset_user_password", fmt.Sprintf("user=%d", req.UserID))
			_ = a.saveLocked()
			writeJSONResponse(w, map[string]interface{}{"success": true, "user": publicUser(a.state.Users[i])})
			return
		}
	}
	jsonError(w, http.StatusNotFound, "user not found")
}

func (a *App) handleAdminUserDelete(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		UserID int64 `json:"user_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.UserID == admin.ID {
		jsonError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := -1
	for i := range a.state.Users {
		if a.state.Users[i].ID == req.UserID {
			idx = i
			break
		}
	}
	if idx == -1 {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}
	if a.state.Users[idx].IsAdmin && a.adminCountLocked() <= 1 {
		jsonError(w, http.StatusBadRequest, "cannot delete the last admin")
		return
	}
	a.state.Users = append(a.state.Users[:idx], a.state.Users[idx+1:]...)
	for token, uid := range a.sessions {
		if uid == req.UserID {
			delete(a.sessions, token)
		}
	}
	a.auditLocked(admin.ID, "delete_user", fmt.Sprintf("user=%d", req.UserID))
	_ = a.saveLocked()
	writeJSONResponse(w, map[string]interface{}{"success": true})
}

func (a *App) handleAdminUserRoots(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		UserID  int64   `json:"user_id"`
		RootIDs []int64 `json:"root_ids"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Users {
		if a.state.Users[i].ID == req.UserID {
			a.state.Users[i].AllowedRoots = uniqueIDs(req.RootIDs)
			a.auditLocked(admin.ID, "update_user_roots", fmt.Sprintf("user=%d roots=%v", req.UserID, req.RootIDs))
			_ = a.saveLocked()
			writeJSONResponse(w, map[string]interface{}{"user": publicUser(a.state.Users[i])})
			return
		}
	}
	jsonError(w, http.StatusNotFound, "user not found")
}

func (a *App) handleAdminUserUploadDir(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		UserID    int64  `json:"user_id"`
		UploadDir string `json:"upload_dir"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.UploadDir = normalizeUserUploadDir(req.UploadDir)
	if req.UploadDir == "/" {
		jsonError(w, http.StatusBadRequest, "upload folder cannot be root")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Users {
		if a.state.Users[i].ID == req.UserID {
			a.state.Users[i].UploadDir = req.UploadDir
			a.auditLocked(admin.ID, "update_user_upload_dir", fmt.Sprintf("user=%d dir=%s", req.UserID, req.UploadDir))
			_ = a.saveLocked()
			writeJSONResponse(w, map[string]interface{}{"success": true, "user": publicUser(a.state.Users[i])})
			return
		}
	}
	jsonError(w, http.StatusNotFound, "user not found")
}

func (a *App) handleAdminRoots(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		defer a.mu.Unlock()
		writeJSONResponse(w, map[string]interface{}{"roots": a.state.Roots})
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.Path = strings.TrimSpace(req.Path)
		if req.Name == "" || req.Path == "" {
			jsonError(w, http.StatusBadRequest, "name and path are required")
			return
		}
		real, err := filepath.EvalSymlinks(req.Path)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		info, err := os.Stat(real)
		if err != nil || !info.IsDir() {
			jsonError(w, http.StatusBadRequest, "path must be a readable directory")
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		root := Root{ID: a.state.NextRootID, Name: req.Name, Path: real, CreatedAt: now()}
		a.state.NextRootID++
		a.state.Roots = append(a.state.Roots, root)
		a.auditLocked(admin.ID, "create_root", real)
		_ = a.saveLocked()
		writeJSONResponse(w, map[string]interface{}{"root": root})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminRootDelete(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		RootID int64 `json:"root_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := -1
	for i := range a.state.Roots {
		if a.state.Roots[i].ID == req.RootID {
			idx = i
			break
		}
	}
	if idx == -1 {
		jsonError(w, http.StatusNotFound, "root not found")
		return
	}
	for _, job := range a.state.Jobs {
		if job.RootID == req.RootID && isRunningJob(job.Stage) {
			jsonError(w, http.StatusConflict, "root has a running job")
			return
		}
	}
	rootPath := a.state.Roots[idx].Path
	a.state.Roots = append(a.state.Roots[:idx], a.state.Roots[idx+1:]...)
	for i := range a.state.Users {
		a.state.Users[i].AllowedRoots = removeID(a.state.Users[i].AllowedRoots, req.RootID)
	}
	a.auditLocked(admin.ID, "delete_root", fmt.Sprintf("root=%d path=%s", req.RootID, rootPath))
	_ = a.saveLocked()
	writeJSONResponse(w, map[string]interface{}{"success": true})
}

func (a *App) handleAdminSite(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		writeJSONResponse(w, map[string]interface{}{"config": a.publicConfig()})
	case http.MethodPost:
		var req struct {
			ListenAddr    string `json:"listen_addr"`
			PublicBaseURL string `json:"public_base_url"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		listen, port, err := normalizeListenAddr(req.ListenAddr)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.mu.Lock()
		currentListen := a.config.ListenAddr
		currentPublicURL := a.config.PublicBaseURL
		a.mu.Unlock()
		oldPort := listenPort(currentListen)
		publicURL := strings.TrimSpace(req.PublicBaseURL)
		if publicURL == "" {
			publicURL = publicURLWithPort(currentPublicURL, port)
		} else if port != oldPort {
			publicURL = rewritePublicURLPort(publicURL, oldPort, port)
		}
		publicURL, err = normalizePublicBaseURL(publicURL)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.mu.Lock()
		oldListen := a.config.ListenAddr
		a.config.ListenAddr = listen
		a.config.PublicBaseURL = publicURL
		configErr := a.saveConfigLocked()
		if configErr == nil {
			a.auditWithIPLocked(admin.ID, "update_site_config", fmt.Sprintf("listen=%s public_url=%s", listen, publicURL), clientIP(r))
			configErr = a.saveLocked()
		}
		config := a.publicConfigLocked()
		a.mu.Unlock()
		if configErr != nil {
			jsonError(w, http.StatusInternalServerError, configErr.Error())
			return
		}
		restartRequired := oldListen != listen
		log.Printf("[config] site config updated by=%q listen=%s public_url=%s restart_required=%t", admin.Username, listen, publicURL, restartRequired)
		writeJSONResponse(w, map[string]interface{}{"success": true, "config": config, "restart_required": restartRequired})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminSynology(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		client := a.synology()
		info, err := client.APIInfo()
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		shares, _ := client.ListShares()
		conn, _ := client.CloudListConn()
		writeJSONResponse(w, map[string]interface{}{"config": a.publicConfig(), "api_info": info, "shares": shares, "cloud": conn})
	case http.MethodPost:
		var req struct {
			SynologyBaseURL        string `json:"synology_base_url"`
			SynologyUsername       string `json:"synology_username"`
			SynologyPassword       string `json:"synology_password"`
			SynologyStagingDir     string `json:"synology_staging_dir"`
			SynologyCloudTargetDir string `json:"synology_cloud_target_dir"`
			VerifyTLS              bool   `json:"verify_tls"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		next := a.config
		next.SynologyBaseURL = strings.TrimSpace(req.SynologyBaseURL)
		next.SynologyUsername = strings.TrimSpace(req.SynologyUsername)
		if req.SynologyPassword != "" {
			next.SynologyPassword = req.SynologyPassword
		}
		next.SynologyStagingDir = synoClean(req.SynologyStagingDir)
		next.SynologyCloudTargetDir = synoClean(req.SynologyCloudTargetDir)
		next.VerifyTLS = req.VerifyTLS
		if next.SynologyBaseURL == "" || next.SynologyUsername == "" || next.SynologyPassword == "" || next.SynologyStagingDir == "/" || next.SynologyCloudTargetDir == "/" {
			jsonError(w, http.StatusBadRequest, "synology url, username, password and upload folders are required")
			return
		}
		a.mu.Lock()
		a.config = next
		a.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !next.VerifyTLS}, Proxy: http.ProxyFromEnvironment}}
		a.auditLocked(admin.ID, "update_synology_config", next.SynologyBaseURL)
		err := a.saveConfigLocked()
		a.mu.Unlock()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("[config] synology config updated by=%q base_url_set=%t username_set=%t staging=%s target=%s verify_tls=%t", admin.Username, next.SynologyBaseURL != "", next.SynologyUsername != "", next.SynologyStagingDir, next.SynologyCloudTargetDir, next.VerifyTLS)
		writeJSONResponse(w, map[string]interface{}{"config": a.publicConfig()})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminMail(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		config := a.mailConfigLocked()
		a.mu.Unlock()
		writeJSONResponse(w, map[string]interface{}{"config": config})
	case http.MethodPost:
		var req struct {
			SMTPEnabled           bool   `json:"smtp_enabled"`
			SMTPHost              string `json:"smtp_host"`
			SMTPPort              int    `json:"smtp_port"`
			SMTPSecure            string `json:"smtp_secure"`
			SMTPUsername          string `json:"smtp_username"`
			SMTPPassword          string `json:"smtp_password"`
			SMTPFromEmail         string `json:"smtp_from_email"`
			SMTPFromName          string `json:"smtp_from_name"`
			MailEventJobNASDone   bool   `json:"mail_event_job_nas_done"`
			MailEventJobCloudDone bool   `json:"mail_event_job_cloud_done"`
			MailEventJobFailed    bool   `json:"mail_event_job_failed"`
			MailEventLoginBan     bool   `json:"mail_event_login_ban"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.mu.Lock()
		next := a.config
		a.mu.Unlock()
		next.SMTPEnabled = req.SMTPEnabled
		next.SMTPHost = strings.TrimSpace(req.SMTPHost)
		next.SMTPPort = req.SMTPPort
		next.SMTPSecure = normalizeSMTPSecure(req.SMTPSecure)
		next.SMTPUsername = strings.TrimSpace(req.SMTPUsername)
		if req.SMTPPassword != "" {
			next.SMTPPassword = req.SMTPPassword
		} else if next.SMTPUsername == "" {
			next.SMTPPassword = ""
		}
		next.SMTPFromEmail = strings.TrimSpace(req.SMTPFromEmail)
		next.SMTPFromName = strings.TrimSpace(req.SMTPFromName)
		next.MailEventJobNASDone = req.MailEventJobNASDone
		next.MailEventJobCloudDone = req.MailEventJobCloudDone
		next.MailEventJobFailed = req.MailEventJobFailed
		next.MailEventLoginBan = req.MailEventLoginBan
		normalizeConfig(&next)
		if next.SMTPEnabled {
			if next.SMTPHost == "" {
				jsonError(w, http.StatusBadRequest, "smtp server is required")
				return
			}
			if next.SMTPPort <= 0 || next.SMTPPort > 65535 {
				jsonError(w, http.StatusBadRequest, "smtp port must be between 1 and 65535")
				return
			}
			if next.SMTPFromEmail == "" {
				next.SMTPFromEmail = next.SMTPUsername
			}
			if _, err := mail.ParseAddress(next.SMTPFromEmail); err != nil {
				jsonError(w, http.StatusBadRequest, "sender email is invalid")
				return
			}
		}
		a.mu.Lock()
		a.config = next
		configErr := a.saveConfigLocked()
		if configErr == nil {
			a.auditWithIPLocked(admin.ID, "update_mail_config", fmt.Sprintf("enabled=%t host=%s port=%d secure=%s events=%t/%t/%t/%t", next.SMTPEnabled, next.SMTPHost, next.SMTPPort, next.SMTPSecure, next.MailEventJobNASDone, next.MailEventJobCloudDone, next.MailEventJobFailed, next.MailEventLoginBan), clientIP(r))
			configErr = a.saveLocked()
		}
		config := a.mailConfigLocked()
		a.mu.Unlock()
		if configErr != nil {
			jsonError(w, http.StatusInternalServerError, configErr.Error())
			return
		}
		log.Printf("[mail] smtp config updated by=%q enabled=%t host=%s port=%d secure=%s username_set=%t from=%s", admin.Username, next.SMTPEnabled, next.SMTPHost, next.SMTPPort, next.SMTPSecure, next.SMTPUsername != "", next.SMTPFromEmail)
		writeJSONResponse(w, map[string]interface{}{"success": true, "config": config})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminMailTest(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		TestTo string `json:"test_to"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var recipients []string
	if strings.TrimSpace(req.TestTo) != "" {
		var err error
		recipients, err = validateEmailList([]string{req.TestTo})
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		a.mu.Lock()
		for _, u := range a.state.Users {
			if u.ID == admin.ID {
				recipients = append(recipients, u.Emails...)
				break
			}
		}
		a.mu.Unlock()
		recipients = normalizeEmailList(recipients)
	}
	if len(recipients) == 0 {
		jsonError(w, http.StatusBadRequest, "test recipient email is required")
		return
	}
	if err := a.sendMail(recipients, appName+" 测试邮件", "这是一封来自 PVE Backup Web 的测试邮件。如果你能看到它，说明 SMTP 配置已经可以正常发送。"); err != nil {
		log.Printf("[mail] test email failed by=%q to=%d error=%v", admin.Username, len(recipients), err)
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.mu.Lock()
	a.auditWithIPLocked(admin.ID, "send_test_mail", fmt.Sprintf("to=%d", len(recipients)), clientIP(r))
	_ = a.saveLocked()
	a.mu.Unlock()
	log.Printf("[mail] test email sent by=%q to=%d", admin.Username, len(recipients))
	writeJSONResponse(w, map[string]interface{}{"success": true, "sent": len(recipients)})
}

func (a *App) handleAdminAnnouncement(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		announcement := a.state.Announcement
		a.mu.Unlock()
		writeJSONResponse(w, map[string]interface{}{"announcement": announcement})
	case http.MethodPost:
		var req struct {
			Content string `json:"content"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		content := strings.TrimSpace(req.Content)
		if len(content) > 5000 {
			jsonError(w, http.StatusBadRequest, "announcement is too long")
			return
		}
		a.mu.Lock()
		a.state.Announcement = Announcement{Content: content, UpdatedAt: now(), UpdatedBy: admin.ID}
		a.auditLocked(admin.ID, "update_announcement", fmt.Sprintf("length=%d", len(content)))
		_ = a.saveLocked()
		announcement := a.state.Announcement
		a.mu.Unlock()
		writeJSONResponse(w, map[string]interface{}{"success": true, "announcement": announcement})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminLogs(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), 200, 1000)
	a.mu.Lock()
	usernames := make(map[int64]string, len(a.state.Users))
	for _, u := range a.state.Users {
		usernames[u.ID] = u.Username
	}
	jobs := append([]Job(nil), a.state.Jobs...)
	audit := append([]AuditLog(nil), a.state.Audit...)
	events := append([]JobEvent(nil), a.state.JobEvents...)
	a.mu.Unlock()

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID > jobs[j].ID })
	if len(jobs) > limit {
		jobs = jobs[:limit]
	}
	jobRows := make([]map[string]interface{}, 0, len(jobs))
	for _, j := range jobs {
		jobRows = append(jobRows, map[string]interface{}{
			"id":               j.ID,
			"user_id":          j.UserID,
			"username":         usernameForID(usernames, j.UserID),
			"root_id":          j.RootID,
			"source_rel_path":  j.SourceRelPath,
			"source_abs_path":  j.SourceAbsPath,
			"source_is_dir":    j.SourceIsDir,
			"source_size":      j.SourceSize,
			"stage":            j.Stage,
			"transfer_bytes":   j.TransferBytes,
			"transfer_total":   j.TransferTotal,
			"transfer_speed":   j.TransferSpeed,
			"cloud_bytes":      j.CloudBytes,
			"cloud_total":      j.CloudTotal,
			"cloud_speed":      j.CloudSpeed,
			"nas_path":         j.NASPath,
			"error":            j.Error,
			"created_at":       j.CreatedAt,
			"started_at":       j.StartedAt,
			"completed_at":     j.CompletedAt,
			"cloud_updated_at": j.CloudUpdatedAt,
		})
	}

	if len(audit) > limit {
		audit = audit[len(audit)-limit:]
	}
	auditRows := make([]map[string]interface{}, 0, len(audit))
	for i := len(audit) - 1; i >= 0; i-- {
		l := audit[i]
		auditRows = append(auditRows, map[string]interface{}{
			"time":     l.Time,
			"user_id":  l.UserID,
			"username": usernameForID(usernames, l.UserID),
			"action":   l.Action,
			"details":  l.Details,
			"ip":       l.IP,
		})
	}

	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	eventRows := make([]map[string]interface{}, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		eventRows = append(eventRows, map[string]interface{}{
			"time":           ev.Time,
			"job_id":         ev.JobID,
			"user_id":        ev.UserID,
			"username":       usernameForID(usernames, ev.UserID),
			"stage":          ev.Stage,
			"transfer_bytes": ev.TransferBytes,
			"transfer_total": ev.TransferTotal,
			"cloud_bytes":    ev.CloudBytes,
			"cloud_total":    ev.CloudTotal,
			"message":        ev.Message,
		})
	}

	writeJSONResponse(w, map[string]interface{}{"jobs": jobRows, "audit": auditRows, "job_events": eventRows})
}

func (a *App) handleAdminClearLogs(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.mu.Lock()
	a.state.Audit = nil
	a.state.JobEvents = nil
	a.auditWithIPLocked(admin.ID, "clear_logs", "cleared audit and job progress logs", clientIP(r))
	_ = a.saveLocked()
	a.mu.Unlock()
	log.Printf("[admin] logs cleared by=%q ip=%s", admin.Username, clientIP(r))
	writeJSONResponse(w, map[string]interface{}{"success": true})
}

func (a *App) handleAdminCertificate(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		status, err := a.certificateStatus()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResponse(w, map[string]interface{}{"certificate": status})
	case http.MethodPost:
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		certPEM, err := multipartValue(r, "cert_file", "cert_pem")
		if err != nil {
			jsonError(w, http.StatusBadRequest, "certificate file is required")
			return
		}
		keyPEM, err := multipartValue(r, "key_file", "key_pem")
		if err != nil {
			jsonError(w, http.StatusBadRequest, "private key file is required")
			return
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "certificate and private key do not match: "+err.Error())
			return
		}
		if len(cert.Certificate) == 0 {
			jsonError(w, http.StatusBadRequest, "certificate is empty")
			return
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			jsonError(w, http.StatusBadRequest, "cannot parse certificate: "+err.Error())
			return
		}
		cert.Leaf = leaf
		if time.Now().After(leaf.NotAfter) {
			jsonError(w, http.StatusBadRequest, "certificate has expired")
			return
		}
		a.mu.Lock()
		if err := a.writeSecureStringLocked("https_cert_pem", string(certPEM)); err != nil {
			a.mu.Unlock()
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.writeSecureStringLocked("https_key_pem", string(keyPEM)); err != nil {
			a.mu.Unlock()
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.tlsCert = cert
		a.auditWithIPLocked(admin.ID, "update_https_certificate", leaf.Subject.CommonName, clientIP(r))
		_ = a.saveLocked()
		a.mu.Unlock()
		log.Printf("[tls] certificate updated by=%q cn=%q not_after=%s", admin.Username, leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339))
		status, _ := a.certificateStatus()
		writeJSONResponse(w, map[string]interface{}{"success": true, "certificate": status})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminSecurity(w http.ResponseWriter, r *http.Request, admin User) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		config := a.securityConfigLocked()
		bans := a.activeLoginBansLocked()
		a.mu.Unlock()
		writeJSONResponse(w, map[string]interface{}{"config": config, "bans": bans})
	case http.MethodPost:
		var req struct {
			CaptchaAfterFailures int  `json:"captcha_after_failures"`
			MaxLoginFailures     int  `json:"max_login_failures"`
			BanDurationMinutes   int  `json:"ban_duration_minutes"`
			PermanentBan         bool `json:"permanent_ban"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.CaptchaAfterFailures < 1 || req.CaptchaAfterFailures > 20 {
			jsonError(w, http.StatusBadRequest, "captcha threshold must be between 1 and 20")
			return
		}
		if req.MaxLoginFailures <= req.CaptchaAfterFailures || req.MaxLoginFailures > 100 {
			jsonError(w, http.StatusBadRequest, "ban threshold must be greater than captcha threshold and no more than 100")
			return
		}
		if req.BanDurationMinutes < 0 || req.BanDurationMinutes > 525600 {
			jsonError(w, http.StatusBadRequest, "ban duration must be between 0 and 525600 minutes")
			return
		}
		a.mu.Lock()
		a.config.CaptchaAfterFailures = req.CaptchaAfterFailures
		a.config.MaxLoginFailures = req.MaxLoginFailures
		a.config.BanDurationMinutes = req.BanDurationMinutes
		a.config.PermanentBan = req.PermanentBan
		normalizeConfig(&a.config)
		configErr := a.saveConfigLocked()
		if configErr == nil {
			a.auditWithIPLocked(admin.ID, "update_login_security", fmt.Sprintf("captcha=%d max_failures=%d permanent=%t duration=%d", a.config.CaptchaAfterFailures, a.config.MaxLoginFailures, a.config.PermanentBan, a.config.BanDurationMinutes), clientIP(r))
			configErr = a.saveLocked()
		}
		config := a.securityConfigLocked()
		bans := a.activeLoginBansLocked()
		a.mu.Unlock()
		if configErr != nil {
			jsonError(w, http.StatusInternalServerError, configErr.Error())
			return
		}
		log.Printf("[security] login security updated by=%q captcha_after=%d max_failures=%d permanent=%t duration_minutes=%d", admin.Username, req.CaptchaAfterFailures, req.MaxLoginFailures, req.PermanentBan, req.BanDurationMinutes)
		writeJSONResponse(w, map[string]interface{}{"success": true, "config": config, "bans": bans})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAdminUnban(w http.ResponseWriter, r *http.Request, admin User) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		BanID int64 `json:"ban_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.LoginBans {
		if a.state.LoginBans[i].ID == req.BanID {
			a.state.LoginBans = append(a.state.LoginBans[:i], a.state.LoginBans[i+1:]...)
			a.auditWithIPLocked(admin.ID, "remove_login_ban", fmt.Sprintf("ban=%d", req.BanID), clientIP(r))
			_ = a.saveLocked()
			log.Printf("[security] login ban removed by=%q ban_id=%d ip=%s", admin.Username, req.BanID, clientIP(r))
			writeJSONResponse(w, map[string]interface{}{"success": true, "bans": a.activeLoginBansLocked()})
			return
		}
	}
	jsonError(w, http.StatusNotFound, "ban not found")
}

func (a *App) rootForUser(rootID int64, u User) (Root, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, root := range a.state.Roots {
		if root.ID == rootID {
			if u.IsAdmin || containsID(u.AllowedRoots, root.ID) {
				return root, nil
			}
			return Root{}, errors.New("root not allowed")
		}
	}
	return Root{}, errors.New("root not found")
}

func (a *App) worker() {
	for id := range a.jobQueue {
		log.Printf("[job] dequeued id=%d", id)
		if err := a.runJob(id); err != nil {
			if errors.Is(err, errJobCanceled) {
				log.Printf("[job] canceled id=%d", id)
				a.updateJob(id, func(j *Job) {
					j.Stage = "Canceled"
					j.TransferSpeed = 0
					j.CloudSpeed = 0
					j.Error = ""
					j.CompletedAt = now()
				})
			} else {
				log.Printf("[job] failed id=%d error=%v", id, err)
				a.updateJob(id, func(j *Job) {
					j.Stage = "Failed"
					j.Error = err.Error()
					j.TransferSpeed = 0
					j.CompletedAt = now()
				})
			}
		}
	}
}

func (a *App) runJob(id int64) error {
	job, ok := a.getJob(id)
	if !ok {
		log.Printf("[job] skip missing id=%d", id)
		return nil
	}
	if job.Stage == "Canceled" || job.Stage == "Canceling" {
		log.Printf("[job] skip canceled id=%d stage=%s", id, job.Stage)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.setJobCancel(id, cancel)
	defer a.clearJobCancel(id)
	defer cancel()
	if job.Stage == "Pending" {
		log.Printf("[job] start id=%d user_id=%d source=%s dir=%t size=%d nas=%s", job.ID, job.UserID, job.SourceAbsPath, job.SourceIsDir, job.SourceSize, job.NASPath)
		a.updateJob(id, func(j *Job) {
			if j.SourceIsDir {
				j.Stage = "Packaging"
			} else {
				j.Stage = "CopyingToNAS"
			}
			j.StartedAt = now()
			j.Error = ""
		})
		uploadPath := job.SourceAbsPath
		cleanup := func() {}
		if job.SourceIsDir {
			log.Printf("[job] packaging directory id=%d source=%s", job.ID, job.SourceAbsPath)
			archivePath, archiveSize, archiveCleanup, err := a.packageDirectory(ctx, job, func(done int64) {
				a.updateJob(id, func(j *Job) {
					j.TransferBytes = done
					j.TransferTotal = j.SourceSize
				})
			})
			if err != nil {
				return err
			}
			uploadPath = archivePath
			cleanup = archiveCleanup
			defer cleanup()
			log.Printf("[job] packaged directory id=%d archive=%s archive_size=%d", job.ID, archivePath, archiveSize)
			a.updateJob(id, func(j *Job) {
				j.Stage = "CopyingToNAS"
				j.TransferBytes = 0
				j.TransferTotal = archiveSize
				j.TransferSpeed = 0
			})
		} else {
			a.updateJob(id, func(j *Job) {
				j.TransferTotal = j.SourceSize
			})
		}
		client := a.synology()
		stagingDir := a.config.SynologyStagingDir
		targetDir := path.Dir(job.NASPath)
		log.Printf("[job] prepare nas folders id=%d staging=%s target=%s", id, stagingDir, targetDir)
		if err := checkCanceled(ctx); err != nil {
			return err
		}
		if err := client.EnsureFolder(stagingDir); err != nil {
			return fmt.Errorf("create staging folder: %w", err)
		}
		if err := client.EnsureFolder(targetDir); err != nil {
			return fmt.Errorf("create cloud target folder: %w", err)
		}
		job, _ = a.getJob(id)
		remoteName := filepath.Base(job.NASPath)
		jobStagingDir := synoJoin(stagingDir, fmt.Sprintf("job-%d", id))
		stagingPath := synoJoin(jobStagingDir, remoteName)
		a.updateJob(id, func(j *Job) { j.StagingPath = stagingPath })
		log.Printf("[job] upload start id=%d local=%s remote_dir=%s remote_name=%s", id, uploadPath, jobStagingDir, remoteName)
		if err := client.UploadFile(ctx, uploadPath, jobStagingDir, remoteName, func(sent, total, speed int64) {
			a.updateJob(id, func(j *Job) {
				j.TransferBytes = sent
				j.TransferTotal = total
				j.TransferSpeed = speed
			})
		}); err != nil {
			return fmt.Errorf("upload to synology: %w", err)
		}
		log.Printf("[job] upload complete id=%d staging_path=%s", id, stagingPath)
		a.updateJob(id, func(j *Job) {
			j.Stage = "MovingToCloudDir"
			if j.TransferTotal > 0 {
				j.TransferBytes = j.TransferTotal
			}
			j.TransferSpeed = 0
		})
		if err := checkCanceled(ctx); err != nil {
			return err
		}
		if err := client.Move(stagingPath, targetDir, ""); err != nil {
			return fmt.Errorf("move into cloud sync folder: %w", err)
		}
		log.Printf("[job] moved into cloud sync folder id=%d target=%s", id, targetDir)
		a.updateJob(id, func(j *Job) {
			j.Stage = "NASCompleted"
			j.StagingPath = ""
			j.CompletedAt = now()
		})
	}
	return nil
}

func (a *App) cloudMonitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.pollCloud()
		}
	}
}

func (a *App) pollCloud() {
	a.mu.Lock()
	var targets []Job
	for _, j := range a.state.Jobs {
		if j.Stage == "NASCompleted" || j.Stage == "WaitingCloudSync" || j.Stage == "CloudSyncUploading" {
			targets = append(targets, j)
		}
	}
	a.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	client := a.synology()
	recent, err := client.CloudRecentlyChanged()
	if err != nil {
		log.Printf("[cloud] monitor unavailable targets=%d error=%v", len(targets), err)
		for _, j := range targets {
			a.updateJob(j.ID, func(job *Job) {
				if job.Stage == "NASCompleted" {
					job.Stage = "CloudStatusUnknown"
				}
				job.Error = "Cloud Sync monitor unavailable: " + err.Error()
			})
		}
		return
	}
	logs, _ := client.CloudLogs()
	for _, target := range targets {
		found := false
		for _, item := range recent.Data.ProcessingItems {
			if sameSynoPath(item.Path, target.NASPath) || item.BaseName == filepath.Base(target.NASPath) {
				found = true
				a.updateJob(target.ID, func(j *Job) {
					j.Stage = "CloudSyncUploading"
					j.CloudBytes = item.CurrentSize
					j.CloudTotal = item.TotalSize
					j.CloudSpeed = item.BitRate
					j.CloudUpdatedAt = now()
					j.Error = ""
				})
				break
			}
		}
		if found {
			continue
		}
		done := false
		failed := false
		for _, li := range logs.Data.Items {
			if sameSynoPath(li.Path, target.NASPath) || li.FileName == filepath.Base(target.NASPath) {
				if li.LogLevel == 0 && li.ErrorCode == 0 && li.Action == 2 {
					done = true
				} else if li.LogLevel > 0 || li.ErrorCode != 0 {
					failed = true
				}
				break
			}
		}
		if done {
			a.updateJob(target.ID, func(j *Job) {
				j.Stage = "CloudCompleted"
				j.CloudBytes = j.SourceSize
				if j.CloudTotal == 0 {
					j.CloudTotal = j.SourceSize
				}
				j.CloudSpeed = 0
				j.CloudUpdatedAt = now()
				j.Error = ""
			})
		} else if failed {
			a.updateJob(target.ID, func(j *Job) {
				j.Stage = "CloudFailed"
				j.CloudSpeed = 0
				j.CloudUpdatedAt = now()
				j.Error = "Cloud Sync reported an error for this file"
			})
		} else if target.Stage == "NASCompleted" {
			a.updateJob(target.ID, func(j *Job) {
				j.Stage = "WaitingCloudSync"
				j.CloudUpdatedAt = now()
			})
		}
	}
}

func (a *App) getJob(id int64) (Job, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, j := range a.state.Jobs {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

func (a *App) updateJob(id int64, fn func(*Job)) {
	a.mu.Lock()
	var before, updated Job
	for i := range a.state.Jobs {
		if a.state.Jobs[i].ID == id {
			before = a.state.Jobs[i]
			fn(&a.state.Jobs[i])
			updated = a.state.Jobs[i]
			if shouldLogJobEvent(before, updated) {
				a.appendJobEventLocked(updated, jobEventMessage(before, updated))
			}
			break
		}
	}
	_ = a.saveLocked()
	a.mu.Unlock()
	if updated.ID != 0 {
		if before.Stage != updated.Stage {
			log.Printf("[job] stage changed id=%d %s -> %s", updated.ID, before.Stage, updated.Stage)
			switch updated.Stage {
			case "NASCompleted":
				go a.notifyJobMail(updated.ID, mailEventJobNASDone)
			case "CloudCompleted":
				go a.notifyJobMail(updated.ID, mailEventJobCloudDone)
			case "Failed":
				go a.notifyJobMail(updated.ID, mailEventJobFailed)
			}
		}
		if before.Error != updated.Error && updated.Error != "" {
			log.Printf("[job] error updated id=%d stage=%s error=%s", updated.ID, updated.Stage, updated.Error)
		}
		a.broadcast("job", updated)
	}
}

func (a *App) setJobCancel(id int64, cancel context.CancelFunc) {
	a.mu.Lock()
	a.jobCancels[id] = cancel
	a.mu.Unlock()
}

func (a *App) clearJobCancel(id int64) {
	a.mu.Lock()
	delete(a.jobCancels, id)
	a.mu.Unlock()
}

func (a *App) cancelJob(id int64) bool {
	a.mu.Lock()
	cancel := a.jobCancels[id]
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

func (a *App) broadcast(t string, data interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ch := range a.events {
		select {
		case ch <- Event{Type: t, Data: data}:
		default:
		}
	}
}

func (a *App) eventDataForUser(ev Event, viewer User) (interface{}, bool) {
	if ev.Type != "job" {
		return ev.Data, true
	}
	job, ok := ev.Data.(Job)
	if !ok {
		return ev.Data, true
	}
	if !viewer.IsAdmin && job.UserID != viewer.ID {
		return nil, false
	}
	a.mu.Lock()
	data := a.publicJobLocked(job, viewer)
	a.mu.Unlock()
	return data, true
}

func (a *App) packageDirectory(ctx context.Context, job Job, progress func(done int64)) (string, int64, func(), error) {
	workDir := filepath.Join(workRootPath, fmt.Sprintf("job-%d", job.ID))
	if err := os.RemoveAll(workDir); err != nil {
		return "", 0, func() {}, err
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return "", 0, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(workDir) }
	base := safeRemoteName(filepath.Base(job.SourceAbsPath))
	if base == "" || base == "." {
		base = fmt.Sprintf("job-%d", job.ID)
	}
	archivePath := filepath.Join(workDir, base+".tar.gz")
	out, err := os.Create(archivePath)
	if err != nil {
		cleanup()
		return "", 0, func() {}, err
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	parent := filepath.Dir(job.SourceAbsPath)
	var done int64
	copyBuf := make([]byte, 1024*1024)
	walkErr := filepath.WalkDir(job.SourceAbsPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := checkCanceled(ctx); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(parent, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		for {
			if err := checkCanceled(ctx); err != nil {
				_ = in.Close()
				return err
			}
			n, readErr := in.Read(copyBuf)
			if n > 0 {
				if _, err := tw.Write(copyBuf[:n]); err != nil {
					_ = in.Close()
					return err
				}
				done += int64(n)
				progress(done)
			}
			if errors.Is(readErr, io.EOF) {
				if err := in.Close(); err != nil {
					return err
				}
				return nil
			}
			if readErr != nil {
				_ = in.Close()
				return readErr
			}
		}
	})
	closeErr := tw.Close()
	gzErr := gz.Close()
	fileErr := out.Close()
	if walkErr != nil {
		cleanup()
		return "", 0, func() {}, walkErr
	}
	if closeErr != nil {
		cleanup()
		return "", 0, func() {}, closeErr
	}
	if gzErr != nil {
		cleanup()
		return "", 0, func() {}, gzErr
	}
	if fileErr != nil {
		cleanup()
		return "", 0, func() {}, fileErr
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		cleanup()
		return "", 0, func() {}, err
	}
	return archivePath, info.Size(), cleanup, nil
}

func (a *App) auditLocked(uid int64, action, details string) {
	a.auditWithIPLocked(uid, action, details, "")
}

func (a *App) auditWithIPLocked(uid int64, action, details, ip string) {
	a.state.Audit = append(a.state.Audit, AuditLog{Time: now(), UserID: uid, Action: action, Details: details, IP: ip})
	if len(a.state.Audit) > 10000 {
		a.state.Audit = a.state.Audit[len(a.state.Audit)-10000:]
	}
}

func (a *App) publicConfig() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.publicConfigLocked()
}

func (a *App) publicConfigLocked() map[string]interface{} {
	return map[string]interface{}{
		"listen_addr":               a.config.ListenAddr,
		"listen_port":               listenPort(a.config.ListenAddr),
		"public_base_url":           a.config.PublicBaseURL,
		"synology_base_url":         a.config.SynologyBaseURL,
		"synology_username":         a.config.SynologyUsername,
		"synology_staging_dir":      a.config.SynologyStagingDir,
		"synology_cloud_target_dir": a.config.SynologyCloudTargetDir,
		"synology_password_set":     a.config.SynologyPassword != "",
		"verify_tls":                a.config.VerifyTLS,
		"smtp_enabled":              a.config.SMTPEnabled,
		"smtp_host":                 a.config.SMTPHost,
		"smtp_port":                 a.config.SMTPPort,
		"smtp_secure":               a.config.SMTPSecure,
		"smtp_username":             a.config.SMTPUsername,
		"smtp_from_email":           a.config.SMTPFromEmail,
		"smtp_from_name":            a.config.SMTPFromName,
		"smtp_password_set":         a.config.SMTPPassword != "",
		"mail_event_job_nas_done":   a.config.MailEventJobNASDone,
		"mail_event_job_cloud_done": a.config.MailEventJobCloudDone,
		"mail_event_job_failed":     a.config.MailEventJobFailed,
		"mail_event_login_ban":      a.config.MailEventLoginBan,
	}
}

func (a *App) mailConfigLocked() map[string]interface{} {
	return map[string]interface{}{
		"smtp_enabled":              a.config.SMTPEnabled,
		"smtp_host":                 a.config.SMTPHost,
		"smtp_port":                 a.config.SMTPPort,
		"smtp_secure":               a.config.SMTPSecure,
		"smtp_username":             a.config.SMTPUsername,
		"smtp_from_email":           a.config.SMTPFromEmail,
		"smtp_from_name":            a.config.SMTPFromName,
		"smtp_password_set":         a.config.SMTPPassword != "",
		"mail_event_job_nas_done":   a.config.MailEventJobNASDone,
		"mail_event_job_cloud_done": a.config.MailEventJobCloudDone,
		"mail_event_job_failed":     a.config.MailEventJobFailed,
		"mail_event_login_ban":      a.config.MailEventLoginBan,
	}
}

func (a *App) appendJobEventLocked(j Job, message string) {
	if j.ID == 0 {
		return
	}
	a.state.JobEvents = append(a.state.JobEvents, JobEvent{
		Time:          now(),
		JobID:         j.ID,
		UserID:        j.UserID,
		Stage:         j.Stage,
		TransferBytes: j.TransferBytes,
		TransferTotal: j.TransferTotal,
		CloudBytes:    j.CloudBytes,
		CloudTotal:    j.CloudTotal,
		Message:       message,
	})
	if len(a.state.JobEvents) > 10000 {
		a.state.JobEvents = a.state.JobEvents[len(a.state.JobEvents)-10000:]
	}
}

func (a *App) notifyJobMail(jobID int64, event string) {
	a.mu.Lock()
	if !mailEventEnabled(a.config, event) {
		a.mu.Unlock()
		return
	}
	var job *Job
	for i := range a.state.Jobs {
		if a.state.Jobs[i].ID == jobID {
			job = &a.state.Jobs[i]
			break
		}
	}
	if job == nil || containsString(job.NotifiedEvents, event) {
		a.mu.Unlock()
		return
	}
	var owner User
	foundOwner := false
	for _, u := range a.state.Users {
		if u.ID == job.UserID {
			owner = u
			foundOwner = true
			break
		}
	}
	recipients := normalizeEmailList(owner.Emails)
	if !foundOwner || !owner.NotifyJobDone || len(recipients) == 0 {
		a.mu.Unlock()
		return
	}
	cfg := a.config
	sourcePath, nasPath := a.jobMailDisplayPathsLocked(*job, owner)
	job.NotifiedEvents = append(job.NotifiedEvents, event)
	snapshot := *job
	_ = a.saveLocked()
	a.mu.Unlock()

	subject, textBody, htmlBody := jobMailContent(snapshot, owner, event, sourcePath, nasPath)
	if err := sendHTMLMailWithConfig(cfg, recipients, subject, textBody, htmlBody); err != nil {
		log.Printf("[mail] job notification failed job=%d event=%s user=%q recipients=%d error=%v", snapshot.ID, event, owner.Username, len(recipients), err)
		return
	}
	log.Printf("[mail] job notification sent job=%d event=%s user=%q recipients=%d", snapshot.ID, event, owner.Username, len(recipients))
}

func (a *App) notifyLoginBan(ban LoginBan) {
	a.mu.Lock()
	if !a.config.SMTPEnabled || !a.config.MailEventLoginBan {
		a.mu.Unlock()
		return
	}
	cfg := a.config
	var recipients []string
	for _, u := range a.state.Users {
		if u.IsAdmin && u.NotifyAdminLogs {
			recipients = append(recipients, u.Emails...)
		}
	}
	recipients = normalizeEmailList(recipients)
	a.mu.Unlock()
	if len(recipients) == 0 {
		return
	}
	subject := appName + " 登录封禁通知"
	body := strings.Join([]string{
		"检测到登录失败次数达到阈值，系统已创建封禁规则。",
		"",
		"用户名：" + valueOrDash(ban.Username),
		"IP 地址：" + valueOrDash(ban.IP),
		"封禁方式：" + banDurationText(ban),
		"原因：" + valueOrDash(ban.Reason),
		"时间：" + valueOrDash(ban.CreatedAt),
		"",
		"这是站点管理日志通知。",
	}, "\n")
	if err := sendMailWithConfig(cfg, recipients, subject, body); err != nil {
		log.Printf("[mail] admin notification failed event=%s ban_id=%d recipients=%d error=%v", mailEventLoginBan, ban.ID, len(recipients), err)
		return
	}
	log.Printf("[mail] admin notification sent event=%s ban_id=%d recipients=%d", mailEventLoginBan, ban.ID, len(recipients))
}

func (a *App) sendMail(recipients []string, subject, body string) error {
	a.mu.Lock()
	cfg := a.config
	a.mu.Unlock()
	return sendMailWithConfig(cfg, recipients, subject, body)
}

func sendMailWithConfig(cfg Config, recipients []string, subject, body string) error {
	return sendMailBodyWithConfig(cfg, recipients, subject, "text/plain; charset=UTF-8", body)
}

func sendHTMLMailWithConfig(cfg Config, recipients []string, subject, textBody, htmlBody string) error {
	if strings.TrimSpace(htmlBody) == "" {
		htmlBody = "<pre>" + html.EscapeString(textBody) + "</pre>"
	}
	return sendMailBodyWithConfig(cfg, recipients, subject, "text/html; charset=UTF-8", htmlBody)
}

func sendMailBodyWithConfig(cfg Config, recipients []string, subject, contentType, body string) error {
	recipients = normalizeEmailList(recipients)
	if len(recipients) == 0 {
		return errors.New("no mail recipients")
	}
	if !cfg.SMTPEnabled {
		return errors.New("smtp is not enabled")
	}
	if cfg.SMTPHost == "" || cfg.SMTPPort <= 0 || cfg.SMTPPort > 65535 {
		return errors.New("smtp server is not configured")
	}
	fromEmail := strings.TrimSpace(cfg.SMTPFromEmail)
	if fromEmail == "" {
		fromEmail = strings.TrimSpace(cfg.SMTPUsername)
	}
	if _, err := mail.ParseAddress(fromEmail); err != nil {
		return fmt.Errorf("sender email is invalid: %w", err)
	}
	message := buildMailMessage(cfg, fromEmail, recipients, subject, contentType, body)
	log.Printf("[mail] sending smtp host=%s port=%d secure=%s to=%d subject=%q", cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPSecure, len(recipients), subject)
	return smtpSend(cfg, fromEmail, recipients, message)
}

func buildMailMessage(cfg Config, fromEmail string, recipients []string, subject, contentType, body string) []byte {
	from := (&mail.Address{Name: strings.TrimSpace(cfg.SMTPFromName), Address: fromEmail}).String()
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(recipients, ", "),
		"Subject: " + mime.QEncoding.Encode("UTF-8", subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: " + contentType,
		"Content-Transfer-Encoding: base64",
	}
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + wrapBase64(base64.StdEncoding.EncodeToString([]byte(body))))
}

func smtpSend(cfg Config, from string, recipients []string, message []byte) error {
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	var err error
	if cfg.SMTPSecure == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()
	if cfg.SMTPSecure == "starttls" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("smtp server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.SMTPUsername) != "" {
		auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(message); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (a *App) jobMailDisplayPathsLocked(job Job, owner User) (string, string) {
	if owner.IsAdmin {
		sourcePath := job.SourceAbsPath
		if strings.TrimSpace(sourcePath) == "" {
			sourcePath = displaySourceRelPath(job.SourceRelPath)
		}
		return sourcePath, job.NASPath
	}
	return displaySourceRelPath(job.SourceRelPath), a.displayNASPathLocked(job, owner)
}

func jobMailContent(job Job, owner User, event, sourcePath, nasPath string) (string, string, string) {
	name := jobDisplayName(job)
	headline := "备份任务已完成"
	subjectPrefix := "文件同步已完成"
	switch event {
	case mailEventJobNASDone:
		subjectPrefix = "文件同步已完成"
	case mailEventJobCloudDone:
		subjectPrefix = "文件已上传到云端"
	case mailEventJobFailed:
		headline = "备份任务未完成"
		subjectPrefix = "备份任务失败"
	}
	subject := fmt.Sprintf("%s - %s", subjectPrefix, name)
	filePath := valueOrDash(sourcePath)
	if filePath == "" || filePath == "-" {
		filePath = "根目录"
	}
	location := valueOrDash(nasPath)
	size := humanBytes(job.SourceSize)
	completedAt := valueOrDash(job.CompletedAt)
	lines := []string{
		headline,
		"",
		"文件：" + filePath,
		"到达的位置：" + location,
		"文件大小：" + size,
		"完成时间：" + completedAt,
	}
	if job.Error != "" {
		lines = append(lines, "错误信息："+job.Error)
	}
	lines = append(lines,
		"",
		"详细信息",
		"任务编号："+strconv.FormatInt(job.ID, 10),
		"用户："+owner.Username,
		"当前状态："+stageName(job.Stage),
		"创建时间："+valueOrDash(job.CreatedAt),
		"开始时间："+valueOrDash(job.StartedAt),
		"这是你的文件传输日志通知。",
	)
	htmlBody := jobMailHTML(headline, filePath, location, size, completedAt, job, owner)
	return subject, strings.Join(lines, "\n"), htmlBody
}

func jobDisplayName(job Job) string {
	rel := cleanRel(job.SourceRelPath)
	if rel != "" {
		name := path.Base(rel)
		if name != "." && name != "/" && name != "" {
			return name
		}
	}
	name := path.Base(job.NASPath)
	if name == "." || name == "/" || name == "" {
		return "备份文件"
	}
	return name
}

func jobMailHTML(headline, filePath, location, size, completedAt string, job Job, owner User) string {
	note := "文件已经处理完成，可以在对应位置查看。"
	if job.Stage == "Failed" || job.Error != "" {
		note = "任务没有完成，请在网页里查看原因。"
	}
	errBlock := ""
	if job.Error != "" {
		errBlock = `<div style="margin-top:14px;padding:12px;border-radius:8px;background:#fef2f2;color:#991b1b;">` + html.EscapeString(job.Error) + `</div>`
	}
	rows := []string{
		htmlRow("文件", filePath),
		htmlRow("到达的位置", location),
		htmlRow("文件大小", size),
		htmlRow("完成时间", completedAt),
	}
	details := []string{
		htmlRow("任务编号", strconv.FormatInt(job.ID, 10)),
		htmlRow("用户", owner.Username),
		htmlRow("当前状态", stageName(job.Stage)),
		htmlRow("创建时间", valueOrDash(job.CreatedAt)),
		htmlRow("开始时间", valueOrDash(job.StartedAt)),
	}
	return `<!doctype html><html><body style="margin:0;background:#f3f6fa;padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,'Microsoft YaHei',sans-serif;color:#17202a;">
<div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
  <div style="padding:24px 26px;background:#0f766e;color:#ffffff;">
    <div style="font-size:22px;font-weight:700;line-height:1.35;">` + html.EscapeString(headline) + `</div>
    <div style="margin-top:6px;font-size:14px;opacity:.9;">` + html.EscapeString(note) + `</div>
  </div>
  <div style="padding:22px 26px;">
    <table role="presentation" style="width:100%;border-collapse:collapse;">` + strings.Join(rows, "") + `</table>` + errBlock + `
    <div style="margin-top:22px;padding-top:16px;border-top:1px solid #e5e7eb;color:#64748b;font-size:12px;line-height:1.7;">
      <div style="font-weight:700;color:#475569;margin-bottom:6px;">详细信息</div>
      <table role="presentation" style="width:100%;border-collapse:collapse;font-size:12px;color:#64748b;">` + strings.Join(details, "") + `</table>
      <div style="margin-top:10px;">这是你的文件传输日志通知。</div>
    </div>
  </div>
</div>
</body></html>`
}

func htmlRow(label, value string) string {
	return `<tr><td style="width:110px;padding:9px 0;color:#64748b;vertical-align:top;">` + html.EscapeString(label) + `</td><td style="padding:9px 0;color:#111827;font-weight:600;word-break:break-all;">` + html.EscapeString(valueOrDash(value)) + `</td></tr>`
}

type SynologyClient struct {
	app *App
	sid string
}

func (a *App) synology() *SynologyClient {
	return &SynologyClient{app: a}
}

func (c *SynologyClient) login() error {
	if c.sid != "" {
		return nil
	}
	cfg := c.app.config
	v := url.Values{}
	v.Set("api", "SYNO.API.Auth")
	v.Set("version", "6")
	v.Set("method", "login")
	v.Set("account", cfg.SynologyUsername)
	v.Set("passwd", cfg.SynologyPassword)
	v.Set("session", "FileStation")
	v.Set("format", "sid")
	var res struct {
		Success bool `json:"success"`
		Data    struct {
			SID string `json:"sid"`
		} `json:"data"`
		Error interface{} `json:"error"`
	}
	if err := c.get("/webapi/auth.cgi", v, &res); err != nil {
		return err
	}
	if !res.Success || res.Data.SID == "" {
		return fmt.Errorf("synology auth failed: %v", res.Error)
	}
	c.sid = res.Data.SID
	return nil
}

func (c *SynologyClient) get(apiPath string, v url.Values, out interface{}) error {
	u := strings.TrimRight(c.app.config.SynologyBaseURL, "/") + apiPath + "?" + v.Encode()
	resp, err := c.app.httpClient.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("synology http %d: %s", resp.StatusCode, compactResponseBody(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode synology response: %w: %s", err, string(b))
	}
	return nil
}

func (c *SynologyClient) entry(v url.Values, out interface{}) error {
	if err := c.login(); err != nil {
		return err
	}
	v.Set("_sid", c.sid)
	return c.get("/webapi/entry.cgi", v, out)
}

func (c *SynologyClient) APIInfo() (map[string]interface{}, error) {
	v := url.Values{}
	v.Set("api", "SYNO.API.Info")
	v.Set("version", "1")
	v.Set("method", "query")
	v.Set("query", "SYNO.API.Auth,SYNO.FileStation.Upload,SYNO.FileStation.List,SYNO.FileStation.CreateFolder,SYNO.FileStation.CopyMove,SYNO.CloudSync")
	var res map[string]interface{}
	return res, c.get("/webapi/query.cgi", v, &res)
}

func (c *SynologyClient) ListShares() (interface{}, error) {
	v := url.Values{}
	v.Set("api", "SYNO.FileStation.List")
	v.Set("version", "2")
	v.Set("method", "list_share")
	var res map[string]interface{}
	err := c.entry(v, &res)
	return res, err
}

func (c *SynologyClient) EnsureFolder(folder string) error {
	folder = synoClean(folder)
	parent := path.Dir(folder)
	name := path.Base(folder)
	v := url.Values{}
	v.Set("api", "SYNO.FileStation.CreateFolder")
	v.Set("version", "2")
	v.Set("method", "create")
	v.Set("folder_path", parent)
	v.Set("name", name)
	v.Set("force_parent", "true")
	var res struct {
		Success bool        `json:"success"`
		Error   interface{} `json:"error"`
	}
	if err := c.entry(v, &res); err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("create folder failed: %v", res.Error)
	}
	return nil
}

func (c *SynologyClient) UploadFile(ctx context.Context, localPath, remoteDir, remoteName string, progress func(sent, total, speed int64)) error {
	if err := c.login(); err != nil {
		return err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var header bytes.Buffer
	mw := multipart.NewWriter(&header)
	fields := map[string]string{
		"path":           remoteDir,
		"create_parents": "true",
		"overwrite":      "true",
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return err
		}
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, escapeQuotes(remoteName)))
	if _, err := mw.CreatePart(h); err != nil {
		return err
	}
	contentType := mw.FormDataContentType()
	footer := []byte("\r\n--" + mw.Boundary() + "--\r\n")
	reader := &progressReader{ctx: ctx, r: f, total: info.Size(), cb: progress, start: time.Now()}
	body := io.MultiReader(bytes.NewReader(header.Bytes()), reader, bytes.NewReader(footer))
	q := url.Values{}
	q.Set("api", "SYNO.FileStation.Upload")
	q.Set("version", "2")
	q.Set("method", "upload")
	q.Set("_sid", c.sid)
	u := strings.TrimRight(c.app.config.SynologyBaseURL, "/") + "/webapi/entry.cgi?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(header.Len()) + info.Size() + int64(len(footer))
	resp, err := c.app.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return errJobCanceled
		}
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("synology upload http %d: %s", resp.StatusCode, compactResponseBody(respBody))
	}
	var res struct {
		Success bool        `json:"success"`
		Error   interface{} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return fmt.Errorf("decode upload response: %w: %s", err, string(respBody))
	}
	if !res.Success {
		return fmt.Errorf("upload failed: %v", res.Error)
	}
	progress(info.Size(), info.Size(), 0)
	return nil
}

func (c *SynologyClient) Move(src, destDir, destName string) error {
	if err := c.EnsureFolder(destDir); err != nil {
		return err
	}
	v := url.Values{}
	v.Set("api", "SYNO.FileStation.CopyMove")
	v.Set("version", "3")
	v.Set("method", "start")
	v.Set("path", jsonStringArray([]string{src}))
	v.Set("dest_folder_path", destDir)
	v.Set("remove_src", "true")
	v.Set("overwrite", "true")
	var res struct {
		Success bool `json:"success"`
		Data    struct {
			TaskID string `json:"taskid"`
		} `json:"data"`
		Error interface{} `json:"error"`
	}
	if err := c.entry(v, &res); err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("move start failed: %v", res.Error)
	}
	if destName != "" && path.Base(src) != destName {
		moved := synoJoin(destDir, path.Base(src))
		v2 := url.Values{}
		v2.Set("api", "SYNO.FileStation.Rename")
		v2.Set("version", "2")
		v2.Set("method", "rename")
		v2.Set("path", moved)
		v2.Set("name", destName)
		var renameRes struct {
			Success bool        `json:"success"`
			Error   interface{} `json:"error"`
		}
		if err := c.entry(v2, &renameRes); err != nil {
			return err
		}
		if !renameRes.Success {
			return fmt.Errorf("rename failed: %v", renameRes.Error)
		}
	}
	return nil
}

type CloudRecent struct {
	Success bool `json:"success"`
	Data    struct {
		ProcessingItems []CloudProcessingItem `json:"processing_items"`
		HistoryItems    []interface{}         `json:"history_items"`
	} `json:"data"`
	Error interface{} `json:"error"`
}

type CloudProcessingItem struct {
	BaseName    string `json:"base_name"`
	Path        string `json:"path"`
	Status      string `json:"status"`
	CurrentSize int64  `json:"current_size"`
	TotalSize   int64  `json:"total_size"`
	BitRate     int64  `json:"bit_rate"`
	SessionID   int64  `json:"session_id"`
}

type CloudLogs struct {
	Success bool `json:"success"`
	Data    struct {
		Items []CloudLogItem `json:"items"`
		Total int            `json:"total"`
	} `json:"data"`
	Error interface{} `json:"error"`
}

type CloudLogItem struct {
	Action    int64  `json:"action"`
	ErrorCode int64  `json:"error_code"`
	FileName  string `json:"file_name"`
	LogLevel  int64  `json:"log_level"`
	Path      string `json:"path"`
	SessionID int64  `json:"session_id"`
	Time      int64  `json:"time"`
}

func (c *SynologyClient) CloudRecentlyChanged() (CloudRecent, error) {
	v := url.Values{}
	v.Set("api", "SYNO.CloudSync")
	v.Set("version", "1")
	v.Set("method", "get_recently_change")
	v.Set("limit", "50")
	v.Set("offset", "0")
	var res CloudRecent
	err := c.entry(v, &res)
	if err == nil && !res.Success {
		err = fmt.Errorf("cloud recent failed: %v", res.Error)
	}
	return res, err
}

func (c *SynologyClient) CloudLogs() (CloudLogs, error) {
	v := url.Values{}
	v.Set("api", "SYNO.CloudSync")
	v.Set("version", "1")
	v.Set("method", "get_log")
	v.Set("limit", "100")
	v.Set("offset", "0")
	var res CloudLogs
	err := c.entry(v, &res)
	if err == nil && !res.Success {
		err = fmt.Errorf("cloud logs failed: %v", res.Error)
	}
	return res, err
}

func (c *SynologyClient) CloudListConn() (interface{}, error) {
	v := url.Values{}
	v.Set("api", "SYNO.CloudSync")
	v.Set("version", "1")
	v.Set("method", "list_conn")
	var res map[string]interface{}
	err := c.entry(v, &res)
	return res, err
}

type progressReader struct {
	ctx   context.Context
	r     io.Reader
	total int64
	sent  int64
	cb    func(sent, total, speed int64)
	start time.Time
	last  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	if err := checkCanceled(p.ctx); err != nil {
		return 0, err
	}
	n, err := p.r.Read(b)
	if n > 0 {
		p.sent += int64(n)
		now := time.Now()
		if p.last.IsZero() || now.Sub(p.last) > time.Second || p.sent == p.total {
			elapsed := now.Sub(p.start).Seconds()
			var speed int64
			if elapsed > 0 {
				speed = int64(float64(p.sent) / elapsed)
			}
			p.cb(p.sent, p.total, speed)
			p.last = now
		}
	}
	return n, err
}

func checkCanceled(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errJobCanceled
	default:
		return nil
	}
}

func readJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonErrorWith(w, status, msg, nil)
}

func jsonErrorWith(w http.ResponseWriter, status int, msg string, extra map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	payload := map[string]interface{}{"error": msg}
	for k, v := range extra {
		payload[k] = v
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func publicRoot(root Root, viewer User) Root {
	if viewer.IsAdmin {
		return root
	}
	root.Path = ""
	return root
}

func (a *App) publicJobLocked(j Job, viewer User) map[string]interface{} {
	sourceAbsPath := j.SourceAbsPath
	nasPath := j.NASPath
	stagingPath := j.StagingPath
	if !viewer.IsAdmin {
		sourceAbsPath = ""
		stagingPath = ""
		nasPath = a.displayNASPathLocked(j, viewer)
	}
	return map[string]interface{}{
		"id":               j.ID,
		"user_id":          j.UserID,
		"root_id":          j.RootID,
		"source_rel_path":  j.SourceRelPath,
		"source_abs_path":  sourceAbsPath,
		"source_is_dir":    j.SourceIsDir,
		"source_size":      j.SourceSize,
		"source_mtime":     j.SourceMtime,
		"stage":            j.Stage,
		"transfer_bytes":   j.TransferBytes,
		"transfer_total":   j.TransferTotal,
		"transfer_speed":   j.TransferSpeed,
		"cloud_bytes":      j.CloudBytes,
		"cloud_total":      j.CloudTotal,
		"cloud_speed":      j.CloudSpeed,
		"nas_path":         nasPath,
		"staging_path":     stagingPath,
		"error":            j.Error,
		"created_at":       j.CreatedAt,
		"started_at":       j.StartedAt,
		"completed_at":     j.CompletedAt,
		"cloud_updated_at": j.CloudUpdatedAt,
	}
}

func publicUser(u User) map[string]interface{} {
	return map[string]interface{}{
		"id":                u.ID,
		"username":          u.Username,
		"is_admin":          u.IsAdmin,
		"allowed_roots":     u.AllowedRoots,
		"upload_dir":        u.UploadDir,
		"emails":            normalizeEmailList(u.Emails),
		"notify_job_done":   u.NotifyJobDone,
		"notify_admin_logs": u.NotifyAdminLogs && u.IsAdmin,
		"created_at":        u.CreatedAt,
	}
}

func safeResolve(root, rel string) (string, error) {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rel = cleanRel(rel)
	joined := filepath.Join(rootReal, filepath.FromSlash(rel))
	real, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	rootWithSep := rootReal
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}
	if real != rootReal && !strings.HasPrefix(real, rootWithSep) {
		return "", errors.New("path escapes allowed root")
	}
	return real, nil
}

func directorySize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func cleanRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "." {
		return ""
	}
	return p
}

func safeRemoteName(name string) string {
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.Trim(name, " .")
	if name == "" {
		name = "backup-file"
	}
	return name
}

func synoClean(p string) string {
	if p == "" {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}

func synoJoin(parts ...string) string {
	out := "/"
	for _, part := range parts {
		out = path.Join(out, strings.Trim(part, "/"))
	}
	return synoClean(out)
}

func normalizeUserUploadDir(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return synoClean(p)
}

func normalizeEmailList(input []string) []string {
	emails, _ := parseEmailList(input, false)
	return emails
}

func validateEmailList(input []string) ([]string, error) {
	return parseEmailList(input, true)
}

func parseEmailList(input []string, strict bool) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range input {
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r'
		})
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			addr, err := mail.ParseAddress(part)
			if err != nil {
				if strict {
					return nil, fmt.Errorf("invalid email: %s", part)
				}
				continue
			}
			email := strings.ToLower(strings.TrimSpace(addr.Address))
			if email == "" {
				continue
			}
			if !seen[email] {
				seen[email] = true
				out = append(out, email)
			}
		}
	}
	if strict && len(out) > 10 {
		return nil, errors.New("you can bind at most 10 email addresses")
	}
	return out, nil
}

func sameSynoPath(a, b string) bool {
	return synoClean(a) == synoClean(b)
}

func normalizeListenAddr(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultAddr
	}
	if _, err := strconv.Atoi(raw); err == nil {
		raw = ":" + raw
	}
	var portRaw string
	if strings.HasPrefix(raw, ":") {
		portRaw = strings.TrimPrefix(raw, ":")
	} else {
		_, port, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, errors.New("web port must be a number between 1 and 65535")
		}
		portRaw = port
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, errors.New("web port must be a number between 1 and 65535")
	}
	return ":" + strconv.Itoa(port), port, nil
}

func listenPort(addr string) int {
	_, port, err := normalizeListenAddr(addr)
	if err != nil {
		return 60000
	}
	return port
}

func normalizePublicBaseURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("public access URL must include http:// or https:// and host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("public access URL must use http or https")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func publicURLWithPort(current string, port int) string {
	u, err := url.Parse(strings.TrimSpace(current))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "https://127.0.0.1:" + strconv.Itoa(port)
	}
	host := u.Hostname()
	if host == "" {
		return "https://127.0.0.1:" + strconv.Itoa(port)
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func rewritePublicURLPort(raw string, oldPort, newPort int) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	if u.Port() == strconv.Itoa(oldPort) {
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(newPort))
		return strings.TrimRight(u.String(), "/")
	}
	return raw
}

func normalizeSMTPSecure(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tls", "ssl", "ssl_tls":
		return "tls"
	case "plain", "none":
		return "plain"
	default:
		return "starttls"
	}
}

func mailEventEnabled(cfg Config, event string) bool {
	if !cfg.SMTPEnabled {
		return false
	}
	switch event {
	case mailEventJobNASDone:
		return cfg.MailEventJobNASDone
	case mailEventJobCloudDone:
		return cfg.MailEventJobCloudDone
	case mailEventJobFailed:
		return cfg.MailEventJobFailed
	case mailEventLoginBan:
		return cfg.MailEventLoginBan
	default:
		return false
	}
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func wrapBase64(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	b.WriteString("\r\n")
	return b.String()
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func banDurationText(ban LoginBan) string {
	if ban.Permanent {
		return "永久封禁"
	}
	return "封禁至 " + valueOrDash(ban.Until)
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func jsonStringArray(v []string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func compactResponseBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if strings.Contains(strings.ToLower(s), "<html") {
		var out strings.Builder
		inTag := false
		for _, r := range s {
			switch r {
			case '<':
				inTag = true
			case '>':
				inTag = false
				out.WriteRune(' ')
			default:
				if !inTag {
					out.WriteRune(r)
				}
			}
		}
		s = strings.Join(strings.Fields(out.String()), " ")
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	if s == "" {
		return "(empty response)"
	}
	return s
}

func escapeQuotes(s string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, `\"`, "\r", "", "\n", "").Replace(s)
}

func containsID(list []int64, id int64) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func uniqueIDs(ids []int64) []int64 {
	m := map[int64]bool{}
	var out []int64
	for _, id := range ids {
		if id > 0 && !m[id] {
			m[id] = true
			out = append(out, id)
		}
	}
	return out
}

func removeID(ids []int64, remove int64) []int64 {
	out := ids[:0]
	for _, id := range ids {
		if id != remove {
			out = append(out, id)
		}
	}
	return out
}

func isRunningJob(stage string) bool {
	return stage == "Packaging" || stage == "CopyingToNAS" || stage == "MovingToCloudDir" || stage == "Canceling"
}

func (a *App) targetDirForUserLocked(u User) string {
	if strings.TrimSpace(u.UploadDir) != "" {
		return synoClean(u.UploadDir)
	}
	return synoClean(a.config.SynologyCloudTargetDir)
}

func (a *App) displayNASPathLocked(j Job, viewer User) string {
	if viewer.IsAdmin {
		return j.NASPath
	}
	base := a.targetDirForUserLocked(viewer)
	return displayRelativeNASPath(j.NASPath, base)
}

func displayRelativeNASPath(fullPath, basePath string) string {
	full := synoClean(fullPath)
	base := synoClean(basePath)
	prefix := strings.TrimSuffix(base, "/") + "/"
	if full == base {
		return path.Base(full)
	}
	if strings.HasPrefix(full, prefix) {
		rel := strings.TrimPrefix(full, prefix)
		if rel != "" {
			return rel
		}
	}
	name := path.Base(full)
	if name == "." || name == "/" || name == "" {
		return "-"
	}
	return name
}

func displaySourceRelPath(rel string) string {
	rel = cleanRel(rel)
	if rel == "" {
		return "根目录"
	}
	return rel
}

func parseLimit(raw string, fallback, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}

func usernameForID(users map[int64]string, id int64) string {
	if name, ok := users[id]; ok && name != "" {
		return name
	}
	return fmt.Sprintf("user-%d", id)
}

func progressBucket(j Job) int64 {
	done := j.TransferBytes
	total := j.TransferTotal
	if j.Stage == "CloudSyncUploading" {
		done = j.CloudBytes
		total = j.CloudTotal
	}
	if total <= 0 {
		total = j.SourceSize
	}
	if total <= 0 {
		return 0
	}
	return done * 10 / total
}

func shouldLogJobEvent(before, after Job) bool {
	if after.ID == 0 {
		return false
	}
	if before.Stage != after.Stage {
		return true
	}
	if progressBucket(before) != progressBucket(after) {
		return true
	}
	if before.Error != after.Error && after.Error != "" {
		return true
	}
	return false
}

func jobEventMessage(before, after Job) string {
	if before.Stage != after.Stage {
		return stageName(before.Stage) + " -> " + stageName(after.Stage)
	}
	if before.Error != after.Error && after.Error != "" {
		return "错误更新"
	}
	return "进度更新"
}

func jobActionMessage(action string) string {
	switch action {
	case "cancel":
		return "手动取消任务"
	case "retry":
		return "手动重试任务"
	case "refresh_cloud":
		return "手动检查云端状态"
	case "mark_cloud_completed":
		return "手动标记云端完成"
	default:
		return "手动操作任务"
	}
}

func stageName(stage string) string {
	switch stage {
	case "Pending":
		return "等待中"
	case "Packaging":
		return "打包目录"
	case "CopyingToNAS":
		return "上传到群晖"
	case "MovingToCloudDir":
		return "移入同步目录"
	case "NASCompleted":
		return "已到达群晖"
	case "WaitingCloudSync":
		return "等待 Cloud Sync"
	case "CloudSyncUploading":
		return "Cloud Sync 上传中"
	case "CloudCompleted":
		return "云端完成"
	case "CloudFailed":
		return "云端失败"
	case "CloudStatusUnknown":
		return "云端状态未知"
	case "Canceling":
		return "正在取消"
	case "Canceled":
		return "已取消"
	case "Failed":
		return "失败"
	default:
		return stage
	}
}

func clientIP(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		raw := r.Header.Get(header)
		if raw == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			ip := strings.TrimSpace(part)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (a *App) captchaRequiredLocked(username, ip string) bool {
	return a.loginFailureCountLocked(username, ip) >= a.config.CaptchaAfterFailures
}

func (a *App) loginFailureCountLocked(username, ip string) int {
	count := 0
	for _, key := range []string{loginPairKey(username, ip), loginIPKey(ip)} {
		if attempt := a.loginFails[key]; attempt != nil {
			if time.Since(attempt.LastAt) > 24*time.Hour {
				delete(a.loginFails, key)
				continue
			}
			if attempt.Count > count {
				count = attempt.Count
			}
		}
	}
	return count
}

func (a *App) registerFailedLoginLocked(username, ip string) (int, bool, LoginBan) {
	count := 0
	for _, key := range []string{loginPairKey(username, ip), loginIPKey(ip)} {
		attempt := a.loginFails[key]
		if attempt == nil {
			attempt = &LoginAttempt{}
			a.loginFails[key] = attempt
		}
		if time.Since(attempt.LastAt) > 24*time.Hour {
			attempt.Count = 0
		}
		attempt.Count++
		attempt.LastAt = time.Now()
		if attempt.Count > count {
			count = attempt.Count
		}
	}
	if count >= a.config.MaxLoginFailures {
		ban := a.addLoginBanLocked(username, ip, fmt.Sprintf("failed login attempts=%d", count), 0)
		a.clearLoginFailuresLocked(username, ip)
		return count, true, ban
	}
	return count, false, LoginBan{}
}

func (a *App) clearLoginFailuresLocked(username, ip string) {
	delete(a.loginFails, loginPairKey(username, ip))
	delete(a.loginFails, loginIPKey(ip))
}

func loginPairKey(username, ip string) string {
	return "pair:" + strings.ToLower(strings.TrimSpace(username)) + "|" + strings.TrimSpace(ip)
}

func loginIPKey(ip string) string {
	return "ip:" + strings.TrimSpace(ip)
}

func (a *App) newCaptchaLocked() map[string]interface{} {
	return newCaptchaChallenge()
}

func newCaptchaChallenge() map[string]interface{} {
	id := captcha.NewLen(5)
	return map[string]interface{}{
		"id":        id,
		"image_url": "/api/captcha/" + id + ".png",
		"expires":   600,
	}
}

func (a *App) validateCaptchaLocked(id, answer string) bool {
	return captcha.VerifyString(strings.TrimSpace(id), strings.TrimSpace(answer))
}

func secureRandInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func (a *App) activeLoginBanLocked(username, ip string) (LoginBan, bool) {
	username = strings.ToLower(strings.TrimSpace(username))
	ip = strings.TrimSpace(ip)
	for _, ban := range a.state.LoginBans {
		if !loginBanActive(ban) {
			continue
		}
		if ip != "" && ban.IP == ip {
			return ban, true
		}
		if username != "" && strings.ToLower(ban.Username) == username {
			return ban, true
		}
	}
	return LoginBan{}, false
}

func (a *App) activeLoginBansLocked() []LoginBan {
	out := []LoginBan{}
	for _, ban := range a.state.LoginBans {
		if loginBanActive(ban) {
			out = append(out, ban)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func loginBanActive(ban LoginBan) bool {
	if ban.Permanent {
		return true
	}
	if ban.Until == "" {
		return false
	}
	until, err := time.Parse(time.RFC3339, ban.Until)
	return err == nil && time.Now().Before(until)
}

func (a *App) addLoginBanLocked(username, ip, reason string, createdBy int64) LoginBan {
	if ban, ok := a.activeLoginBanLocked(username, ip); ok {
		return ban
	}
	username = strings.TrimSpace(username)
	ip = strings.TrimSpace(ip)
	userID := int64(0)
	for _, u := range a.state.Users {
		if strings.EqualFold(u.Username, username) {
			userID = u.ID
			username = u.Username
			break
		}
	}
	ban := LoginBan{
		ID:        a.state.NextBanID,
		Username:  username,
		UserID:    userID,
		IP:        ip,
		Permanent: a.config.PermanentBan || a.config.BanDurationMinutes == 0,
		CreatedAt: now(),
		CreatedBy: createdBy,
		Reason:    reason,
	}
	if !ban.Permanent {
		ban.Until = time.Now().Add(time.Duration(a.config.BanDurationMinutes) * time.Minute).Format(time.RFC3339)
	}
	a.state.NextBanID++
	a.state.LoginBans = append(a.state.LoginBans, ban)
	return ban
}

func banPayload(ban LoginBan) map[string]interface{} {
	return map[string]interface{}{
		"banned":    true,
		"ban_id":    ban.ID,
		"username":  ban.Username,
		"ip":        ban.IP,
		"permanent": ban.Permanent,
		"until":     ban.Until,
	}
}

func (a *App) securityConfigLocked() map[string]interface{} {
	return map[string]interface{}{
		"captcha_after_failures": a.config.CaptchaAfterFailures,
		"max_login_failures":     a.config.MaxLoginFailures,
		"ban_duration_minutes":   a.config.BanDurationMinutes,
		"permanent_ban":          a.config.PermanentBan,
	}
}

func (a *App) adminCountLocked() int {
	count := 0
	for _, u := range a.state.Users {
		if u.IsAdmin {
			count++
		}
	}
	return count
}

func now() string {
	return time.Now().Format(time.RFC3339)
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashPassword(password string) (string, string) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	dk := pbkdf2SHA256([]byte(password), salt, 150000, 32)
	return hex.EncodeToString(salt), hex.EncodeToString(dk)
}

func verifyPassword(password, saltHex, hashHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, 150000, len(want))
	return hmac.Equal(got, want)
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func (a *App) loadTLSCertificate() error {
	var certPEM, keyPEM []byte
	a.mu.Lock()
	certRaw, certOK, err := a.readSecureStringLocked("https_cert_pem")
	if err != nil {
		a.mu.Unlock()
		return err
	}
	keyRaw, keyOK, err := a.readSecureStringLocked("https_key_pem")
	if err != nil {
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	if certOK && keyOK {
		certPEM = []byte(certRaw)
		keyPEM = []byte(keyRaw)
		log.Printf("[tls] loading certificate from encrypted sqlite storage")
	} else if legacyCert, legacyCertErr := os.ReadFile(certPath); legacyCertErr == nil {
		legacyKey, legacyKeyErr := os.ReadFile(keyPath)
		if legacyKeyErr != nil {
			return legacyKeyErr
		}
		certPEM = legacyCert
		keyPEM = legacyKey
		log.Printf("[tls] importing legacy certificate files into encrypted sqlite storage")
	} else {
		var genErr error
		certPEM, keyPEM, genErr = generateSelfSignedCertificatePEM()
		if genErr != nil {
			return genErr
		}
		log.Printf("[tls] generated self-signed certificate and stored it encrypted")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	a.mu.Lock()
	a.tlsCert = cert
	if err := a.writeSecureStringLocked("https_cert_pem", string(certPEM)); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.writeSecureStringLocked("https_key_pem", string(keyPEM)); err != nil {
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	if cert.Leaf != nil {
		log.Printf("[tls] certificate ready cn=%q not_after=%s", cert.Leaf.Subject.CommonName, cert.Leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func (a *App) getTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mu.Lock()
	cert := a.tlsCert
	a.mu.Unlock()
	if len(cert.Certificate) == 0 {
		return nil, errors.New("tls certificate is not loaded")
	}
	return &cert, nil
}

func (a *App) certificateStatus() (map[string]interface{}, error) {
	a.mu.Lock()
	cert := a.tlsCert
	a.mu.Unlock()
	if len(cert.Certificate) == 0 {
		return nil, errors.New("tls certificate is not loaded")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	ips := make([]string, 0, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	isSelfSigned := bytes.Equal(leaf.RawSubject, leaf.RawIssuer) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	return map[string]interface{}{
		"common_name":    leaf.Subject.CommonName,
		"issuer":         leaf.Issuer.String(),
		"not_before":     leaf.NotBefore.Format(time.RFC3339),
		"not_after":      leaf.NotAfter.Format(time.RFC3339),
		"dns_names":      leaf.DNSNames,
		"ip_addresses":   ips,
		"is_self_signed": isSelfSigned,
		"storage":        "SQLite secure_settings (AES-GCM encrypted)",
	}, nil
}

func multipartValue(r *http.Request, fileKey, valueKey string) ([]byte, error) {
	f, _, err := r.FormFile(fileKey)
	if err == nil {
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 2<<20))
	}
	raw := strings.TrimSpace(r.FormValue(valueKey))
	if raw == "" {
		return nil, err
	}
	return []byte(raw), nil
}

func saveTLSFiles(certPEM, keyPEM []byte) error {
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			backup := p + ".bak-" + ts
			if err := copyFile(p, backup, 0600); err != nil {
				return err
			}
		}
	}
	certTmp := filepath.Join(dir, ".server.crt.tmp")
	keyTmp := filepath.Join(dir, ".server.key.tmp")
	if err := os.WriteFile(certTmp, certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyTmp, keyPEM, 0600); err != nil {
		_ = os.Remove(certTmp)
		return err
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		_ = os.Remove(certTmp)
		_ = os.Remove(keyTmp)
		return err
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		return err
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func generateSelfSignedCertificatePEM() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pve-backup-web"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "pve-backup-web"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.2.6"), net.ParseIP("202.189.4.217")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := &bytes.Buffer{}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyOut := &bytes.Buffer{}
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certOut.Bytes(), keyOut.Bytes(), nil
}

func ensureSelfSignedCert(certFile, keyFile string) (tls.Certificate, error) {
	if _, err := os.Stat(certFile); err == nil {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return tls.Certificate{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pve-backup-web"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "pve-backup-web"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.2.6"), net.ParseIP("202.189.4.217")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certOut := &bytes.Buffer{}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyOut := &bytes.Buffer{}
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(certFile, certOut.Bytes(), 0600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyFile, keyOut.Bytes(), 0600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
}

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#172554"/>
<path d="M17 18h30v9H27v7h16v9H27v13H17V18Z" fill="#f8fafc"/>
<path d="M43 18h4a9 9 0 0 1 0 18h-4v-8h3.4a2 2 0 0 0 0-4H43v-6Z" fill="#38bdf8"/>
<circle cx="49" cy="49" r="7" fill="#10b981"/>
</svg>`

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <title>PVE Backup Web</title>
  <style>
    :root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17202a;background:#eef2f6}
    *{box-sizing:border-box}body{margin:0;background:#eef2f6}button,input,select,textarea{font:inherit}
    button{border:0;border-radius:6px;background:#2563eb;color:white;padding:8px 12px;cursor:pointer;transition:transform .14s ease,box-shadow .14s ease,background .14s ease}button:hover{transform:translateY(-1px);box-shadow:0 8px 18px rgba(37,99,235,.18)}button:active{transform:translateY(0) scale(.98);box-shadow:none}
    button.secondary{background:#e6eaf0;color:#1f2937}button.secondary:hover{box-shadow:0 8px 18px rgba(31,41,55,.1)}button.ghost{background:transparent;color:#d8dee7;border:1px solid #3a4656;box-shadow:none}button.ghost:hover{background:#243142;transform:translateX(2px)}button.danger{background:#dc2626}
    .shell{min-height:100vh;display:grid;grid-template-columns:240px minmax(0,1fr);background:linear-gradient(180deg,#f8fafc 0%,#eef2f6 100%)}aside{background:#18212d;color:#eef3f7;padding:20px;display:flex;flex-direction:column;gap:18px}.brand{font-weight:700;font-size:18px}.muted{color:#96a3b4;font-size:13px;line-height:1.55;overflow-wrap:anywhere}
    main{width:100%;max-width:1240px;margin:0 auto;padding:22px;display:grid;gap:16px;grid-template-rows:auto 1fr}.top{display:flex;justify-content:space-between;align-items:center;gap:12px}.grid{display:grid;grid-template-columns:repeat(2,minmax(320px,1fr));gap:16px;align-items:start}.wide{grid-column:1/-1}.formGrid{display:grid;grid-template-columns:repeat(2,minmax(220px,1fr));gap:12px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
    .panel{background:white;border:1px solid #dce2ea;border-radius:8px;overflow:hidden;box-shadow:0 10px 28px rgba(15,23,42,.055);animation:rise .22s ease}.panel h2{font-size:15px;margin:0;padding:12px 14px;border-bottom:1px solid #e5e9ef;background:#fbfcfe}.panel .body{padding:14px}.soft{background:#f8fafc;border:1px solid #e5e9ef;border-radius:8px;padding:12px}
    .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.stack{display:grid;gap:10px}.list{display:grid}.item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid #eef1f5;transition:background .14s ease}.item:hover{background:#f8fafc}.name{font-weight:600;overflow-wrap:anywhere}.small{font-size:12px;color:#64748b;line-height:1.5;overflow-wrap:anywhere}.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid #d6dde8;border-radius:999px;padding:3px 8px;background:#f8fafc;color:#475569;font-size:12px}.fileMain{display:flex;align-items:center;gap:10px;min-width:0}.fileText{min-width:0}.fileIcon{width:34px;height:34px;border-radius:7px;border:1px solid #d6dde8;display:inline-flex;align-items:center;justify-content:center;flex:0 0 34px;background:white;color:#64748b}.fileIcon svg{width:22px;height:22px;display:block}.fileIcon span{font-size:10px;font-weight:800;line-height:1;letter-spacing:0}.fileIcon.folder{background:#fff7ed;border-color:#fed7aa;color:#d97706}.fileIcon.video{background:#eef2ff;border-color:#c7d2fe;color:#4f46e5}.fileIcon.code{background:#ecfdf5;border-color:#bbf7d0;color:#15803d}.fileIcon.text{background:#f8fafc;border-color:#cbd5e1;color:#334155}.fileIcon.image{background:#fdf2f8;border-color:#fbcfe8;color:#be185d}.fileIcon.disk{background:#f0fdfa;border-color:#99f6e4;color:#0f766e}.fileIcon.archive{background:#fffbeb;border-color:#fde68a;color:#b45309}.fileIcon.pdf{background:#fef2f2;border-color:#fecaca;color:#b91c1c}.fileIcon.office{background:#eff6ff;border-color:#bfdbfe;color:#1d4ed8}
    .crumb{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.field,textarea{width:100%;border:1px solid #cad2dc;border-radius:6px;padding:9px;background:white;transition:border .14s ease,box-shadow .14s ease}.field:focus,textarea:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.13)}textarea{min-height:92px;resize:vertical}.captchaImage{width:180px;height:64px;border:1px solid #cad2dc;border-radius:6px;background:white;display:block}
    .login{min-height:100vh;display:grid;place-items:center;padding:32px;background:radial-gradient(circle at 20% 10%,#1d4ed8 0,#172554 24%,#0f172a 63%,#062f2b 100%)}.loginCard{width:min(430px,100%);background:#f8fafc;border:1px solid rgba(255,255,255,.22);border-radius:8px;overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.34);animation:rise .28s ease}.loginForm{padding:34px;display:grid;gap:14px}.loginForm h1{margin:0;font-size:28px;line-height:1.1;letter-spacing:0}.loginForm label{display:grid;gap:6px;font-size:13px;color:#475569}
    table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #eef1f5;padding:8px;text-align:left;font-size:13px;vertical-align:top}td:last-child,th:last-child{text-align:right}.tableWrap{max-height:380px;overflow:auto;border:1px solid #edf1f6;border-radius:8px}.progress{height:8px;background:#e8edf3;border-radius:99px;overflow:hidden}.bar{height:100%;background:linear-gradient(90deg,#0ea5e9,#10b981);width:0;transition:width .22s ease}.tabs{display:flex;gap:8px}.hidden{display:none!important}.error{background:#fee2e2;color:#991b1b;padding:8px;border-radius:6px}.ok{background:#dcfce7;color:#166534;padding:8px;border-radius:6px}
    .modal{position:fixed;inset:0;background:rgba(15,23,42,.55);display:grid;place-items:center;padding:24px;z-index:20}.modalCard{width:min(560px,100%);background:white;border-radius:8px;border:1px solid #dce2ea;box-shadow:0 28px 90px rgba(15,23,42,.34);animation:rise .22s ease}.modalCard h2{margin:0;padding:16px;border-bottom:1px solid #e5e9ef;font-size:17px}.modalBody{padding:16px;display:grid;gap:14px}.noticeText{white-space:pre-wrap;line-height:1.7;color:#334155;max-height:50vh;overflow:auto}
    @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
    @media(max-width:900px){.shell{grid-template-columns:1fr}aside{position:static}.grid,.formGrid{grid-template-columns:1fr}.item{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
  </style>
</head>
<body>
<div id="login" class="login">
  <div class="loginCard">
    <div class="loginForm">
      <div>
        <h1>PVE Backup Web</h1>
        <div class="small">输入您的账户凭据</div>
      </div>
      <label>用户名<input id="loginUser" class="field" autocomplete="username"></label>
      <label>密码<input id="loginPass" class="field" type="password" autocomplete="current-password"></label>
      <div id="captchaBox" class="soft hidden">
        <label>验证码
          <img id="captchaImage" class="captchaImage" alt="验证码">
          <input id="captchaAnswer" class="field" inputmode="numeric" autocomplete="off">
        </label>
        <button class="secondary" type="button" onclick="refreshCaptcha()">换一张</button>
      </div>
      <button onclick="doLogin()">登录</button>
      <div id="loginErr"></div>
    </div>
  </div>
</div>
<div id="app" class="shell hidden">
  <aside>
    <div>
      <div class="brand">PVE Backup Web</div>
      <div class="muted" id="who"></div>
    </div>
    <div class="stack">
      <button class="ghost" onclick="showTab('files')">文件</button>
      <button class="ghost" onclick="showTab('jobs')">任务</button>
      <button class="ghost" onclick="showTab('account')">账户</button>
      <button class="ghost adminOnly" onclick="showTab('admin')">管理</button>
      <button class="ghost adminOnly" onclick="showTab('logs')">日志</button>
      <button class="ghost" onclick="logout()">退出</button>
    </div>
    <div class="muted adminOnly" id="synoSummary"></div>
  </aside>
  <main>
    <div class="top">
      <div class="tabs"><button class="secondary" onclick="loadAll()">刷新</button></div>
      <div class="small" id="status"></div>
    </div>
    <section id="tab-files" class="grid">
      <div class="panel"><h2>授权目录</h2><div class="body"><select id="rootSelect" class="field" onchange="openRoot()"></select></div></div>
      <div class="panel"><h2>当前路径</h2><div class="body"><div id="crumb" class="crumb"></div></div></div>
      <div class="panel" style="grid-column:1/-1"><h2>文件列表</h2><div id="files" class="list"></div></div>
    </section>
    <section id="tab-jobs" class="panel hidden"><h2>备份任务</h2><div class="body"><div id="jobs" class="stack"></div></div></section>
    <section id="tab-account" class="grid hidden">
      <div class="panel"><h2>密码</h2><div class="body stack"><input id="currentPass" class="field" type="password" placeholder="当前密码"><input id="newSelfPass" class="field" type="password" placeholder="新密码，至少 8 位"><button onclick="changePassword()">修改密码</button><div id="accountMsg"></div></div></div>
      <div class="panel"><h2>邮箱通知</h2><div class="body stack">
        <textarea id="accountEmails" placeholder="每行一个邮箱，也可以用逗号分隔"></textarea>
        <label><input type="checkbox" id="notifyJobDone"> 接收文件传输日志</label>
        <label class="adminOnly"><input type="checkbox" id="notifyAdminLogs"> 接收站点管理日志</label>
        <div class="row"><button onclick="saveAccountNotifications()">保存邮箱设置</button><span class="small">最多绑定 10 个邮箱</span></div>
        <div id="accountMailMsg"></div>
      </div></div>
    </section>
    <section id="tab-admin" class="grid hidden">
      <div class="panel"><h2>目录根</h2><div class="body stack"><input id="rootName" class="field" placeholder="名称"><input id="rootPath" class="field" placeholder="/path/on/pve"><button onclick="addRoot()">添加目录</button><div id="adminRoots"></div></div></div>
      <div class="panel"><h2>用户</h2><div class="body stack"><input id="newUser" class="field" placeholder="用户名"><input id="newPass" class="field" placeholder="密码，至少 8 位"><input id="newUploadDir" class="field" placeholder="群晖上传目录，留空使用默认"><label><input type="checkbox" id="newAdmin"> 管理员</label><button onclick="addUser()">创建用户</button><div id="adminUsers"></div></div></div>
      <div class="panel wide"><h2>网页访问</h2><div class="body stack">
        <div class="formGrid">
          <label>网页端口<input id="sitePort" class="field" type="number" min="1" max="65535" placeholder="60000"></label>
          <label>公开访问地址<input id="publicBaseURL" class="field" placeholder="https://202.189.4.217:60000"></label>
        </div>
        <div class="row"><button onclick="saveSiteConfig()">保存访问设置</button><span class="small">端口保存后重启程序或服务生效</span></div>
        <div id="siteMsg"></div>
      </div></div>
      <div class="panel wide"><h2>群晖连接</h2><div class="body stack">
        <div class="formGrid">
          <label>DSM 地址<input id="synoBaseURL" class="field" placeholder="http://192.168.2.5:5000"></label>
          <label>用户名<input id="synoUsername" class="field"></label>
          <label>密码<input id="synoPassword" class="field" type="password" placeholder="留空则不修改"></label>
          <label>上传临时目录<input id="synoStagingDir" class="field" placeholder="/NVME/.pve-backup-incoming"></label>
          <label>最终同步目录<input id="synoCloudTargetDir" class="field" placeholder="/NVME/PVEBackup"></label>
          <label style="align-self:end"><input type="checkbox" id="synoVerifyTLS"> 校验 HTTPS 证书</label>
        </div>
        <div class="row"><button onclick="saveSynology()">保存配置</button><button class="secondary" onclick="testSynology()">测试群晖 API</button></div>
        <div id="synologyMsg"></div>
        <pre id="synologyInfo" style="white-space:pre-wrap;overflow:auto"></pre>
      </div></div>
      <div class="panel wide"><h2>邮件发送</h2><div class="body stack">
        <div class="formGrid">
          <label style="align-self:end"><input type="checkbox" id="smtpEnabled"> 启用 SMTP 发信</label>
          <label>加密方式<select id="smtpSecure" class="field"><option value="starttls">STARTTLS</option><option value="tls">SSL/TLS</option><option value="plain">普通连接</option></select></label>
          <label>SMTP 服务器<input id="smtpHost" class="field" placeholder="smtp.qq.com"></label>
          <label>SMTP 端口<input id="smtpPort" class="field" type="number" min="1" max="65535" placeholder="587"></label>
          <label>SMTP 用户名<input id="smtpUsername" class="field" autocomplete="off"></label>
          <label>SMTP 密码/授权码<input id="smtpPassword" class="field" type="password" placeholder="留空则不修改"></label>
          <label>发件邮箱<input id="smtpFromEmail" class="field" placeholder="name@example.com"></label>
          <label>发件名称<input id="smtpFromName" class="field" placeholder="PVE Backup Web"></label>
        </div>
        <div class="soft stack">
          <label><input type="checkbox" id="mailEventJobNASDone"> 文件上传到群晖后通知</label>
          <label><input type="checkbox" id="mailEventJobCloudDone"> Cloud Sync 完成后通知</label>
          <label><input type="checkbox" id="mailEventJobFailed"> 任务失败时通知</label>
          <label><input type="checkbox" id="mailEventLoginBan"> 用户或 IP 被封禁时通知管理员</label>
        </div>
        <div class="row"><button onclick="saveMailConfig()">保存邮件配置</button><input id="testMailTo" class="field" style="max-width:280px" placeholder="测试收件邮箱"><button class="secondary" onclick="sendTestMail()">发送测试邮件</button></div>
        <div id="mailMsg"></div>
      </div></div>
      <div class="panel wide"><h2>登录风控</h2><div class="body stack">
        <div class="formGrid">
          <label>输错几次后显示验证码<input id="captchaAfterFailures" class="field" type="number" min="1" max="20"></label>
          <label>连续错误几次后封禁<input id="maxLoginFailures" class="field" type="number" min="2" max="100"></label>
          <label>封禁时长（分钟）<input id="banDurationMinutes" class="field" type="number" min="0" max="525600"></label>
          <label style="align-self:end"><input type="checkbox" id="permanentBan"> 永久封禁</label>
        </div>
        <div class="row"><button onclick="saveSecurity()">保存风控设置</button><span class="small">非永久封禁时，封禁时长为 0 也会按永久封禁处理</span></div>
        <div id="securityMsg"></div>
        <div id="securityBans" class="tableWrap"></div>
      </div></div>
      <div class="panel wide"><h2>HTTPS 证书</h2><div class="body stack">
        <div id="certStatus" class="soft small"></div>
        <div class="formGrid">
          <label>证书文件<input id="tlsCertFile" class="field" type="file" accept=".crt,.cer,.pem"></label>
          <label>私钥文件<input id="tlsKeyFile" class="field" type="file" accept=".key,.pem"></label>
        </div>
        <div class="row"><button onclick="uploadCertificate()">上传并启用证书</button><span class="small">支持 PEM 格式证书链和私钥</span></div>
        <div id="certMsg"></div>
      </div></div>
      <div class="panel wide"><h2>站点公告</h2><div class="body stack">
        <textarea id="announcementText" placeholder="公告内容为空时，用户登录后不会弹窗"></textarea>
        <div class="row"><button onclick="saveAnnouncement()">保存公告</button><span class="small" id="announcementMeta"></span></div>
        <div id="announcementMsg"></div>
      </div></div>
    </section>
    <section id="tab-logs" class="stack hidden">
      <div class="panel"><h2>日志操作</h2><div class="body row"><button class="danger" onclick="clearLogs()">清除日志</button><div id="logsMsg"></div></div></div>
      <div class="panel"><h2>用户任务与上传进度</h2><div class="body"><div id="adminTaskLog" class="tableWrap"></div></div></div>
      <div class="panel"><h2>任务进度流水</h2><div class="body"><div id="adminProgressLog" class="tableWrap"></div></div></div>
      <div class="panel"><h2>用户文件操作记录</h2><div class="body"><div id="adminAuditLog" class="tableWrap"></div></div></div>
    </section>
  </main>
</div>
<div id="announcementModal" class="modal hidden">
  <div class="modalCard">
    <h2>站点公告</h2>
    <div class="modalBody">
      <div id="announcementContent" class="noticeText"></div>
      <div class="row"><button data-action="confirm-announcement">确认</button></div>
    </div>
  </div>
</div>
<script>
let me=null, roots=[], curRoot=null, curPath='', jobs=[], users=[], currentConfig=null, currentAnnouncement=null, eventSource=null, currentCaptcha=null;
const el={};
function bindElements(){
  Object.assign(el,{
    loginBox:document.getElementById('login'),
    appShell:document.getElementById('app'),
    loginUser:document.getElementById('loginUser'),
    loginPass:document.getElementById('loginPass'),
    loginErr:document.getElementById('loginErr'),
    captchaBox:document.getElementById('captchaBox'),
    captchaImage:document.getElementById('captchaImage'),
    captchaAnswer:document.getElementById('captchaAnswer'),
    who:document.getElementById('who'),
    synoSummary:document.getElementById('synoSummary'),
    status:document.getElementById('status'),
    rootSelect:document.getElementById('rootSelect'),
    crumb:document.getElementById('crumb'),
    files:document.getElementById('files'),
    jobs:document.getElementById('jobs'),
    currentPass:document.getElementById('currentPass'),
    newSelfPass:document.getElementById('newSelfPass'),
    accountMsg:document.getElementById('accountMsg'),
    accountEmails:document.getElementById('accountEmails'),
    notifyJobDone:document.getElementById('notifyJobDone'),
    notifyAdminLogs:document.getElementById('notifyAdminLogs'),
    accountMailMsg:document.getElementById('accountMailMsg'),
    adminRoots:document.getElementById('adminRoots'),
    adminUsers:document.getElementById('adminUsers'),
    synologyInfo:document.getElementById('synologyInfo'),
    rootName:document.getElementById('rootName'),
    rootPath:document.getElementById('rootPath'),
    newUser:document.getElementById('newUser'),
    newPass:document.getElementById('newPass'),
    newUploadDir:document.getElementById('newUploadDir'),
    newAdmin:document.getElementById('newAdmin'),
    sitePort:document.getElementById('sitePort'),
    publicBaseURL:document.getElementById('publicBaseURL'),
    siteMsg:document.getElementById('siteMsg'),
    synoBaseURL:document.getElementById('synoBaseURL'),
    synoUsername:document.getElementById('synoUsername'),
    synoPassword:document.getElementById('synoPassword'),
    synoStagingDir:document.getElementById('synoStagingDir'),
    synoCloudTargetDir:document.getElementById('synoCloudTargetDir'),
    synoVerifyTLS:document.getElementById('synoVerifyTLS'),
    synologyMsg:document.getElementById('synologyMsg'),
    smtpEnabled:document.getElementById('smtpEnabled'),
    smtpHost:document.getElementById('smtpHost'),
    smtpPort:document.getElementById('smtpPort'),
    smtpSecure:document.getElementById('smtpSecure'),
    smtpUsername:document.getElementById('smtpUsername'),
    smtpPassword:document.getElementById('smtpPassword'),
    smtpFromEmail:document.getElementById('smtpFromEmail'),
    smtpFromName:document.getElementById('smtpFromName'),
    mailEventJobNASDone:document.getElementById('mailEventJobNASDone'),
    mailEventJobCloudDone:document.getElementById('mailEventJobCloudDone'),
    mailEventJobFailed:document.getElementById('mailEventJobFailed'),
    mailEventLoginBan:document.getElementById('mailEventLoginBan'),
    testMailTo:document.getElementById('testMailTo'),
    mailMsg:document.getElementById('mailMsg'),
    announcementText:document.getElementById('announcementText'),
    announcementMeta:document.getElementById('announcementMeta'),
    announcementMsg:document.getElementById('announcementMsg'),
    announcementModal:document.getElementById('announcementModal'),
    announcementContent:document.getElementById('announcementContent'),
    adminTaskLog:document.getElementById('adminTaskLog'),
    adminProgressLog:document.getElementById('adminProgressLog'),
    adminAuditLog:document.getElementById('adminAuditLog'),
    logsMsg:document.getElementById('logsMsg'),
    certStatus:document.getElementById('certStatus'),
    tlsCertFile:document.getElementById('tlsCertFile'),
    tlsKeyFile:document.getElementById('tlsKeyFile'),
    certMsg:document.getElementById('certMsg'),
    captchaAfterFailures:document.getElementById('captchaAfterFailures'),
    maxLoginFailures:document.getElementById('maxLoginFailures'),
    banDurationMinutes:document.getElementById('banDurationMinutes'),
    permanentBan:document.getElementById('permanentBan'),
    securityMsg:document.getElementById('securityMsg'),
    securityBans:document.getElementById('securityBans')
  });
}
async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json'},...opt});const j=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(j.error||r.statusText);Object.assign(e,j);throw e}return j}
function bytes(n){if(!n)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]}
function pct(a,b){return b?Math.max(0,Math.min(100,a/b*100)):0}
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function timeText(s){if(!s)return '';const d=new Date(s);return Number.isNaN(d.getTime())?s:d.toLocaleString()}
function displayPath(s){return s?String(s):'根目录'}
function applyCaptcha(challenge){currentCaptcha=challenge||null;if(currentCaptcha){el.captchaImage.src=currentCaptcha.image_url+'?t='+Date.now();el.captchaAnswer.value='';el.captchaBox.classList.remove('hidden')}else{el.captchaBox.classList.add('hidden');el.captchaImage.removeAttribute('src');el.captchaAnswer.value=''}}
async function refreshCaptcha(){const r=await api('/api/captcha/new');applyCaptcha(r.captcha)}
function fileExt(name){
  const n=String(name||'').toLowerCase();
  if(n.endsWith('.tar.gz')||n.endsWith('.tar.zst')||n.endsWith('.tar.xz'))return 'tar';
  const i=n.lastIndexOf('.');
  return i>0&&i<n.length-1?n.slice(i+1):'';
}
function fileTypeInfo(name){
  const ext=fileExt(name);
  const types={
    mp4:['video','MP4'],mkv:['video','MKV'],mov:['video','MOV'],avi:['video','AVI'],webm:['video','WEBM'],
    py:['code','PY'],pyw:['code','PY'],
    txt:['text','TXT'],log:['text','LOG'],md:['text','MD'],json:['text','JSON'],xml:['text','XML'],yml:['text','YML'],yaml:['text','YAML'],csv:['text','CSV'],sql:['text','SQL'],ini:['text','INI'],conf:['text','CONF'],cfg:['text','CFG'],sh:['text','SH'],
    png:['image','PNG'],jpg:['image','JPG'],jpeg:['image','JPG'],gif:['image','GIF'],webp:['image','WEBP'],bmp:['image','BMP'],svg:['image','SVG'],
    img:['disk','IMG'],iso:['disk','ISO'],qcow2:['disk','QCOW'],raw:['disk','RAW'],vmdk:['disk','VMDK'],vhd:['disk','VHD'],vhdx:['disk','VHDX'],vma:['disk','VMA'],
    zip:['archive','ZIP'],rar:['archive','RAR'],'7z':['archive','7Z'],tar:['archive','TAR'],gz:['archive','GZ'],tgz:['archive','TGZ'],zst:['archive','ZST'],xz:['archive','XZ'],
    pdf:['pdf','PDF'],doc:['office','DOC'],docx:['office','DOCX'],xls:['office','XLS'],xlsx:['office','XLSX'],ppt:['office','PPT'],pptx:['office','PPTX']
  };
  return types[ext]||null;
}
function fileIcon(it){
  if(it.is_dir)return '<span class="fileIcon folder" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M3.5 6.8A2.3 2.3 0 0 1 5.8 4.5h4.1l2 2.4h6.3a2.3 2.3 0 0 1 2.3 2.3v7.9a2.4 2.4 0 0 1-2.4 2.4H5.9a2.4 2.4 0 0 1-2.4-2.4V6.8Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M3.8 9.1h16.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span>';
  const info=fileTypeInfo(it.name);
  if(info)return '<span class="fileIcon '+info[0]+'" aria-hidden="true"><span>'+esc(info[1])+'</span></span>';
  return '<span class="fileIcon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 3.8h7.2L19 8.6V20a.8.8 0 0 1-.8.8H7A1.9 1.9 0 0 1 5.2 19V5.6A1.8 1.8 0 0 1 7 3.8Z" fill="white" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M14 4v4.8h4.8" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg></span>';
}
async function doLogin(){
  const payload={username:el.loginUser.value,password:el.loginPass.value};
  if(currentCaptcha){payload.captcha_id=currentCaptcha.id;payload.captcha_answer=el.captchaAnswer.value}
  try{
    await api('/login',{method:'POST',body:JSON.stringify(payload)});
    applyCaptcha(null);
    el.loginErr.innerHTML='';
    await boot(true);
  }catch(e){
    if(e.captcha_required)applyCaptcha(e.captcha);
    const ban=e.banned?(e.permanent?' · 已永久封禁':' · 封禁至 '+timeText(e.until)):'';
    el.loginErr.innerHTML='<div class=error>'+esc(e.message+ban)+'</div>';
  }
}
async function logout(){await api('/logout',{method:'POST',body:'{}'}).catch(()=>{});location.reload()}
async function boot(justLoggedIn=false){try{const m=await api('/api/me');me=m.user;currentConfig=m.config||{};currentAnnouncement=m.announcement||{};el.loginBox.classList.add('hidden');el.appShell.classList.remove('hidden');el.who.textContent=me.username+(me.is_admin?' · 管理员':'');document.querySelectorAll('.adminOnly').forEach(x=>x.style.display=me.is_admin?'block':'none');renderAccountNotifications();if(me.is_admin){renderSiteConfig();renderSynologyConfig();renderMailConfig(currentConfig);el.synoSummary.textContent='NAS: '+(currentConfig.synology_base_url||'-')+' → '+(currentConfig.synology_cloud_target_dir||'-')}else{el.synoSummary.textContent=''}connectEvents();await loadAll();if(justLoggedIn)showAnnouncement(currentAnnouncement)}catch(e){el.loginBox.classList.remove('hidden');el.appShell.classList.add('hidden')}}
function showTab(t){['files','jobs','account','admin','logs'].forEach(x=>document.getElementById('tab-'+x).classList.toggle('hidden',x!==t));if(t==='jobs')loadJobs();if(t==='admin')loadAdmin();if(t==='logs')loadLogs()}
async function loadAll(){await loadRoots();await loadJobs();if(me&&me.is_admin)await loadAdmin().catch(()=>{})}
async function loadRoots(){const r=await api('/api/roots');roots=r.roots||[];el.rootSelect.innerHTML=roots.map(x=>'<option value="'+x.id+'">'+esc(x.path?x.name+' · '+x.path:x.name)+'</option>').join('');if(roots.length&&!curRoot){curRoot=roots[0].id;el.rootSelect.value=curRoot;await openRoot()}else if(curRoot){el.rootSelect.value=curRoot}}
async function openRoot(){curRoot=Number(el.rootSelect.value);curPath='';await loadFiles()}
async function openDir(p){curPath=p||'';await loadFiles()}
async function loadFiles(){
  if(!curRoot)return;
  const r=await api('/api/files?root_id='+curRoot+'&path='+encodeURIComponent(curPath));
  el.crumb.innerHTML='<button class=secondary data-action="open-dir" data-path="">/</button>';
  let acc='';
  curPath.split('/').filter(Boolean).forEach(part=>{
    acc=acc?acc+'/'+part:part;
    el.crumb.innerHTML+='<button class=secondary data-action="open-dir" data-path="'+esc(acc)+'">'+esc(part)+'</button>';
  });
  el.files.innerHTML=(r.items||[]).map(it=>{
    const buttons=it.is_dir
      ? '<button class=secondary data-action="open-dir" data-path="'+esc(it.path)+'">打开</button><button data-action="backup-file" data-path="'+esc(it.path)+'">备份目录</button>'
      : '<button data-action="backup-file" data-path="'+esc(it.path)+'">备份</button>';
    return '<div class=item><div class=fileMain>'+fileIcon(it)+'<div class=fileText><div class=name>'+esc(it.name)+'</div><div class=small>'+esc(it.path)+' · '+(it.is_dir?'目录':bytes(it.size))+'</div></div></div><div class=row>'+buttons+'</div></div>';
  }).join('')||'<div class=item>空目录</div>';
}
async function createJob(p){await api('/api/jobs',{method:'POST',body:JSON.stringify({root_id:curRoot,path:p})});showTab('jobs');await loadJobs()}
async function loadJobs(){const r=await api('/api/jobs');jobs=r.jobs||[];renderJobs()}
function stageText(stage){
  return ({
    Pending:'等待中',
    Packaging:'打包目录',
    CopyingToNAS:'上传到群晖',
    MovingToCloudDir:'移入同步目录',
    NASCompleted:'已到达群晖',
    WaitingCloudSync:'等待 Cloud Sync',
    CloudSyncUploading:'Cloud Sync 上传中',
    CloudCompleted:'云端完成',
    CloudFailed:'云端失败',
    CloudStatusUnknown:'已到达群晖，云端状态未知',
    Canceling:'正在取消',
    Canceled:'已取消',
    Failed:'失败'
  })[stage]||stage;
}
function isJobBusy(stage){return ['Packaging','CopyingToNAS','MovingToCloudDir','Canceling'].includes(stage)}
function renderJobs(){
  jobs.sort((a,b)=>b.id-a.id);
  el.jobs.innerHTML=jobs.map(j=>{
    let a=j.transfer_bytes,b=j.transfer_total||j.source_size;
    if(j.stage==='Packaging'){b=j.source_size}
    if(j.stage==='CloudSyncUploading'){a=j.cloud_bytes;b=j.cloud_total||j.source_size}
    const controls=[];
    if(isJobBusy(j.stage)){
      controls.push('<button class=danger data-action="cancel-job" data-id="'+j.id+'">取消</button>');
    }
    if(!isJobBusy(j.stage)&&j.stage!=='CloudCompleted'){
      controls.push('<button class=secondary data-action="retry-job" data-id="'+j.id+'">重试</button>');
    }
    if(['CloudStatusUnknown','WaitingCloudSync','NASCompleted','CloudFailed'].includes(j.stage)){
      controls.push('<button class=secondary data-action="refresh-cloud" data-id="'+j.id+'">检查云端</button>');
      if(me?.is_admin)controls.push('<button class=secondary data-action="mark-cloud-completed" data-id="'+j.id+'">标记云端完成</button>');
    }
    if(!isJobBusy(j.stage))controls.push('<button class=danger data-action="delete-job" data-id="'+j.id+'">删除</button>');
    return '<div class=panel><div class=body stack><div class=row><b>#'+j.id+'</b><span>'+esc(stageText(j.stage))+'</span><span class=small>'+(j.source_is_dir?'目录包 · ':'')+esc(displayPath(j.source_rel_path))+'</span></div><div class=progress><div class=bar style="width:'+pct(a,b)+'%"></div></div><div class=small>'+bytes(a)+' / '+bytes(b)+' · NAS '+esc(j.nas_path)+' · '+(j.transfer_speed?bytes(j.transfer_speed)+'/s':'')+(j.cloud_speed?' · Cloud '+bytes(j.cloud_speed)+'/s':'')+'</div>'+(j.error?'<div class=error>'+esc(j.error)+'</div>':'')+'<div class=row>'+controls.join('')+'</div></div></div>';
  }).join('')||'暂无任务';
}
async function loadAdmin(){
  if(!me?.is_admin)return;
  const rr=await api('/api/admin/roots');
  roots=rr.roots||roots;
  el.adminRoots.innerHTML='<table><tr><th>ID</th><th>名称</th><th>路径</th><th></th></tr>'+roots.map(r=>'<tr><td>'+r.id+'</td><td>'+esc(r.name)+'</td><td>'+esc(r.path)+'</td><td><button class=danger data-action="delete-root" data-id="'+r.id+'">删除</button></td></tr>').join('')+'</table>';
  const uu=await api('/api/admin/users');
  users=uu.users||[];
  el.adminUsers.innerHTML=users.map(u=>{
    const rootChecks=roots.map(r=>'<label style="margin-right:10px"><input type=checkbox data-user="'+u.id+'" value="'+r.id+'" '+((u.allowed_roots||[]).includes(r.id)?'checked':'')+'> '+esc(r.name)+'</label>').join('');
    const deleteBtn=u.id===me.id?'':'<button class=danger data-action="delete-user" data-id="'+u.id+'">删除用户</button>';
    return '<div class=panel><div class=body stack><div class=row><b>'+esc(u.username)+(u.is_admin?' · 管理员':'')+'</b><span class=pill>ID '+u.id+'</span><span class=pill>邮箱 '+((u.emails||[]).length)+'</span></div><div class=soft>'+rootChecks+'</div><div class=row><button class=secondary onclick="saveUserRoots('+u.id+')">保存目录权限</button>'+deleteBtn+'</div><div class=row><input class=field style="max-width:360px" data-upload-user="'+u.id+'" placeholder="群晖上传目录，留空使用默认" value="'+esc(u.upload_dir||'')+'"><button class=secondary data-action="save-user-upload-dir" data-id="'+u.id+'">保存上传目录</button></div><div class=row><input class=field style="max-width:260px" type=password data-reset-user="'+u.id+'" placeholder="新密码"><button class=secondary data-action="reset-user-password" data-id="'+u.id+'">重置密码</button></div></div></div>';
  }).join('');
  const aa=await api('/api/admin/announcement');
  currentAnnouncement=aa.announcement||currentAnnouncement||{};
  renderAnnouncementAdmin();
  const site=await api('/api/admin/site').catch(()=>null);
  if(site?.config){currentConfig={...currentConfig,...site.config};renderSiteConfig()}
  const mail=await api('/api/admin/mail').catch(()=>null);
  if(mail?.config)renderMailConfig(mail.config);
  await loadCertificateStatus().catch(()=>{});
  await loadSecurity().catch(()=>{});
}
async function addRoot(){await api('/api/admin/roots',{method:'POST',body:JSON.stringify({name:el.rootName.value,path:el.rootPath.value})});el.rootName.value='';el.rootPath.value='';await loadAll()}
async function addUser(){await api('/api/admin/users',{method:'POST',body:JSON.stringify({username:el.newUser.value,password:el.newPass.value,is_admin:el.newAdmin.checked,upload_dir:el.newUploadDir.value})});el.newUser.value='';el.newPass.value='';el.newUploadDir.value='';el.newAdmin.checked=false;await loadAdmin()}
async function saveUserRoots(uid){const ids=[...document.querySelectorAll('input[data-user="'+uid+'"]:checked')].map(x=>Number(x.value));await api('/api/admin/user-roots',{method:'POST',body:JSON.stringify({user_id:uid,root_ids:ids})});await loadAdmin()}
async function saveUserUploadDir(id){const input=document.querySelector('input[data-upload-user="'+id+'"]');await api('/api/admin/user-upload-dir',{method:'POST',body:JSON.stringify({user_id:Number(id),upload_dir:input?.value||''})});await loadAdmin()}
async function loadSecurity(){
  const r=await api('/api/admin/security');
  renderSecurity(r.config||{},r.bans||[]);
}
function renderSecurity(cfg,bans){
  el.captchaAfterFailures.value=cfg.captcha_after_failures||2;
  el.maxLoginFailures.value=cfg.max_login_failures||10;
  el.banDurationMinutes.value=cfg.ban_duration_minutes||0;
  el.permanentBan.checked=!!cfg.permanent_ban;
  el.securityBans.innerHTML='<table><tr><th>ID</th><th>用户</th><th>IP</th><th>封禁</th><th>原因</th><th></th></tr>'+(bans||[]).map(b=>'<tr><td>'+b.id+'</td><td>'+esc(b.username||'-')+'</td><td>'+esc(b.ip||'-')+'</td><td>'+esc(b.permanent?'永久':('至 '+timeText(b.until)))+'</td><td>'+esc(b.reason||'')+'</td><td><button class=secondary data-action="unban-login" data-id="'+b.id+'">解除</button></td></tr>').join('')+'</table>';
}
async function saveSecurity(){
  try{
    const r=await api('/api/admin/security',{method:'POST',body:JSON.stringify({
      captcha_after_failures:Number(el.captchaAfterFailures.value),
      max_login_failures:Number(el.maxLoginFailures.value),
      ban_duration_minutes:Number(el.banDurationMinutes.value),
      permanent_ban:el.permanentBan.checked
    })});
    renderSecurity(r.config||{},r.bans||[]);
    el.securityMsg.innerHTML='<div class=ok>风控设置已保存</div>';
  }catch(e){el.securityMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function unbanLogin(id){
  const r=await api('/api/admin/security/unban',{method:'POST',body:JSON.stringify({ban_id:Number(id)})});
  await loadSecurity();
  el.securityMsg.innerHTML='<div class=ok>封禁已解除</div>';
}
async function loadCertificateStatus(){
  const r=await api('/api/admin/certificate');
  renderCertificateStatus(r.certificate||{});
}
function renderCertificateStatus(c){
  if(!el.certStatus)return;
  const names=[...(c.dns_names||[]),...(c.ip_addresses||[])].join(', ')||'-';
  el.certStatus.innerHTML='<div><b>'+esc(c.common_name||'-')+'</b>'+(c.is_self_signed?' <span class=pill>自签证书</span>':' <span class=pill>自定义证书</span>')+'</div><div>签发者：'+esc(c.issuer||'-')+'</div><div>有效期：'+esc(timeText(c.not_before))+' 至 '+esc(timeText(c.not_after))+'</div><div>SAN：'+esc(names)+'</div>';
}
async function uploadCertificate(){
  try{
    if(!el.tlsCertFile.files.length||!el.tlsKeyFile.files.length)throw new Error('请选择证书文件和私钥文件');
    const fd=new FormData();
    fd.append('cert_file',el.tlsCertFile.files[0]);
    fd.append('key_file',el.tlsKeyFile.files[0]);
    const r=await fetch('/api/admin/certificate',{method:'POST',credentials:'same-origin',body:fd});
    const j=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(j.error||r.statusText);
    renderCertificateStatus(j.certificate||{});
    el.tlsCertFile.value='';el.tlsKeyFile.value='';
    el.certMsg.innerHTML='<div class=ok>证书已上传并启用</div>';
  }catch(e){el.certMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
function showAnnouncement(announcement){
  const content=(announcement?.content||'').trim();
  if(!content)return;
  el.announcementContent.innerHTML=esc(content).replace(/\n/g,'<br>');
  el.announcementModal.classList.remove('hidden');
}
async function saveAnnouncement(){
  try{
    const r=await api('/api/admin/announcement',{method:'POST',body:JSON.stringify({content:el.announcementText.value})});
    currentAnnouncement=r.announcement||{};
    renderAnnouncementAdmin();
    el.announcementMsg.innerHTML='<div class=ok>公告已保存</div>';
  }catch(e){el.announcementMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
function renderAnnouncementAdmin(){
  if(!el.announcementText)return;
  el.announcementText.value=currentAnnouncement?.content||'';
  const meta=currentAnnouncement?.updated_at?'上次更新：'+timeText(currentAnnouncement.updated_at):'当前未设置公告';
  el.announcementMeta.textContent=meta;
}
async function loadLogs(){
  if(!me?.is_admin)return;
  const r=await api('/api/admin/logs?limit=300');
  el.adminTaskLog.innerHTML='<table><tr><th>任务</th><th>用户</th><th>状态</th><th>文件</th><th>进度</th><th>NAS</th><th>时间</th></tr>'+(r.jobs||[]).map(j=>{
    const total=(j.stage==='CloudSyncUploading'?(j.cloud_total||j.source_size):(j.transfer_total||j.source_size));
    const done=(j.stage==='CloudSyncUploading'?j.cloud_bytes:j.transfer_bytes);
    return '<tr><td>#'+j.id+'</td><td>'+esc(j.username)+'</td><td>'+esc(stageText(j.stage))+'</td><td>'+esc(j.source_rel_path||j.source_abs_path)+'</td><td>'+bytes(done)+' / '+bytes(total)+'</td><td>'+esc(j.nas_path)+'</td><td>'+esc(timeText(j.created_at))+'</td></tr>';
  }).join('')+'</table>';
  el.adminProgressLog.innerHTML='<table><tr><th>时间</th><th>任务</th><th>用户</th><th>阶段</th><th>进度</th><th>说明</th></tr>'+(r.job_events||[]).map(x=>{
    const total=x.stage==='CloudSyncUploading'?(x.cloud_total||0):(x.transfer_total||0);
    const done=x.stage==='CloudSyncUploading'?(x.cloud_bytes||0):(x.transfer_bytes||0);
    return '<tr><td>'+esc(timeText(x.time))+'</td><td>#'+x.job_id+'</td><td>'+esc(x.username)+'</td><td>'+esc(stageText(x.stage))+'</td><td>'+bytes(done)+' / '+bytes(total)+'</td><td>'+esc(x.message)+'</td></tr>';
  }).join('')+'</table>';
  el.adminAuditLog.innerHTML='<table><tr><th>时间</th><th>用户</th><th>IP</th><th>操作</th><th>详情</th></tr>'+(r.audit||[]).map(x=>'<tr><td>'+esc(timeText(x.time))+'</td><td>'+esc(x.username)+'</td><td>'+esc(x.ip||'-')+'</td><td>'+esc(actionText(x.action))+'</td><td>'+esc(x.details)+'</td></tr>').join('')+'</table>';
}
async function clearLogs(){
  if(!confirm('确认清除操作日志和任务进度流水？任务记录本身会保留。'))return;
  try{
    await api('/api/admin/logs/clear',{method:'POST',body:'{}'});
    el.logsMsg.innerHTML='<div class=ok>日志已清除</div>';
    await loadLogs();
  }catch(e){el.logsMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
function actionText(action){
  return ({
    login:'登录',
    login_failed:'登录失败',
    login_blocked:'登录被封禁拦截',
    change_password:'修改密码',
    create_job:'创建备份任务',
    cancel_job:'取消任务',
    delete_job:'删除任务',
    retry_job:'重试任务',
    refresh_cloud_job:'检查云端状态',
    mark_cloud_completed:'标记云端完成',
    create_user:'创建用户',
    delete_user:'删除用户',
    reset_user_password:'重置用户密码',
    update_user_roots:'修改目录权限',
    update_user_upload_dir:'修改用户上传目录',
    create_root:'添加目录根',
    delete_root:'删除目录根',
    update_synology_config:'修改群晖配置',
    update_announcement:'修改公告',
    clear_logs:'清除日志',
    update_https_certificate:'更新 HTTPS 证书',
    update_login_security:'修改登录风控',
    remove_login_ban:'解除登录封禁',
    update_site_config:'修改网页访问设置',
    update_mail_config:'修改邮件配置',
    send_test_mail:'发送测试邮件',
    update_email_settings:'修改邮箱通知'
  })[action]||action;
}
function parseEmailText(value){return String(value||'').split(/[\n,;]+/).map(x=>x.trim()).filter(Boolean)}
function renderAccountNotifications(){
  if(!me||!el.accountEmails)return;
  el.accountEmails.value=(me.emails||[]).join('\n');
  el.notifyJobDone.checked=!!me.notify_job_done;
  el.notifyAdminLogs.checked=!!me.notify_admin_logs;
}
async function saveAccountNotifications(){
  try{
    const r=await api('/api/account/notifications',{method:'POST',body:JSON.stringify({
      emails:parseEmailText(el.accountEmails.value),
      notify_job_done:el.notifyJobDone.checked,
      notify_admin_logs:el.notifyAdminLogs.checked
    })});
    me=r.user||me;
    renderAccountNotifications();
    el.accountMailMsg.innerHTML='<div class=ok>邮箱设置已保存</div>';
  }catch(e){el.accountMailMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function changePassword(){
  try{
    await api('/api/change-password',{method:'POST',body:JSON.stringify({current_password:el.currentPass.value,new_password:el.newSelfPass.value})});
    el.currentPass.value='';el.newSelfPass.value='';
    el.accountMsg.innerHTML='<div class=ok>密码已修改</div>';
  }catch(e){el.accountMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function jobAction(id,action){
  await api('/api/jobs/action',{method:'POST',body:JSON.stringify({job_id:Number(id),action})});
  await loadJobs();
}
async function deleteRoot(id){
  if(!confirm('确认删除这个目录根？用户授权会同步移除。'))return;
  await api('/api/admin/root-delete',{method:'POST',body:JSON.stringify({root_id:Number(id)})});
  await loadAll();
}
async function deleteUser(id){
  if(!confirm('确认删除这个用户？历史任务会保留。'))return;
  await api('/api/admin/user-delete',{method:'POST',body:JSON.stringify({user_id:Number(id)})});
  await loadAdmin();
}
async function resetUserPassword(id){
  const input=document.querySelector('input[data-reset-user="'+id+'"]');
  const pw=input?.value||'';
  await api('/api/admin/user-password',{method:'POST',body:JSON.stringify({user_id:Number(id),new_password:pw})});
  if(input)input.value='';
  await loadAdmin();
}
function renderSynologyConfig(){
  if(!currentConfig||!el.synoBaseURL)return;
  el.synoBaseURL.value=currentConfig.synology_base_url||'';
  el.synoUsername.value=currentConfig.synology_username||'';
  el.synoPassword.value='';
  el.synoStagingDir.value=currentConfig.synology_staging_dir||'';
  el.synoCloudTargetDir.value=currentConfig.synology_cloud_target_dir||'';
  el.synoVerifyTLS.checked=!!currentConfig.verify_tls;
}
function renderSiteConfig(){
  if(!currentConfig||!el.sitePort)return;
  el.sitePort.value=currentConfig.listen_port||String(currentConfig.listen_addr||':60000').replace(':','')||60000;
  el.publicBaseURL.value=currentConfig.public_base_url||'';
}
async function saveSiteConfig(){
  try{
    const res=await api('/api/admin/site',{method:'POST',body:JSON.stringify({
      listen_addr:':'+Number(el.sitePort.value||60000),
      public_base_url:el.publicBaseURL.value
    })});
    currentConfig={...currentConfig,...res.config};
    renderSiteConfig();
    const restart=res.restart_required?'，重启程序或服务后生效':'';
    el.siteMsg.innerHTML='<div class=ok>访问设置已保存'+restart+'</div>';
  }catch(e){el.siteMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
function renderMailConfig(cfg){
  cfg=cfg||currentConfig||{};
  if(!el.smtpEnabled)return;
  el.smtpEnabled.checked=!!cfg.smtp_enabled;
  el.smtpHost.value=cfg.smtp_host||'';
  el.smtpPort.value=cfg.smtp_port||587;
  el.smtpSecure.value=cfg.smtp_secure||'starttls';
  el.smtpUsername.value=cfg.smtp_username||'';
  el.smtpPassword.value='';
  el.smtpFromEmail.value=cfg.smtp_from_email||'';
  el.smtpFromName.value=cfg.smtp_from_name||'PVE Backup Web';
  el.mailEventJobNASDone.checked=!!cfg.mail_event_job_nas_done;
  el.mailEventJobCloudDone.checked=!!cfg.mail_event_job_cloud_done;
  el.mailEventJobFailed.checked=!!cfg.mail_event_job_failed;
  el.mailEventLoginBan.checked=!!cfg.mail_event_login_ban;
}
async function saveMailConfig(){
  try{
    const res=await api('/api/admin/mail',{method:'POST',body:JSON.stringify({
      smtp_enabled:el.smtpEnabled.checked,
      smtp_host:el.smtpHost.value,
      smtp_port:Number(el.smtpPort.value||587),
      smtp_secure:el.smtpSecure.value,
      smtp_username:el.smtpUsername.value,
      smtp_password:el.smtpPassword.value,
      smtp_from_email:el.smtpFromEmail.value,
      smtp_from_name:el.smtpFromName.value,
      mail_event_job_nas_done:el.mailEventJobNASDone.checked,
      mail_event_job_cloud_done:el.mailEventJobCloudDone.checked,
      mail_event_job_failed:el.mailEventJobFailed.checked,
      mail_event_login_ban:el.mailEventLoginBan.checked
    })});
    currentConfig={...currentConfig,...res.config};
    renderMailConfig(res.config);
    el.mailMsg.innerHTML='<div class=ok>邮件配置已保存</div>';
  }catch(e){el.mailMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function sendTestMail(){
  try{
    const r=await api('/api/admin/mail/test',{method:'POST',body:JSON.stringify({test_to:el.testMailTo.value})});
    el.mailMsg.innerHTML='<div class=ok>测试邮件已发送，共 '+r.sent+' 个收件人</div>';
  }catch(e){el.mailMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function saveSynology(){
  try{
    const res=await api('/api/admin/synology',{method:'POST',body:JSON.stringify({
      synology_base_url:el.synoBaseURL.value,
      synology_username:el.synoUsername.value,
      synology_password:el.synoPassword.value,
      synology_staging_dir:el.synoStagingDir.value,
      synology_cloud_target_dir:el.synoCloudTargetDir.value,
      verify_tls:el.synoVerifyTLS.checked
    })});
    currentConfig=res.config;
    renderSynologyConfig();
    el.synoSummary.textContent='NAS: '+currentConfig.synology_base_url+' → '+currentConfig.synology_cloud_target_dir;
    el.synologyMsg.innerHTML='<div class=ok>群晖配置已保存</div>';
  }catch(e){el.synologyMsg.innerHTML='<div class=error>'+esc(e.message)+'</div>'}
}
async function testSynology(){try{const r=await api('/api/admin/synology');el.synologyInfo.textContent=JSON.stringify(r,null,2)}catch(e){el.synologyInfo.textContent=e.message}}
function connectEvents(){if(eventSource)return;eventSource=new EventSource('/api/events');eventSource.addEventListener('job',ev=>{const j=JSON.parse(ev.data);const i=jobs.findIndex(x=>x.id===j.id);if(i>=0)jobs[i]=j;else jobs.unshift(j);renderJobs()});eventSource.addEventListener('job_deleted',ev=>{const j=JSON.parse(ev.data);jobs=jobs.filter(x=>x.id!==j.id);renderJobs()});eventSource.onerror=()=>{el.status.textContent='实时连接断开，正在重连'}}
document.addEventListener('click',ev=>{
  const btn=ev.target.closest('button[data-action]');
  if(!btn)return;
  if(btn.dataset.action==='open-dir')openDir(btn.dataset.path||'');
  if(btn.dataset.action==='backup-file')createJob(btn.dataset.path||'');
  if(btn.dataset.action==='cancel-job')jobAction(btn.dataset.id,'cancel');
  if(btn.dataset.action==='retry-job')jobAction(btn.dataset.id,'retry');
  if(btn.dataset.action==='refresh-cloud')jobAction(btn.dataset.id,'refresh_cloud');
  if(btn.dataset.action==='mark-cloud-completed')jobAction(btn.dataset.id,'mark_cloud_completed');
  if(btn.dataset.action==='delete-job'&&confirm('确认删除这个任务记录？'))jobAction(btn.dataset.id,'delete');
  if(btn.dataset.action==='delete-root')deleteRoot(btn.dataset.id);
  if(btn.dataset.action==='delete-user')deleteUser(btn.dataset.id);
  if(btn.dataset.action==='reset-user-password')resetUserPassword(btn.dataset.id);
  if(btn.dataset.action==='save-user-upload-dir')saveUserUploadDir(btn.dataset.id);
  if(btn.dataset.action==='unban-login')unbanLogin(btn.dataset.id);
  if(btn.dataset.action==='confirm-announcement')el.announcementModal.classList.add('hidden');
});
bindElements();
boot();
</script>
</body>
</html>`

func init() {
	_ = html.EscapeString
	_ = bufio.ErrInvalidUnreadByte
}
