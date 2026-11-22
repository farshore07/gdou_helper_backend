package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/farshore07/gdou_helper_backend/internal/integration/jwxt"
)

var (
	errStoreFull     = errors.New("当前并发验证请求过多，请稍后重试")
	errTokenNotFound = errors.New("验证会话不存在或已过期，请重新登录")
)

type mfaEntry struct {
	mu        sync.Mutex
	tx        *jwxt.MfaTransaction
	expiresAt time.Time
}

type captchaEntry struct {
	tx        *jwxt.CaptchaTransaction
	expiresAt time.Time
}

// AuthTxStore 管理图形验证码与二次验证的进程内存短期事务态。
type AuthTxStore struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	mfa        map[string]*mfaEntry
	captcha    map[string]*captchaEntry
	stopCh     chan struct{}
	closeOnce  sync.Once
}

// NewAuthTxStore 创建带容量上限与定时过期的内存事务存储。
func NewAuthTxStore(ttl time.Duration, maxEntries int) *AuthTxStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 500
	}
	s := &AuthTxStore{
		ttl:        ttl,
		maxEntries: maxEntries,
		mfa:        make(map[string]*mfaEntry),
		captcha:    make(map[string]*captchaEntry),
		stopCh:     make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close 停止后台清理协程，用于服务优雅停机。
func (s *AuthTxStore) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *AuthTxStore) cleanupLoop() {
	interval := s.ttl / 2
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.evictExpiredLocked(time.Now())
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

func (s *AuthTxStore) evictExpiredLocked(now time.Time) {
	for token, entry := range s.mfa {
		if now.After(entry.expiresAt) {
			delete(s.mfa, token)
		}
	}
	for token, entry := range s.captcha {
		if now.After(entry.expiresAt) {
			delete(s.captcha, token)
		}
	}
}

func (s *AuthTxStore) totalCountLocked() int {
	return len(s.mfa) + len(s.captcha)
}

// PutMFA 保存一个新的二次验证会话并返回随机 token。
func (s *AuthTxStore) PutMFA(tx *jwxt.MfaTransaction) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	if s.totalCountLocked() >= s.maxEntries {
		return "", errStoreFull
	}
	s.mfa[token] = &mfaEntry{
		tx:        tx,
		expiresAt: now.Add(s.ttl),
	}
	return token, nil
}

// AcquireMFA 获取并锁定指定 token 的二次验证事务，防止同一 token 并发操作竞态。
// 调用方必须执行返回的 release(consume) 函数释放锁，consume=true 时销毁该事务。
func (s *AuthTxStore) AcquireMFA(token string) (*jwxt.MfaTransaction, func(consume bool), error) {
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.mfa[token]
	if !ok || now.After(entry.expiresAt) {
		delete(s.mfa, token)
		s.mu.Unlock()
		return nil, nil, errTokenNotFound
	}
	s.mu.Unlock()

	entry.mu.Lock()
	// 再次检查是否已被并发请求销毁或过期
	s.mu.Lock()
	current, exists := s.mfa[token]
	if !exists || current != entry || time.Now().After(entry.expiresAt) {
		delete(s.mfa, token)
		s.mu.Unlock()
		entry.mu.Unlock()
		return nil, nil, errTokenNotFound
	}
	s.mu.Unlock()

	released := false
	release := func(consume bool) {
		if released {
			return
		}
		released = true
		if consume {
			s.mu.Lock()
			if s.mfa[token] == entry {
				delete(s.mfa, token)
			}
			s.mu.Unlock()
		}
		entry.mu.Unlock()
	}
	return entry.tx, release, nil
}

// PutCaptcha 保存图形验证码事务（不保存用户密码）并返回随机 token。
func (s *AuthTxStore) PutCaptcha(tx *jwxt.CaptchaTransaction) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	if s.totalCountLocked() >= s.maxEntries {
		return "", errStoreFull
	}
	s.captcha[token] = &captchaEntry{
		tx:        tx,
		expiresAt: now.Add(s.ttl),
	}
	return token, nil
}

// TakeCaptcha 一次性取出并删除图形验证码事务，防止同一验证码 token 被重放。
func (s *AuthTxStore) TakeCaptcha(token string) (*jwxt.CaptchaTransaction, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.captcha[token]
	if !ok {
		return nil, errTokenNotFound
	}
	delete(s.captcha, token)
	if now.After(entry.expiresAt) {
		return nil, errTokenNotFound
	}
	return entry.tx, nil
}

func generateToken() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
