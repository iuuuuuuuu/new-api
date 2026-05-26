package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/thanhpk/randstr"
)

// Airwallex headers — both for the auth handshake and the webhook callback.
const (
	airwallexHeaderClientId  = "x-client-id"
	airwallexHeaderApiKey    = "x-api-key"
	airwallexHeaderSignature = "x-signature"
	airwallexHeaderTimestamp = "x-timestamp"

	// Webhooks within this skew (seconds) are accepted; anything older is
	// treated as a replay. 5 minutes matches the tolerance suggested in
	// the Airwallex signature-validation docs.
	airwallexWebhookMaxAgeSeconds = 5 * 60

	// Access tokens are valid for 30 min per docs; we refresh a bit early
	// so an in-flight request never hits the boundary.
	airwallexTokenSafetyWindow = 5 * time.Minute
)

// airwallexAdaptor mirrors stripeAdaptor / creemAdaptor — keeping the
// controller code organised around a single instance so tests can swap
// it later if needed.
var airwallexAdaptor = &AirwallexAdaptor{}

type AirwallexAdaptor struct{}

// airwallexTokenCache stores the currently valid access token so we
// don't pay a round-trip to /authentication/login per payment request.
// The token lasts ~30 minutes — see airwallexTokenSafetyWindow.
type airwallexTokenCache struct {
	mu        sync.Mutex
	token     string
	expiresAt time.Time
	// host the token was issued against (so flipping sandbox invalidates it)
	host string
}

var airwallexToken = &airwallexTokenCache{}

// AirwallexPayRequest is the user-facing request body for /api/user/airwallex/pay.
type AirwallexPayRequest struct {
	Amount        int64  `json:"amount"`
	PaymentMethod string `json:"payment_method"`
	// Optional caller-provided redirect; the value is validated against
	// the trusted-redirect domain list before being forwarded to Airwallex.
	ReturnURL string `json:"return_url,omitempty"`
}

// RequestAirwallexAmount computes the displayed total for a given top-up.
func RequestAirwallexAmount(c *gin.Context) {
	var req AirwallexPayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "参数错误"})
		return
	}
	airwallexAdaptor.RequestAmount(c, &req)
}

// RequestAirwallexPay creates the order + remote payment link, returning
// the hosted checkout URL for the client to open.
func RequestAirwallexPay(c *gin.Context) {
	var req AirwallexPayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "参数错误"})
		return
	}
	airwallexAdaptor.RequestPay(c, &req)
}

func (*AirwallexAdaptor) RequestAmount(c *gin.Context, req *AirwallexPayRequest) {
	if req.Amount < getAirwallexMinTopup() {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", getAirwallexMinTopup())})
		return
	}
	userId := c.GetInt("id")
	group, err := model.GetUserGroup(userId, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}
	payMoney := getAirwallexPayMoney(float64(req.Amount), group)
	if payMoney <= 0.01 {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "data": strconv.FormatFloat(payMoney, 'f', 2, 64)})
}

func (*AirwallexAdaptor) RequestPay(c *gin.Context, req *AirwallexPayRequest) {
	ctx := c.Request.Context()
	if !isAirwallexTopUpEnabled() {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "Airwallex 支付未配置"})
		return
	}
	if req.PaymentMethod != model.PaymentMethodAirwallex {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "不支持的支付渠道"})
		return
	}
	if req.Amount < getAirwallexMinTopup() {
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("充值数量不能小于 %d", getAirwallexMinTopup()), "data": 10})
		return
	}
	if req.Amount > 10000 {
		c.JSON(http.StatusOK, gin.H{"message": "充值数量不能大于 10000", "data": 10})
		return
	}
	if req.ReturnURL != "" && common.ValidateRedirectURL(req.ReturnURL) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "支付重定向URL不在可信任域名列表中", "data": ""})
		return
	}

	userId := c.GetInt("id")
	user, _ := model.GetUserById(userId, false)
	if user == nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "用户不存在"})
		return
	}
	chargedMoney := GetChargedAmount(float64(req.Amount), *user)

	reference := fmt.Sprintf("new-api-awx-%d-%d-%s", user.Id, time.Now().UnixMilli(), randstr.String(4))
	tradeNo := "awx_" + common.Sha1([]byte(reference))

	payAmount := getAirwallexPayMoney(float64(req.Amount), user.Group)
	if payAmount <= 0.01 {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}

	returnURL := req.ReturnURL
	if returnURL == "" {
		if strings.TrimSpace(setting.AirwallexReturnUrl) != "" {
			returnURL = strings.TrimSpace(setting.AirwallexReturnUrl)
		} else {
			returnURL = paymentReturnPath("/console/log")
		}
	}

	payLink, err := createAirwallexPaymentLink(ctx, tradeNo, payAmount, setting.AirwallexCurrency, user.Email, returnURL)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex 创建支付链接失败 user_id=%d trade_no=%s amount=%d error=%q", userId, tradeNo, req.Amount, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}

	topUp := &model.TopUp{
		UserId:          userId,
		Amount:          req.Amount,
		Money:           chargedMoney,
		TradeNo:         tradeNo,
		PaymentMethod:   model.PaymentMethodAirwallex,
		PaymentProvider: model.PaymentProviderAirwallex,
		CreateTime:      time.Now().Unix(),
		Status:          common.TopUpStatusPending,
	}
	if err := topUp.Insert(); err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex 创建充值订单失败 user_id=%d trade_no=%s amount=%d error=%q", userId, tradeNo, req.Amount, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "创建订单失败"})
		return
	}
	logger.LogInfo(ctx, fmt.Sprintf("Airwallex 充值订单创建成功 user_id=%d trade_no=%s amount=%d money=%.2f", userId, tradeNo, req.Amount, chargedMoney))
	c.JSON(http.StatusOK, gin.H{
		"message": "success",
		"data": gin.H{
			"pay_link": payLink,
		},
	})
}

// AirwallexWebhook handles Airwallex webhook deliveries. We verify the
// HMAC-SHA256 signature, decode the event and reconcile the order on
// payment_intent.succeeded / failed / cancelled.
func AirwallexWebhook(c *gin.Context) {
	ctx := c.Request.Context()
	if !isAirwallexWebhookEnabled() {
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex webhook 被拒绝 reason=webhook_disabled path=%q client_ip=%s", c.Request.RequestURI, c.ClientIP()))
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex webhook 读取请求体失败 path=%q client_ip=%s error=%q", c.Request.RequestURI, c.ClientIP(), err.Error()))
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}

	timestamp := c.GetHeader(airwallexHeaderTimestamp)
	signature := c.GetHeader(airwallexHeaderSignature)
	if !verifyAirwallexSignature(payload, timestamp, signature, setting.AirwallexWebhookSecret) {
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex webhook 验签失败 path=%q client_ip=%s timestamp=%q signature=%q", c.Request.RequestURI, c.ClientIP(), timestamp, signature))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Reject obviously stale events to mitigate replay attacks.
	if ts, parseErr := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64); parseErr == nil {
		now := time.Now().Unix()
		// Airwallex timestamps are seconds since epoch.
		if now-ts > airwallexWebhookMaxAgeSeconds {
			logger.LogWarn(ctx, fmt.Sprintf("Airwallex webhook 时间戳过期 trade_no_unknown timestamp=%d age=%d", ts, now-ts))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}

	var event struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AccountID string `json:"account_id"`
		Data      struct {
			Object struct {
				ID               string            `json:"id"`
				Amount           float64           `json:"amount"`
				Currency         string            `json:"currency"`
				Status           string            `json:"status"`
				MerchantOrderID  string            `json:"merchant_order_id"`
				Metadata         map[string]string `json:"metadata"`
				LatestPaymentErr struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"latest_payment_attempt"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := common.Unmarshal(payload, &event); err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex webhook JSON 解码失败 client_ip=%s error=%q body=%q", c.ClientIP(), err.Error(), string(payload)))
		// Returning 200 prevents Airwallex from retrying a payload we can
		// never decode; the alternative (loop forever) is worse.
		c.Status(http.StatusOK)
		return
	}

	tradeNo := strings.TrimSpace(event.Data.Object.MerchantOrderID)
	if tradeNo == "" {
		tradeNo = strings.TrimSpace(event.Data.Object.Metadata["trade_no"])
	}
	callerIp := c.ClientIP()
	logger.LogInfo(ctx, fmt.Sprintf("Airwallex webhook 验签成功 event_type=%s event_id=%s trade_no=%s client_ip=%s", event.Name, event.ID, tradeNo, callerIp))

	switch event.Name {
	case "payment_intent.succeeded":
		handleAirwallexSucceeded(ctx, tradeNo, callerIp)
	case "payment_intent.failed", "payment_intent.cancelled":
		handleAirwallexTerminal(ctx, tradeNo, callerIp, event.Name)
	default:
		logger.LogInfo(ctx, fmt.Sprintf("Airwallex webhook 忽略事件 event_type=%s event_id=%s trade_no=%s", event.Name, event.ID, tradeNo))
	}

	c.Status(http.StatusOK)
}

func handleAirwallexSucceeded(ctx context.Context, tradeNo string, callerIp string) {
	if tradeNo == "" {
		logger.LogWarn(ctx, "Airwallex payment_intent.succeeded 缺少订单号")
		return
	}
	LockOrder(tradeNo)
	defer UnlockOrder(tradeNo)
	if err := model.RechargeAirwallex(tradeNo, callerIp); err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex 充值处理失败 trade_no=%s client_ip=%s error=%q", tradeNo, callerIp, err.Error()))
		return
	}
	logger.LogInfo(ctx, fmt.Sprintf("Airwallex 充值成功 trade_no=%s client_ip=%s", tradeNo, callerIp))
}

func handleAirwallexTerminal(ctx context.Context, tradeNo string, callerIp string, eventType string) {
	if tradeNo == "" {
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex %s 缺少订单号 client_ip=%s", eventType, callerIp))
		return
	}
	LockOrder(tradeNo)
	defer UnlockOrder(tradeNo)
	target := common.TopUpStatusFailed
	if eventType == "payment_intent.cancelled" {
		target = common.TopUpStatusExpired
	}
	err := model.UpdatePendingTopUpStatus(tradeNo, model.PaymentProviderAirwallex, target)
	if errors.Is(err, model.ErrTopUpNotFound) {
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex %s 但本地订单不存在 trade_no=%s client_ip=%s", eventType, tradeNo, callerIp))
		return
	}
	if errors.Is(err, model.ErrTopUpStatusInvalid) {
		logger.LogInfo(ctx, fmt.Sprintf("Airwallex %s 但订单状态非 pending，忽略 trade_no=%s client_ip=%s", eventType, tradeNo, callerIp))
		return
	}
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("Airwallex %s 标记订单状态失败 trade_no=%s client_ip=%s error=%q", eventType, tradeNo, callerIp, err.Error()))
		return
	}
	logger.LogInfo(ctx, fmt.Sprintf("Airwallex 订单已标记 trade_no=%s status=%s client_ip=%s", tradeNo, target, callerIp))
}

// verifyAirwallexSignature implements the HMAC-SHA256 scheme from
// the docs: HEX(HMAC_SHA256(secret, timestamp + raw_body)).
func verifyAirwallexSignature(payload []byte, timestamp string, signature string, secret string) bool {
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(signature) == "" || strings.TrimSpace(timestamp) == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// createAirwallexPaymentLink calls POST /api/v1/pa/payment_links/create
// with a one-time link, returning the shareable checkout URL. The
// merchant_order_id field carries our trade_no so the webhook can match
// the resulting payment_intent.succeeded event back to the order.
func createAirwallexPaymentLink(ctx context.Context, tradeNo string, amount float64, currency string, email string, returnURL string) (string, error) {
	if strings.TrimSpace(setting.AirwallexClientId) == "" || strings.TrimSpace(setting.AirwallexApiKey) == "" {
		return "", errors.New("Airwallex API 凭据未配置")
	}
	if amount <= 0 {
		return "", errors.New("无效的支付金额")
	}
	if strings.TrimSpace(currency) == "" {
		currency = "USD"
	}
	token, err := getAirwallexAccessToken(ctx)
	if err != nil {
		return "", err
	}

	body := map[string]any{
		"request_id":       uuid.NewString(),
		"title":            fmt.Sprintf("Top-up %s", tradeNo),
		"amount":           amount,
		"currency":         strings.ToUpper(currency),
		"reusable":         false,
		"merchant_order_id": tradeNo,
		"metadata": map[string]string{
			"trade_no": tradeNo,
		},
	}
	if strings.TrimSpace(returnURL) != "" {
		body["return_url"] = returnURL
	}
	if strings.TrimSpace(email) != "" {
		body["collectable_shopper_info"] = map[string]bool{}
		body["prefill"] = map[string]any{"email": email}
	}

	endpoint := setting.AirwallexApiHost() + "/api/v1/pa/payment_links/create"
	payload, err := common.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("airwallex create payment link returned %d: %s", resp.StatusCode, truncateForLog(string(respBody), 512))
	}

	var parsed struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := common.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("airwallex payment link decode failed: %w (body=%s)", err, truncateForLog(string(respBody), 256))
	}
	if strings.TrimSpace(parsed.URL) == "" {
		return "", fmt.Errorf("airwallex payment link response missing url field (body=%s)", truncateForLog(string(respBody), 256))
	}
	return parsed.URL, nil
}

// getAirwallexAccessToken returns a cached bearer token, refreshing it
// when it's within airwallexTokenSafetyWindow of expiry.
func getAirwallexAccessToken(ctx context.Context) (string, error) {
	airwallexToken.mu.Lock()
	defer airwallexToken.mu.Unlock()

	currentHost := setting.AirwallexApiHost()
	if airwallexToken.host == currentHost && airwallexToken.token != "" &&
		time.Until(airwallexToken.expiresAt) > airwallexTokenSafetyWindow {
		return airwallexToken.token, nil
	}

	endpoint := currentHost + "/api/v1/authentication/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(airwallexHeaderClientId, setting.AirwallexClientId)
	req.Header.Set(airwallexHeaderApiKey, setting.AirwallexApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("airwallex auth returned %d: %s", resp.StatusCode, truncateForLog(string(respBody), 512))
	}

	var parsed struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := common.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("airwallex auth decode failed: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return "", errors.New("airwallex auth response missing token")
	}
	expiry := time.Now().Add(25 * time.Minute)
	if parsed.ExpiresAt != "" {
		// Per docs the value is RFC3339; tolerate other formats by falling back to 25min.
		if parsedTime, parseErr := time.Parse(time.RFC3339, parsed.ExpiresAt); parseErr == nil {
			expiry = parsedTime
		}
	}
	airwallexToken.token = parsed.Token
	airwallexToken.expiresAt = expiry
	airwallexToken.host = currentHost
	return parsed.Token, nil
}

// invalidateAirwallexToken drops the cached token; used by tests + when
// settings change at runtime.
func invalidateAirwallexToken() {
	airwallexToken.mu.Lock()
	defer airwallexToken.mu.Unlock()
	airwallexToken.token = ""
	airwallexToken.expiresAt = time.Time{}
	airwallexToken.host = ""
}

func getAirwallexMinTopup() int64 {
	minTopup := setting.AirwallexMinTopUp
	if operation_setting.GetQuotaDisplayType() == operation_setting.QuotaDisplayTypeTokens {
		minTopup = minTopup * int(common.QuotaPerUnit)
	}
	return int64(minTopup)
}

func getAirwallexPayMoney(amount float64, group string) float64 {
	originalAmount := amount
	if operation_setting.GetQuotaDisplayType() == operation_setting.QuotaDisplayTypeTokens {
		amount = amount / common.QuotaPerUnit
	}
	topupGroupRatio := common.GetTopupGroupRatio(group)
	if topupGroupRatio == 0 {
		topupGroupRatio = 1
	}
	discount := 1.0
	if ds, ok := operation_setting.GetPaymentSetting().AmountDiscount[int(originalAmount)]; ok && ds > 0 {
		discount = ds
	}
	return amount * setting.AirwallexUnitPrice * topupGroupRatio * discount
}

// defaultHTTPClient — shared 30s-timeout client for Airwallex calls.
// Defined here (not in a shared file) to keep this controller's outbound
// HTTP behaviour self-contained; the Stripe SDK has its own client.
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// AirwallexTestRequest lets the admin probe credentials without committing
// them. Empty fields fall back to the saved OptionMap values, so an
// operator can verify a stored API key without retyping the secret.
type AirwallexTestRequest struct {
	ClientId string `json:"client_id"`
	ApiKey   string `json:"api_key"`
	Sandbox  *bool  `json:"sandbox"`
}

// TestAirwallexConnection runs the two-step Airwallex handshake (auth +
// payment_links/create probe) and returns a structured result so the UI
// can show exactly which step failed. This is the easiest way for an
// operator to tell the three common failure modes apart:
//
//   - credentials_invalid          -> wrong env (sandbox vs prod) or bad keys
//   - 401 Insufficient permissions -> keys are valid but lack Payment Links scope
//   - everything OK                -> link URL is returned for click-through
func TestAirwallexConnection(c *gin.Context) {
	ctx := c.Request.Context()
	var req AirwallexTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// An empty body is fine — fall back entirely to saved settings.
		req = AirwallexTestRequest{}
	}

	clientId := strings.TrimSpace(req.ClientId)
	if clientId == "" {
		clientId = setting.AirwallexClientId
	}
	apiKey := strings.TrimSpace(req.ApiKey)
	if apiKey == "" {
		apiKey = setting.AirwallexApiKey
	}
	sandbox := setting.AirwallexSandbox
	if req.Sandbox != nil {
		sandbox = *req.Sandbox
	}

	host := "https://api.airwallex.com"
	if sandbox {
		host = "https://api-demo.airwallex.com"
	}

	result := gin.H{
		"success":          false,
		"auth_ok":          false,
		"payment_link_ok":  false,
		"host":             host,
		"sandbox":          sandbox,
	}

	if clientId == "" || apiKey == "" {
		result["stage"] = "config"
		result["message"] = "Airwallex 凭据未配置（缺少 Client ID 或 API Key）"
		c.JSON(http.StatusOK, result)
		return
	}

	// Step 1: authenticate. This isolates the "wrong environment" /
	// "wrong key" failure mode from the permissions one.
	token, authErr := testAirwallexAuth(ctx, host, clientId, apiKey)
	if authErr != nil {
		result["stage"] = "auth"
		result["message"] = "认证失败：" + airwallexAuthErrorHint(authErr.Error())
		result["detail"] = authErr.Error()
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex 测试连接 认证失败 host=%s error=%q", host, authErr.Error()))
		c.JSON(http.StatusOK, result)
		return
	}
	result["auth_ok"] = true

	// Step 2: probe Payment Links. This is where account-level
	// Payment Acceptance entitlement / key scope shows up.
	linkURL, linkErr := testAirwallexPaymentLink(ctx, host, token)
	if linkErr != nil {
		result["stage"] = "payment_link"
		result["message"] = "创建支付链接失败：" + airwallexLinkErrorHint(linkErr.Error())
		result["detail"] = linkErr.Error()
		logger.LogWarn(ctx, fmt.Sprintf("Airwallex 测试连接 创建支付链接失败 host=%s error=%q", host, linkErr.Error()))
		c.JSON(http.StatusOK, result)
		return
	}
	result["payment_link_ok"] = true
	result["success"] = true
	result["stage"] = "ok"
	result["message"] = "连接成功，凭据可用且具备 Payment Links 权限"
	result["probe_link"] = linkURL
	logger.LogInfo(ctx, fmt.Sprintf("Airwallex 测试连接 成功 host=%s probe_link=%s", host, linkURL))
	c.JSON(http.StatusOK, result)
}

// testAirwallexAuth performs a fresh login call (no shared cache) so the
// probe always reflects the requested credentials, not whatever happens
// to be cached from prior production traffic.
func testAirwallexAuth(ctx context.Context, host, clientId, apiKey string) (string, error) {
	endpoint := host + "/api/v1/authentication/login"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set(airwallexHeaderClientId, clientId)
	httpReq.Header.Set(airwallexHeaderApiKey, apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient().Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, truncateForLog(string(respBody), 512))
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := common.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode failed: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return "", errors.New("response missing token")
	}
	return parsed.Token, nil
}

// testAirwallexPaymentLink creates a small one-time probe link so we can
// confirm the API key actually has Payment Acceptance scope. The link
// is reusable=false and never written to the local DB, so it's safe to
// leave dangling on the Airwallex side.
func testAirwallexPaymentLink(ctx context.Context, host, token string) (string, error) {
	body := map[string]any{
		"request_id":        uuid.NewString(),
		"title":             "new-api connection probe",
		"amount":            1.0,
		"currency":          "USD",
		"reusable":          false,
		"merchant_order_id": "probe_" + uuid.NewString(),
	}
	payload, err := common.Marshal(body)
	if err != nil {
		return "", err
	}
	endpoint := host + "/api/v1/pa/payment_links/create"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := defaultHTTPClient().Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, truncateForLog(string(respBody), 512))
	}
	var parsed struct {
		URL string `json:"url"`
	}
	if err := common.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode failed: %w (body=%s)", err, truncateForLog(string(respBody), 256))
	}
	if strings.TrimSpace(parsed.URL) == "" {
		return "", fmt.Errorf("response missing url (body=%s)", truncateForLog(string(respBody), 256))
	}
	return parsed.URL, nil
}

// airwallexAuthErrorHint surfaces the most common auth-failure causes in
// plain Chinese so the operator doesn't have to read the raw JSON body.
func airwallexAuthErrorHint(raw string) string {
	low := strings.ToLower(raw)
	switch {
	case strings.Contains(low, "credentials_invalid") || strings.Contains(low, "access denied"):
		return "Client ID / API Key 与当前环境不匹配（请检查 Sandbox 开关，或确认 Airwallex 后台的 API Key 仍然有效）"
	case strings.Contains(low, "status=403"):
		return "Airwallex 拒绝该请求（403），可能是 IP 限制或账户未激活"
	case strings.Contains(low, "status=5"):
		return "Airwallex 服务暂时不可用，请稍后重试"
	}
	return "认证接口返回错误"
}

// airwallexLinkErrorHint maps the Insufficient-permissions branch to a
// specific actionable message — this is the case the operator was
// burning hours on.
func airwallexLinkErrorHint(raw string) string {
	low := strings.ToLower(raw)
	switch {
	case strings.Contains(low, "insufficient permissions") || strings.Contains(low, "unauthorized"):
		return "API Key 缺少 Payment Links 权限。请在 Airwallex 后台 Settings > Developer > API keys，编辑该 Key 并勾选 Payment Acceptance（或创建一把带该权限的新 Key）"
	case strings.Contains(low, "merchant") && strings.Contains(low, "not"):
		return "账户未启用 Payment Acceptance / Payment Links 能力，请联系 Airwallex 开通"
	case strings.Contains(low, "status=403"):
		return "Airwallex 拒绝该请求（403），账户或 API Key 可能没有 Payment Links 能力"
	}
	return "Payment Links 接口返回错误"
}
