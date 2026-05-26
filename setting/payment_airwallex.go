package setting

// Airwallex top-up settings.
//
// Integration target: Airwallex Payment Links API
// (POST /api/v1/pa/payment_links/create). The server creates a one-time
// hosted checkout link, returns its URL to the browser, and reconciles
// the resulting payment via the payment_intent.succeeded webhook.
//
// Two environments are exposed (demo / prod) so operators can switch
// without changing host code; per Airwallex docs the only difference is
// the API host: https://api-demo.airwallex.com vs https://api.airwallex.com.
var (
	AirwallexClientId      = ""
	AirwallexApiKey        = ""
	AirwallexWebhookSecret = ""
	// AirwallexSandbox routes all API calls to api-demo.airwallex.com when true.
	AirwallexSandbox = true
	// AirwallexCurrency is the 3-letter ISO 4217 code used on every link.
	// Airwallex requires this per request; we default to USD because the
	// rest of new-api treats USD as the canonical pricing currency.
	AirwallexCurrency = "USD"
	// AirwallexUnitPrice is how much of the configured currency to charge
	// per 1 USD of recharge quota. Mirrors StripeUnitPrice / WaffoUnitPrice.
	AirwallexUnitPrice = 1.0
	AirwallexMinTopUp  = 1
	// AirwallexReturnUrl, when set, overrides the default success/cancel
	// redirect (which lands the shopper on /console/log).
	AirwallexReturnUrl = ""
)

// AirwallexApiHost returns the API host for the active environment.
func AirwallexApiHost() string {
	if AirwallexSandbox {
		return "https://api-demo.airwallex.com"
	}
	return "https://api.airwallex.com"
}
