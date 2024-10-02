package util

// Constants for all supported currencies
const (
	USD = "USD"
	INR = "INR"
	EUR = "EUR"
)

// IsSupportedCurrency returns true if the currency is supported
func IsSupportedCurrency(currency string) bool {
	switch currency {
	case USD, INR, EUR:
		return true
	}
	return false
}
