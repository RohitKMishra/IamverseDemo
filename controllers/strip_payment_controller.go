package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/paymentintent"
)

// Set your Stripe API key
func init() {
	stripe.Key = "sk_test_51NVwRcDAx359yF7WXuvItR2GOr9oDvwhGEhHlat6yNQGvGbByzvABt2JUuEcjzGDAQ2Mrg62oD3bbsDDhKRg4e0z00kkX28urh"
}

// PaymentRequest struct for parsing payment request JSON
type PaymentRequest struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// API endpoint to handle payment requests
func MakeStripePayment(c *fiber.Ctx) error {
	// Parse request JSON
	var paymentRequest PaymentRequest
	if err := c.BodyParser(&paymentRequest); err != nil {
		return err
	}

	// Create a PaymentIntent with Stripe
	params := &stripe.PaymentIntentParams{
		Amount:             stripe.Int64(paymentRequest.Amount), // amount in cents
		Currency:           stripe.String(paymentRequest.Currency),
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		return err
	}

	// Return the client secret to the frontend
	return c.JSON(fiber.Map{
		"client_secret": pi.ClientSecret,
	})
}
