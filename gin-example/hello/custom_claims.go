package hello

import (
	"context"
	"fmt"
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	// Name         string `json:"name"`
	// Username     string `json:"username"`
	// ShouldReject bool   `json:"shouldReject,omitempty"`
	Issuer string `json:"iss"`
	Scope string `json:"scope"`
}

// Validate errors out if `ShouldReject` is true.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	// if c.ShouldReject {
	// 	return errors.New("should reject was set to true")
	// }
	fmt.Println("C: %v", c)
	return nil
}
