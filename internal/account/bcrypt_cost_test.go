package account

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Guards the production work factor; tests themselves run at MinCost.
func TestProductionBcryptCost(t *testing.T) {
	if got := bcryptCostFor(false); got != bcrypt.DefaultCost {
		t.Fatalf("production bcrypt cost = %d, want %d", got, bcrypt.DefaultCost)
	}
}
