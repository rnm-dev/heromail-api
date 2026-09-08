package account

import "testing"

func TestPersonalNameValidation(t *testing.T) {
	for _, name := range []string{"admin", "abuse", "a..b", "a@b", "ab", ".abc", "abc-", "мираc", "a b"} {
		if validatePersonalName(name) == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"miras", "miras.s", "miras_01", "miras-test"} {
		if err := validatePersonalName(name); err != nil {
			t.Errorf("rejected %q: %v", name, err)
		}
	}
}
