package imapservice

import "testing"

func TestSystemFolderAttributes(t *testing.T) {
	for _, name := range []string{"Junk", "Archive", "Trash"} {
		info, err := (&Mailbox{name: name}).Info()
		if err != nil || len(info.Attributes) != 1 || info.Attributes[0] != `\`+name {
			t.Fatalf("%s: %#v %v", name, info, err)
		}
	}
}
