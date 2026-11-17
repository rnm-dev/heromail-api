package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// Gmail-style signatures: named HTML signatures belong to the user, and each
// accessible sender picks one for new mail and one for replies/forwards.
// The HTML is stored as untrusted: the web client sanitizes it on every use.
var (
	userSignaturePath     = regexp.MustCompile(`^/signatures(?:/([0-9a-fA-F-]{36}))?$`)
	signatureDefaultsPath = regexp.MustCompile(`^/workspaces/([^/]+)/signature-defaults$`)
)

const (
	signatureNameLimit = 100
	signatureHTMLLimit = 20000
)

type userSignature struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	HTML string `json:"html"`
}

type signatureDefault struct {
	Sender  string  `json:"sender"`
	NewID   *string `json:"new_id"`
	ReplyID *string `json:"reply_id"`
}

func (s *Server) userSignatures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := account.CurrentUser(ctx)
	id := userSignaturePath.FindStringSubmatch(r.URL.Path)[1]
	switch {
	case id == "" && r.Method == http.MethodGet:
		rows, err := s.pool.Query(ctx, `SELECT id,name,html FROM user_signatures WHERE user_id=$1 ORDER BY created_at,id`, user.ID)
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (userSignature, error) {
			var sig userSignature
			return sig, row.Scan(&sig.ID, &sig.Name, &sig.HTML)
		})
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"signatures": list})
	case id == "" && r.Method == http.MethodPost, id != "" && r.Method == http.MethodPut:
		var in userSignature
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&in); err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" || utf8.RuneCountInString(in.Name) > signatureNameLimit || utf8.RuneCountInString(in.HTML) > signatureHTMLLimit {
			writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", "Название обязательно (до 100 символов), подпись — до 20000 символов.")
			return
		}
		var sig userSignature
		var err error
		if id == "" {
			err = s.pool.QueryRow(ctx, `INSERT INTO user_signatures(user_id,name,html) VALUES($1,$2,$3) RETURNING id,name,html`, user.ID, in.Name, in.HTML).Scan(&sig.ID, &sig.Name, &sig.HTML)
		} else {
			err = s.pool.QueryRow(ctx, `UPDATE user_signatures SET name=$3,html=$4,updated_at=now() WHERE id=$1 AND user_id=$2 RETURNING id,name,html`, id, user.ID, in.Name, in.HTML).Scan(&sig.ID, &sig.Name, &sig.HTML)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "signature not found")
			return
		}
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		writeJSON(w, map[bool]int{true: http.StatusCreated, false: http.StatusOK}[id == ""], sig)
	case id != "" && r.Method == http.MethodDelete:
		tag, err := s.pool.Exec(ctx, `DELETE FROM user_signatures WHERE id=$1 AND user_id=$2`, id, user.ID)
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if tag.RowsAffected() == 0 {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "signature not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// signatureDefaults lists or sets, per accessible sender in the workspace,
// which of the user's own signatures is inserted automatically.
func (s *Server) signatureDefaults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, _, err := s.scope(ctx, signatureDefaultsPath.FindStringSubmatch(r.URL.Path)[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(ctx)
	boxes, err := s.inbound.MailboxesForWorkspace(ctx, ws)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	ids := make([]string, len(boxes))
	for i, box := range boxes {
		ids[i] = box.ID
	}
	readable, err := s.inbound.AccessibleMailboxes(ctx, user.ID, ids)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	allowed := []string{}
	for _, box := range boxes {
		if readable[box.ID] {
			allowed = append(allowed, strings.ToLower(box.Address))
		}
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.pool.Query(ctx, `SELECT sender,new_signature_id::text,reply_signature_id::text FROM signature_defaults
 WHERE workspace_id=$1 AND user_id=$2 AND sender=ANY($3) ORDER BY sender`, ws, user.ID, allowed)
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (signatureDefault, error) {
			var d signatureDefault
			return d, row.Scan(&d.Sender, &d.NewID, &d.ReplyID)
		})
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"defaults": list})
	case http.MethodPut:
		var in signatureDefault
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&in); err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
			return
		}
		in.Sender = strings.ToLower(strings.TrimSpace(in.Sender))
		ok := false
		for _, address := range allowed {
			ok = ok || address == in.Sender
		}
		if !ok {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "sender not found")
			return
		}
		// Only the user's own signatures may be referenced.
		var owned bool
		if err := s.pool.QueryRow(ctx, `SELECT count(*)=count(*) FILTER (WHERE user_id=$1) FROM user_signatures WHERE id::text=ANY($2)`,
			user.ID, []string{deref(in.NewID), deref(in.ReplyID)}).Scan(&owned); err != nil || !owned {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "signature not found")
			return
		}
		_, err := s.pool.Exec(ctx, `INSERT INTO signature_defaults(workspace_id,user_id,sender,new_signature_id,reply_signature_id) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(workspace_id,user_id,sender) DO UPDATE SET new_signature_id=EXCLUDED.new_signature_id,reply_signature_id=EXCLUDED.reply_signature_id`,
			ws, user.ID, in.Sender, in.NewID, in.ReplyID)
		if err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", "invalid signature")
			return
		}
		writeJSON(w, http.StatusOK, in)
	default:
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or PUT")
	}
}
