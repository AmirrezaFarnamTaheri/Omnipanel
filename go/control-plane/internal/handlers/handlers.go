package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"omnipanel/control-plane/internal/auth"
	"omnipanel/control-plane/internal/crypto"
	"omnipanel/control-plane/config"
	"omnipanel/control-plane/internal/store"
)

// ---------- response helpers ----------

func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

// ---------- context keys ----------

type storeKey struct{}

// ---------- identity ----------

func setupAdmin(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Email      string `json:"email"`
			Password   string `json:"password"`
			SetupToken string `json:"setup_token"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Email == "" || req.Password == "" || req.SetupToken == "" {
			jsonError(w, http.StatusBadRequest, "email, password, and setup_token are required")
			return
		}
		if cfg.SetupToken != "" && req.SetupToken != cfg.SetupToken {
			jsonError(w, http.StatusUnauthorized, "invalid setup token")
			return
		}

		var count int
		err = r.Context().Value(storeKey{}).(*store.Store).Pool().QueryRow(r.Context(), "SELECT COUNT(*) FROM admins").Scan(&count)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if count > 0 {
			jsonError(w, http.StatusConflict, "setup already completed")
			return
		}

		hash, err := crypto.HashPassword(req.Password)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "password hashing failed")
			return
		}

		var adminID int32
		err = r.Context().Value(storeKey{}).(*store.Store).Pool().QueryRow(r.Context(), `
			INSERT INTO admins (email, password_hash, role, totp_secret_enc, totp_enabled, created_at)
			VALUES ($1, $2, 'owner', NULL, false, now())
			RETURNING id
		`, req.Email, hash).Scan(&adminID)
		if err != nil {
			jsonError(w, http.StatusConflict, "admin with this email already exists")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"admin_id": adminID,
			"email":    req.Email,
			"role":     "owner",
		})
	}
}

func loginAdmin(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		var passwordHash, role string
		var adminID int32
		err = r.Context().Value(storeKey{}).(*store.Store).Pool().QueryRow(r.Context(), `
			SELECT id, password_hash, role FROM admins WHERE email = $1
		`, req.Email).Scan(&adminID, &passwordHash, &role)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		ok, err := crypto.VerifyPassword(passwordHash, req.Password)
		if err != nil || !ok {
			jsonError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		tokenHash := crypto.Hash256([]byte(req.Email + req.Password + time.Now().String()))
		expiresAt := time.Now().Add(12 * time.Hour)

		var sessionID int32
		err = r.Context().Value(storeKey{}).(*store.Store).Pool().QueryRow(r.Context(), `
			INSERT INTO admin_sessions (admin_id, token_hash, expires_at)
			VALUES ($1, $2, $3)
			RETURNING id
		`, adminID, tokenHash, expiresAt).Scan(&sessionID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "session creation failed")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "omni_session",
			Value:    tokenHash,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.PublicURL != "",
			SameSite: http.SameSiteLaxMode,
			Expires:  expiresAt,
		})

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"admin_id": adminID,
			"role":     role,
		})
	}
}

func logoutAdmin(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("omni_session")
		if err == nil {
			_, _ = r.Context().Value(storeKey{}).(*store.Store).Pool().Exec(r.Context(), "DELETE FROM admin_sessions WHERE token_hash = $1", cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "omni_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		jsonResponse(w, http.StatusOK, map[string]string{"status": "logged out"})
	}
}

func enableTotp(cfg *config.Config) http.HandlerFunc {
	return notImplemented
}

func verifyTotp(cfg *config.Config) http.HandlerFunc {
	return notImplemented
}

// ---------- plans ----------

func listPlans(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, name, quota_bytes, enforcement, created_at FROM plans ORDER BY id`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type planOut struct {
			ID         int32     `json:"id"`
			Name       string    `json:"name"`
			QuotaBytes int64     `json:"quota_bytes,omitempty"`
			Enforcement string    `json:"enforcement"`
			CreatedAt  time.Time `json:"created_at"`
		}
		var plans []planOut
		for rows.Next() {
			var p planOut
			var quota pgtype.Int8
			if err := rows.Scan(&p.ID, &p.Name, &quota, &p.Enforcement, &p.CreatedAt); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			p.QuotaBytes = quota.Int64
			plans = append(plans, p)
		}
		jsonResponse(w, http.StatusOK, plans)
	}
}

func createPlan(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Name       string  `json:"name"`
			QuotaGB    float64 `json:"quota_gb"`
			Enforcement string `json:"enforcement"`
			IdemKey    string  `json:"idem_key"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Name == "" || req.IdemKey == "" {
			jsonError(w, http.StatusBadRequest, "name and idem_key are required")
			return
		}
		if req.Enforcement == "" {
			req.Enforcement = "metered"
		}

		var quotaBytes int64
		if req.QuotaGB > 0 {
			quotaBytes = int64(req.QuotaGB * 1024 * 1024 * 1024)
		}

		s := storeFromCtx(r)
		var planID int32
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			var existing string
			err := s.Pool().QueryRow(r.Context(), `SELECT key FROM idempotency_records WHERE scope = 'plan' AND key = $1`, req.IdemKey).Scan(&existing)
			if err == nil {
				return errors.New("idempotency key already used")
			}

			err = s.Pool().QueryRow(r.Context(), `
				INSERT INTO plans (name, quota_bytes, enforcement, created_at)
				VALUES ($1, $2, $3, now())
				RETURNING id
			`, req.Name, quotaBytes, req.Enforcement).Scan(&planID)
			if err != nil {
				return err
			}

			_, err = s.Pool().Exec(r.Context(), `
				INSERT INTO idempotency_records (scope, key, request_hash, response, created_at)
				VALUES ('plan', $1, $2, '{}', now())
			`, req.IdemKey, crypto.Hash256([]byte(req.Name)))
			return err
		})
		if err != nil {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"id": planID, "name": req.Name})
	}
}

func getPlan(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid plan id")
			return
		}

		s := storeFromCtx(r)
		var name, enforcement string
		var quota pgtype.Int8
		var createdAt time.Time
		err = s.Pool().QueryRow(r.Context(), `SELECT name, quota_bytes, enforcement, created_at FROM plans WHERE id = $1`, id).Scan(&name, &quota, &enforcement, &createdAt)
		if err != nil {
			jsonError(w, http.StatusNotFound, "plan not found")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":           id,
			"name":         name,
			"quota_bytes":  quota.Int64,
			"enforcement":  enforcement,
			"created_at":   createdAt,
		})
	}
}

// ---------- users ----------

func listUsers(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, name, email, plan_id, status, suspend_reason, expires_at, version, created_at, updated_at FROM users ORDER BY id`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type userOut struct {
			ID            int32     `json:"id"`
			Name          string    `json:"name"`
			Email         string    `json:"email,omitempty"`
			PlanID          int32     `json:"plan_id"`
			Status        string    `json:"status"`
			SuspendReason string    `json:"suspend_reason,omitempty"`
			ExpiresAt     time.Time `json:"expires_at,omitempty"`
			Version       int32     `json:"version"`
			CreatedAt     time.Time `json:"created_at"`
			UpdatedAt     time.Time `json:"updated_at"`
		}
		var users []userOut
		for rows.Next() {
			var u userOut
			var email sql.NullString
			var suspendReason sql.NullString
			var expiresAt sql.NullTime
			if err := rows.Scan(&u.ID, &u.Name, &email, &u.PlanID, &u.Status, &suspendReason, &expiresAt, &u.Version, &u.CreatedAt, &u.UpdatedAt); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			u.Email = email.String
			u.SuspendReason = suspendReason.String
			u.ExpiresAt = expiresAt.Time
			users = append(users, u)
		}
		jsonResponse(w, http.StatusOK, users)
	}
}

func createUser(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Name    string `json:"name"`
			Email   string `json:"email"`
			PlanID  int32  `json:"plan_id"`
			IdemKey string `json:"idem_key"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Name == "" || req.PlanID == 0 || req.IdemKey == "" {
			jsonError(w, http.StatusBadRequest, "name, plan_id, and idem_key are required")
			return
		}

		s := storeFromCtx(r)
		var userID int32
		var token string
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			var existing string
			err := s.Pool().QueryRow(r.Context(), `SELECT key FROM idempotency_records WHERE scope = 'user' AND key = $1`, req.IdemKey).Scan(&existing)
			if err == nil {
				return errors.New("idempotency key already used")
			}

			err = s.Pool().QueryRow(r.Context(), `
				INSERT INTO users (name, email, plan_id, status, version, created_at, updated_at)
				VALUES ($1, $2, $3, 'active', 1, now(), now())
				RETURNING id
			`, req.Name, req.Email, req.PlanID).Scan(&userID)
			if err != nil {
				return err
			}

			tokenRaw := crypto.Hash256([]byte(fmt.Sprintf("%d:%s:%d", userID, req.IdemKey, time.Now().UnixNano())))
			token = "omni_" + tokenRaw[:16]
			tokenHash := crypto.Hash256([]byte(token))
			_, err = s.Pool().Exec(r.Context(), `
				INSERT INTO subscription_tokens (user_id, token_hash, prefix, created_at)
				VALUES ($1, $2, $3, now())
			`, userID, tokenHash, "omni")
			if err != nil {
				return err
			}

			_, err = s.Pool().Exec(r.Context(), `
				INSERT INTO idempotency_records (scope, key, request_hash, response, created_at)
				VALUES ('user', $1, $2, '{}', now())
			`, req.IdemKey, crypto.Hash256([]byte(req.Name+req.Email)))
			return err
		})
		if err != nil {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"user_id": userID,
			"token":   token,
		})
	}
}

func getUser(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		s := storeFromCtx(r)
		var name, status string
		var planID int32
		var email sql.NullString
		var suspendReason sql.NullString
		var expiresAt sql.NullTime
		var version int32
		var createdAt, updatedAt time.Time
		err = s.Pool().QueryRow(r.Context(), `SELECT name, email, plan_id, status, suspend_reason, expires_at, version, created_at, updated_at FROM users WHERE id = $1`, id).Scan(&name, &email, &planID, &status, &suspendReason, &expiresAt, &version, &createdAt, &updatedAt)
		if err != nil {
			jsonError(w, http.StatusNotFound, "user not found")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":             id,
			"name":           name,
			"email":          email.String,
			"plan_id":        planID,
			"status":         status,
			"suspend_reason": suspendReason.String,
			"expires_at":     expiresAt.Time,
			"version":        version,
			"created_at":     createdAt,
			"updated_at":     updatedAt,
		})
	}
}

func updateUserStatus(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Status != "active" && req.Status != "suspended" && req.Status != "expired" {
			jsonError(w, http.StatusBadRequest, "invalid status")
			return
		}

		s := storeFromCtx(r)
		_, err = s.Pool().Exec(r.Context(), `
			UPDATE users SET status = $2, suspend_reason = $3, updated_at = now(), version = version + 1
			WHERE id = $1
		`, id, req.Status, req.Reason)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "update failed")
			return
		}

		// Queue outbox job
		payloadBytes, _ := json.Marshal(map[string]interface{}{"user_id": id, "status": req.Status})
		_, _ = s.Pool().Exec(r.Context(), `
			INSERT INTO outbox_jobs (kind, payload, status, attempts, run_after, created_at)
			VALUES ('quota.evaluate', $1, 'pending', 0, now(), now())
		`, string(payloadBytes))

		jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func suspendUser(cfg *config.Config) http.HandlerFunc {
	return updateUserStatus(cfg)
}

func resumeUser(cfg *config.Config) http.HandlerFunc {
	return updateUserStatus(cfg)
}

func getMyUsage(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.SessionFromContext(r.Context())
		if !ok {
			jsonError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"user_id":    sess.AdminID,
			"total_up":   0,
			"total_down": 0,
			"suspended":  false,
		})
	}
}

// ---------- subscription ----------

func getSubscription(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "token")
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "singbox"
		}

		tokenHash := crypto.Hash256([]byte(token))
		var userID int32
		err := storeFromCtx(r).Pool().QueryRow(r.Context(), `
			SELECT st.user_id FROM subscription_tokens st
			WHERE st.token_hash = $1 AND st.revoked_at IS NULL
		`, tokenHash).Scan(&userID)
		if err != nil {
			jsonError(w, http.StatusNotFound, "token not found or revoked")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"format": format,
			"config": fmt.Sprintf("# subscription for user %d (format: %s)\n# placeholder config\n", userID, format),
		})
	}
}

// ---------- infrastructure ----------

func listNodes(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, name, public_address, provider, asn, region, status, node_key_hash, last_seen_at, agent_version, structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components, created_at FROM nodes ORDER BY id`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type nodeOut struct {
			ID                 int32     `json:"id"`
			Name               string    `json:"name"`
			PublicAddress      string    `json:"public_address"`
			Provider           string    `json:"provider"`
			ASN                string    `json:"asn"`
			Region             string    `json:"region"`
			Status             string    `json:"status"`
			StructuralSeq      int32     `json:"structural_seq"`
			MembershipSeq      int32     `json:"membership_seq"`
			AppliedState       string    `json:"applied_state"`
			CreatedAt          time.Time `json:"created_at"`
		}
		var nodes []nodeOut
		for rows.Next() {
			var n nodeOut
			var keyHash sql.NullString
			var lastSeen sql.NullTime
			var agentVersion sql.NullString
			var appliedEpoch sql.NullInt32
			var appliedState sql.NullString
			var components []byte
			if err := rows.Scan(&n.ID, &n.Name, &n.PublicAddress, &n.Provider, &n.ASN, &n.Region, &n.Status,
				&keyHash, &lastSeen, &agentVersion, &n.StructuralSeq, &n.MembershipSeq,
				&appliedEpoch, &n.AppliedStructuralSeq, &n.AppliedMembershipSeq, &appliedState,
				&components, &n.CreatedAt); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			n.AppliedState = appliedState.String
			nodes = append(nodes, n)
		}
		jsonResponse(w, http.StatusOK, nodes)
	}
}

func createNode(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Name    string `json:"name"`
			Address string `json:"address"`
			Provider string `json:"provider"`
			ASN     string `json:"asn"`
			Region  string `json:"region"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Name == "" || req.Address == "" || req.Provider == "" {
			jsonError(w, http.StatusBadRequest, "name, address, and provider are required")
			return
		}
		if strings.HasPrefix(req.Address, "127.") || req.Address == "localhost" {
			jsonError(w, http.StatusUnprocessableEntity, "loopback address not allowed")
			return
		}

		s := storeFromCtx(r)
		var nodeID int32
		var token string
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			err := s.Pool().QueryRow(r.Context(), `
				INSERT INTO nodes (name, public_address, provider, asn, region, status, created_at)
				VALUES ($1, $2, $3, $4, $5, 'pending_enrollment', now())
				RETURNING id
			`, req.Name, req.Address, req.Provider, req.ASN, req.Region).Scan(&nodeID)
			if err != nil {
				return err
			}

			enrollTokenRaw := crypto.Hash256([]byte(fmt.Sprintf("%d:%s:%d", nodeID, req.Name, time.Now().UnixNano())))
			token = "omni-enroll_" + enrollTokenRaw[:24]
			tokenHash := crypto.Hash256([]byte(token))
			expiresAt := time.Now().Add(24 * time.Hour)
			_, err = s.Pool().Exec(r.Context(), `
				INSERT INTO enrollment_tokens (node_id, token_hash, expires_at)
				VALUES ($1, $2, $3)
			`, nodeID, tokenHash, expiresAt)
			return err
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "node creation failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"node_id": nodeID,
			"token":   token,
		})
	}
}

func getNode(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}

		s := storeFromCtx(r)
		var name, address, provider, asn, region, status string
		var createdAt time.Time
		err = s.Pool().QueryRow(r.Context(), `SELECT name, public_address, provider, asn, region, status, created_at FROM nodes WHERE id = $1`, id).Scan(&name, &address, &provider, &asn, &region, &status, &createdAt)
		if err != nil {
			jsonError(w, http.StatusNotFound, "node not found")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":           id,
			"name":         name,
			"public_address": address,
			"provider":     provider,
			"asn":          asn,
			"region":       region,
			"status":       status,
			"created_at":   createdAt,
		})
	}
}

func updateNodeAddress(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}

		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if strings.HasPrefix(req.Address, "127.") || req.Address == "localhost" {
			jsonError(w, http.StatusUnprocessableEntity, "loopback address not allowed")
			return
		}

		s := storeFromCtx(r)
		var name, address, provider, asn, region, status string
		err = s.Pool().QueryRow(r.Context(), `
			UPDATE nodes SET public_address = $2 WHERE id = $1
			RETURNING name, public_address, provider, asn, region, status
		`, id, req.Address).Scan(&name, &address, &provider, &asn, &region, &status)
		if err != nil {
			jsonError(w, http.StatusNotFound, "node not found")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":           id,
			"name":         name,
			"public_address": address,
			"provider":     provider,
			"asn":          asn,
			"region":       region,
			"status":       status,
		})
	}
}

func quarantineNode(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}

		s := storeFromCtx(r)
		_, err = s.Pool().Exec(r.Context(), `
			UPDATE nodes SET status = 'quarantined', node_key_hash = NULL WHERE id = $1
		`, id)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "quarantine failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"affected": 1})
	}
}

func rotateNodeSecrets(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}

		s := storeFromCtx(r)
		var principalID, inboundID int32
		err := s.Pool().QueryRow(r.Context(), `
			SELECT ep.id, ep.inbound_id FROM endpoint_principals ep
			JOIN inbounds i ON i.id = ep.inbound_id
			WHERE i.node_id = $1 AND ep.state = 'active'
			LIMIT 1
		`, id).Scan(&principalID, &inboundID)
		if err != nil {
			jsonError(w, http.StatusNotFound, "no active principal to rotate")
			return
		}

		credRaw := crypto.Hash256([]byte(fmt.Sprintf("%d:%d:%d", principalID, id, time.Now().UnixNano())))
		newCredential := "omni-cred_" + credRaw[:24]
		credEnc, err := crypto.Encrypt(cfg.KEK, []byte(newCredential))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "encryption failed")
			return
		}

		_, err = s.Pool().Exec(r.Context(), `
			UPDATE endpoint_principals SET state = 'revoked', revoked_at = now() WHERE id = $1
		`, principalID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "revoke failed")
			return
		}

		_, err = s.Pool().Exec(r.Context(), `
			INSERT INTO endpoint_principals (user_id, inbound_id, attribution_key, credential_enc, state, created_at)
			SELECT user_id, $2, $3, $4, 'active', now()
			FROM endpoint_principals WHERE id = $1
		`, principalID, inboundID, "rotated_"+crypto.Hash256([]byte(newCredential))[:16], string(credEnc))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "insert failed")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"principal_id":   principalID,
			"new_credential": newCredential,
		})
	}
}

func createInbound(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeIDStr := chi.URLParam(r, "id")
		nodeID, err := strconv.ParseInt(nodeIDStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}

		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Name      string            `json:"name"`
			Runtime   string            `json:"runtime"`
			Protocol  string            `json:"protocol"`
			Transport string            `json:"transport"`
			Port      int32             `json:"port"`
			SNI       string            `json:"sni"`
			Params    map[string]string `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Name == "" || req.Runtime == "" || req.Protocol == "" || req.Transport == "" || req.Port == 0 || req.SNI == "" {
			jsonError(w, http.StatusBadRequest, "name, runtime, protocol, transport, port, and sni are required")
			return
		}

		paramsJSON, _ := json.Marshal(req.Params)
		secretsJSON, _ := json.Marshal(map[string]string{})

		s := storeFromCtx(r)
		var inboundID int32
		err = s.Pool().QueryRow(r.Context(), `
			INSERT INTO inbounds (node_id, name, runtime, protocol, transport, port, sni, params, secrets, enabled, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, now())
			RETURNING id
		`, nodeID, req.Name, req.Runtime, req.Protocol, req.Transport, req.Port, req.SNI, string(paramsJSON), string(secretsJSON)).Scan(&inboundID)
		if err != nil {
			if strings.Contains(err.Error(), "inbounds_listener_uq") {
				jsonError(w, http.StatusConflict, "listener conflict (node + transport + port already exists)")
				return
			}
			jsonError(w, http.StatusInternalServerError, "inbound creation failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":        inboundID,
			"node_id":   nodeID,
			"name":      req.Name,
			"runtime":   req.Runtime,
			"protocol":  req.Protocol,
			"transport": req.Transport,
			"port":      req.Port,
			"sni":       req.SNI,
			"enabled":   true,
		})
	}
}

func setInboundEnabled(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid inbound id")
			return
		}

		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		s := storeFromCtx(r)
		_, err = s.Pool().Exec(r.Context(), `UPDATE inbounds SET enabled = $2 WHERE id = $1`, id, req.Enabled)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "update failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

// ---------- agent protocol ----------

func enrollAgent(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		tokenHash := crypto.Hash256([]byte(req.Token))
		var nodeID int32
		s := storeFromCtx(r)
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			err := s.Pool().QueryRow(r.Context(), `
				SELECT et.node_id FROM enrollment_tokens et
				WHERE et.token_hash = $1 AND et.used_at IS NULL AND et.expires_at > now()
			`, tokenHash).Scan(&nodeID)
			if err != nil {
				return errors.New("invalid or expired enrollment token")
			}

			_, err = s.Pool().Exec(r.Context(), `UPDATE enrollment_tokens SET used_at = now() WHERE token_hash = $1`, tokenHash)
			if err != nil {
				return err
			}

			nodeKeyRaw := crypto.Hash256([]byte(fmt.Sprintf("%d:%s:%d", nodeID, req.Token, time.Now().UnixNano())))
			_, err = s.Pool().Exec(r.Context(), `
				UPDATE nodes SET node_key_hash = $2, status = 'active', last_seen_at = now() WHERE id = $1
			`, nodeID, crypto.Hash256(nodeKeyRaw[:32]))
			if err != nil {
				return err
			}

			// Return node key as base64url of the raw hash
			_ = nodeKeyRaw
			return nil
		})
		if err != nil {
			jsonError(w, http.StatusUnauthorized, err.Error())
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"node_id": nodeID,
			"node_key": base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", nodeID))),
			"epoch":   1,
		})
	}
}

func getDesiredState(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token, ok := auth.StripBearer(authHeader)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 {
			jsonError(w, http.StatusUnauthorized, "invalid agent token format")
			return
		}

		nodeID, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid node id")
			return
		}

		nodeKeyHash := crypto.Hash256([]byte(parts[1]))
		var valid bool
		s := storeFromCtx(r)
		err = s.Pool().QueryRow(r.Context(), `SELECT node_key_hash = $2 FROM nodes WHERE id = $1 AND status = 'active'`, nodeID, nodeKeyHash).Scan(&valid)
		if err != nil || !valid {
			jsonError(w, http.StatusUnauthorized, "invalid agent credentials")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"epoch": 1,
			"structural": map[string]interface{}{
				"sequence":  0,
				"digest":    "",
				"manifest":  map[string]interface{}{},
				"signature": "",
			},
			"membership": map[string]interface{}{
				"mode":     "snapshot",
				"sequence": 0,
				"principals": []interface{}{},
			},
		})
	}
}

func agentReport(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			NodeID        int32       `json:"node_id"`
			Epoch         int32       `json:"epoch"`
			StructuralSeq int32       `json:"structural_seq"`
			MembershipSeq int32       `json:"membership_seq"`
			State         string      `json:"state"`
			Components    []interface{} `json:"components"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		s := storeFromCtx(r)
		componentsJSON, _ := json.Marshal(req.Components)
		_, err = s.Pool().Exec(r.Context(), `
			INSERT INTO deployment_attempts (node_id, epoch, structural_seq, state, components, reported_at)
			VALUES ($1, $2, $3, $4, $5, now())
		`, req.NodeID, req.Epoch, req.StructuralSeq, req.State, string(componentsJSON))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "report failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "accepted"})
	}
}

func agentMetering(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			NodeID       int32 `json:"node_id"`
			Observations []struct {
				AttributionKey   string `json:"attribution_key"`
				Generation       string `json:"generation"`
				Seq              int64  `json:"seq"`
				Up               int64  `json:"up"`
				Down             int64  `json:"down"`
				GenerationStart  bool   `json:"generation_start"`
			} `json:"observations"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		accepted := 0
		duplicate := 0
		conflict := 0
		probeExcluded := 0

		s := storeFromCtx(r)
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			for _, obs := range req.Observations {
				if strings.HasPrefix(obs.AttributionKey, "probe-") {
					probeExcluded++
					continue
				}

				var streamID int32
				var lastSeq int64
				err := s.Pool().QueryRow(r.Context(), `
					SELECT id, last_seq FROM meter_streams
					WHERE node_id = $1 AND attribution_key = $2 AND generation = $3
				`, req.NodeID, obs.AttributionKey, obs.Generation).Scan(&streamID, &lastSeq)
				if err != nil {
					err = s.Pool().QueryRow(r.Context(), `
						INSERT INTO meter_streams (node_id, attribution_key, generation, user_id, last_seq, last_up, last_down, started_at, updated_at)
						VALUES ($1, $2, $3, NULL, $4, 0, 0, now(), now())
						RETURNING id
					`, req.NodeID, obs.AttributionKey, obs.Generation, obs.Seq).Scan(&streamID)
					if err != nil {
						return err
					}
					lastSeq = obs.Seq - 1
				}

				if obs.Seq <= lastSeq {
					duplicate++
					continue
				}
				if obs.Seq != lastSeq+1 {
					conflict++
				}

				_, err = s.Pool().Exec(r.Context(), `
					INSERT INTO meter_observations (stream_id, seq, up, down, delta_up, delta_down, classification, observed_at, received_at)
					VALUES ($1, $2, $3, $4, $5, $6, 'accepted', now(), now())
				`, streamID, obs.Seq, obs.Up, obs.Down, obs.Up, obs.Down)
				if err != nil {
					return err
				}

				_, err = s.Pool().Exec(r.Context(), `
					UPDATE meter_streams SET last_seq = $2, last_up = $3, last_down = $4, updated_at = now() WHERE id = $1
				`, streamID, obs.Seq, obs.Up, obs.Down)
				if err != nil {
					return err
				}
				accepted++
			}
			return nil
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "metering failed")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"accepted":       accepted,
			"duplicate":      duplicate,
			"conflict":       conflict,
			"probe_excluded": probeExcluded,
		})
	}
}

// ---------- revisions ----------

func publishStructural(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			NodeID               int32  `json:"node_id"`
			RollbackOfSequence   int32  `json:"rollback_of_sequence"`
			Force                bool   `json:"force"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		s := storeFromCtx(r)
		var revID int32
		var sequence int32
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			var latestSeq int32
			err := s.Pool().QueryRow(r.Context(), `SELECT COALESCE(MAX(sequence), 0) FROM structural_revisions WHERE node_id = $1`, req.NodeID).Scan(&latestSeq)
			if err != nil {
				return err
			}
			sequence = latestSeq + 1

			if req.RollbackOfSequence > 0 {
				err = s.Pool().QueryRow(r.Context(), `
					INSERT INTO structural_revisions (node_id, epoch, sequence, digest, manifest, disruption, rollback_of, created_by, created_at)
					VALUES ($1, 1, $2, $3, $4, 'reload', $5, 'operator', now())
					RETURNING id
				`, req.NodeID, sequence, crypto.Hash256([]byte(fmt.Sprintf("rollback:%d", sequence))), `{}`, req.RollbackOfSequence).Scan(&revID)
				return err
			}

			err = s.Pool().QueryRow(r.Context(), `
				INSERT INTO structural_revisions (node_id, epoch, sequence, digest, manifest, disruption, rollback_of, created_by, created_at)
				VALUES ($1, 1, $2, $3, $4, 'none', NULL, 'operator', now())
				RETURNING id
			`, req.NodeID, sequence, crypto.Hash256([]byte(fmt.Sprintf("structural:%d", sequence))), `{"version":1}`).Scan(&revID)
			return err
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "publish failed")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":        revID,
			"node_id":   req.NodeID,
			"epoch":     1,
			"sequence":  sequence,
			"digest":    crypto.Hash256([]byte(fmt.Sprintf("structural:%d", sequence))),
			"disruption": "none",
		})
	}
}

func rollbackStructural(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			NodeID              int32  `json:"node_id"`
			RollbackOfSequence  int32  `json:"rollback_of_sequence"`
			Force               bool   `json:"force"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		s := storeFromCtx(r)
		var revID int32
		var sequence int32
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			var latestSeq int32
			err := s.Pool().QueryRow(r.Context(), `SELECT COALESCE(MAX(sequence), 0) FROM structural_revisions WHERE node_id = $1`, req.NodeID).Scan(&latestSeq)
			if err != nil {
				return err
			}
			sequence = latestSeq + 1

			err = s.Pool().QueryRow(r.Context(), `
				INSERT INTO structural_revisions (node_id, epoch, sequence, digest, manifest, disruption, rollback_of, created_by, created_at)
				VALUES ($1, 1, $2, $3, $4, 'reload', $5, 'operator', now())
				RETURNING id
			`, req.NodeID, sequence, crypto.Hash256([]byte(fmt.Sprintf("rollback:%d", sequence))), `{}`, req.RollbackOfSequence).Scan(&revID)
			return err
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "rollback failed")
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":          revID,
			"node_id":     req.NodeID,
			"epoch":       1,
			"sequence":    sequence,
			"rollback_of": req.RollbackOfSequence,
		})
	}
}

func declareRecoveryEpoch(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Reason == "" {
			jsonError(w, http.StatusBadRequest, "reason is required")
			return
		}

		s := storeFromCtx(r)
		var newEpoch int32
		err = s.Tx(r.Context(), func(pgx.Tx) error {
			err := s.Pool().QueryRow(r.Context(), `SELECT COALESCE(MAX(epoch), 0) + 1 FROM nodes`).Scan(&newEpoch)
			if err != nil {
				return err
			}
			_, err = s.Pool().Exec(r.Context(), `UPDATE nodes SET applied_epoch = NULL WHERE applied_epoch IS NOT NULL`)
			return err
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "recovery epoch failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"epoch": newEpoch})
	}
}

// ---------- accounting ----------

func getUsage(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "userId")
		userID, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		s := storeFromCtx(r)
		var up, down int64
		err = s.Pool().QueryRow(r.Context(), `
			SELECT COALESCE(SUM(up), 0), COALESCE(SUM(down), 0)
			FROM usage_aggregates WHERE user_id = $1
		`, userID).Scan(&up, &down)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"user_id":   userID,
			"total_up":  up,
			"total_down": down,
		})
	}
}

func listCapabilityEvidence(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, capability_key, claim, status, note, recorded_at FROM capability_evidence ORDER BY recorded_at DESC`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type evidenceOut struct {
			ID            int32     `json:"id"`
			CapabilityKey string    `json:"capability_key"`
			Claim         string    `json:"claim"`
			Status        string    `json:"status"`
			Note          string    `json:"note"`
			RecordedAt    time.Time `json:"recorded_at"`
		}
		var items []evidenceOut
		for rows.Next() {
			var e evidenceOut
			if err := rows.Scan(&e.ID, &e.CapabilityKey, &e.Claim, &e.Status, &e.Note, &e.RecordedAt); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			items = append(items, e)
		}
		jsonResponse(w, http.StatusOK, items)
	}
}

// ---------- health ----------

func recordHealthObservation(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req struct {
			NodeID    int32  `json:"node_id"`
			InboundID int32  `json:"inbound_id"`
			Vantage   string `json:"vantage"`
			Level     string `json:"level"`
			OK        bool   `json:"ok"`
			LatencyMs int32  `json:"latency_ms"`
			Detail    string `json:"detail"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		s := storeFromCtx(r)
		_, err = s.Pool().Exec(r.Context(), `
			INSERT INTO health_observations (node_id, inbound_id, vantage, level, ok, latency_ms, detail, observed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		`, req.NodeID, req.InboundID, req.Vantage, req.Level, req.OK, req.LatencyMs, req.Detail)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "observation failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "recorded"})
	}
}

func getInboundHealth(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		inboundID, err := strconv.ParseInt(idStr, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid inbound id")
			return
		}

		s := storeFromCtx(r)
		var state string
		var since time.Time
		err = s.Pool().QueryRow(r.Context(), `SELECT state, since FROM inbound_health WHERE inbound_id = $1`, inboundID).Scan(&state, &since)
		if err != nil {
			jsonError(w, http.StatusNotFound, "inbound health not found")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"inbound_id": inboundID,
			"state":      state,
			"since":      since,
		})
	}
}

func listAlerts(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, severity, kind, node_id, message, dedupe_key, created_at, resolved_at FROM alerts ORDER BY created_at DESC`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type alertOut struct {
			ID        int32     `json:"id"`
			Severity  string    `json:"severity"`
			Kind      string    `json:"kind"`
			NodeID    int32     `json:"node_id,omitempty"`
			Message   string    `json:"message"`
			DedupeKey string    `json:"dedupe_key"`
			CreatedAt time.Time `json:"created_at"`
			ResolvedAt time.Time `json:"resolved_at,omitempty"`
		}
		var items []alertOut
		for rows.Next() {
			var a alertOut
			var nodeID sql.NullInt32
			var resolvedAt sql.NullTime
			if err := rows.Scan(&a.ID, &a.Severity, &a.Kind, &nodeID, &a.Message, &a.DedupeKey, &a.CreatedAt, &resolvedAt); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			if nodeID.Valid { a.NodeID = nodeID.Int32 }
			a.ResolvedAt = resolvedAt.Time
			items = append(items, a)
		}
		jsonResponse(w, http.StatusOK, items)
	}
}

// ---------- outbox ----------

func listOutboxJobs(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := storeFromCtx(r)
		rows, err := s.Pool().Query(r.Context(), `SELECT id, kind, payload, status, attempts, run_after, created_at, done_at, last_error FROM outbox_jobs ORDER BY id DESC LIMIT 100`)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "query failed")
			return
		}
		defer rows.Close()

		type jobOut struct {
			ID        int32     `json:"id"`
			Kind      string    `json:"kind"`
			Payload   string    `json:"payload"`
			Status    string    `json:"status"`
			Attempts  int32     `json:"attempts"`
			RunAfter  time.Time `json:"run_after"`
			CreatedAt time.Time `json:"created_at"`
			DoneAt    time.Time `json:"done_at,omitempty"`
			LastError string    `json:"last_error,omitempty"`
		}
		var items []jobOut
		for rows.Next() {
			var j jobOut
			var doneAt sql.NullTime
			var lastError sql.NullString
			if err := rows.Scan(&j.ID, &j.Kind, &j.Payload, &j.Status, &j.Attempts, &j.RunAfter, &j.CreatedAt, &doneAt, &lastError); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan failed")
				return
			}
			j.DoneAt = doneAt.Time
			j.LastError = lastError.String
			items = append(items, j)
		}
		jsonResponse(w, http.StatusOK, items)
	}
}

// ---------- M2 ----------

func getXrayConfig(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeIDStr := chi.URLParam(r, "nodeId")
		if _, err := strconv.ParseInt(nodeIDStr, 10, 32); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid node id")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"node_id": nodeIDStr,
			"config":  map[string]interface{}{},
			"note":    "Xray config generation not yet implemented",
		})
	}
}

func listCdnProviders(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, []map[string]interface{}{
			{"id": "cloudflare", "name": "Cloudflare", "supported": true},
			{"id": "fastly", "name": "Fastly", "supported": true},
			{"id": "aws_cloudfront", "name": "AWS CloudFront", "supported": true},
		})
	}
}

func createCdnMapping(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"id":     1,
			"status": "pending",
			"note":   "CDN mapping not yet implemented",
		})
	}
}

func listRelayNodes(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, []map[string]interface{}{})
	}
}

func createRelayTunnel(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status": "pending",
			"note":   "Relay tunnel not yet implemented",
		})
	}
}

func listWarpPeers(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, []map[string]interface{}{})
	}
}

func configureWarp(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status": "pending",
			"note":   "WARP configuration not yet implemented",
		})
	}
}

func getBpbPolicy(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"bandwidth_limit": 0,
			"priority":        0,
			"note":            "BPB policy not yet implemented",
		})
	}
}

func updateBpbPolicy(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status": "updated",
			"note":   "BPB policy not yet implemented",
		})
	}
}

// ---------- helpers ----------

func notImplemented(w http.ResponseWriter, r *http.Request) {
	jsonError(w, http.StatusNotImplemented, "not implemented")
}

func storeFromCtx(r *http.Request) *store.Store {
	return r.Context().Value(storeKey{}).(*store.Store)
}

func cfgFromCtx(r *http.Request) *config.Config {
	return r.Context().Value(cfgKey{}).(*config.Config)
}

// ---------- route registration ----------

// Routes registers all v1 API routes on a chi router.
// Store and config are injected into request context by the router middleware.
func Routes(cfg *config.Config, s *store.Store) http.Handler {
	r := chi.NewRouter()

	// Identity
	r.Route("/auth", func(r chi.Router) {
		r.Post("/setup", setupAdmin(cfg))
		r.Post("/login", loginAdmin(cfg))
		r.Post("/logout", logoutAdmin(cfg))
		r.Route("/totp", func(r chi.Router) {
			r.Post("/enable", enableTotp(cfg))
			r.Post("/verify", verifyTotp(cfg))
		})
	})

	// Plans
	r.Route("/plans", func(r chi.Router) {
		r.Get("/", listPlans(cfg))
		r.Post("/", createPlan(cfg))
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", getPlan(cfg))
		})
	})

	// Users
	r.Route("/users", func(r chi.Router) {
		r.Get("/", listUsers(cfg))
		r.Post("/", createUser(cfg))
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", getUser(cfg))
			r.Patch("/", updateUserStatus(cfg))
			r.Post("/suspend", suspendUser(cfg))
			r.Post("/resume", resumeUser(cfg))
		})
		r.Get("/me/usage", getMyUsage(cfg))
	})

	// Subscription (public, agent-facing)
	r.Route("/sub", func(r chi.Router) {
		r.Get("/{token}", getSubscription(cfg))
	})

	// Infrastructure
	r.Route("/infrastructure/nodes", func(r chi.Router) {
		r.Get("/", listNodes(cfg))
		r.Post("/", createNode(cfg))
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", getNode(cfg))
			r.Put("/address", updateNodeAddress(cfg))
			r.Post("/quarantine", quarantineNode(cfg))
			r.Post("/rotate-secrets", rotateNodeSecrets(cfg))
			r.Post("/inbounds", createInbound(cfg))
		})
	})
	r.Route("/infrastructure/inbounds/{id}/enable", func(r chi.Router) {
		r.Put("/", setInboundEnabled(cfg))
	})

	// Agent protocol
	r.Route("/agent", func(r chi.Router) {
		r.Post("/enroll", enrollAgent(cfg))
		r.Get("/desired", getDesiredState(cfg))
		r.Post("/report", agentReport(cfg))
		r.Post("/metering", agentMetering(cfg))
	})

	// Revisions
	r.Route("/revisions", func(r chi.Router) {
		r.Post("/structural", publishStructural(cfg))
		r.Post("/rollback", rollbackStructural(cfg))
		r.Post("/recovery-epoch", declareRecoveryEpoch(cfg))
	})

	// Accounting
	r.Route("/accounting", func(r chi.Router) {
		r.Get("/usage/{userId}", getUsage(cfg))
		r.Get("/capability-evidence", listCapabilityEvidence(cfg))
	})

	// Health
	r.Route("/health", func(r chi.Router) {
		r.Post("/observations", recordHealthObservation(cfg))
		r.Route("/inbounds/{id}", func(r chi.Router) {
			r.Get("/", getInboundHealth(cfg))
		})
		r.Get("/alerts", listAlerts(cfg))
	})

	// Outbox
	r.Route("/outbox", func(r chi.Router) {
		r.Get("/jobs", listOutboxJobs(cfg))
	})

	// M2: Integrated platform
	r.Route("/m2", func(r chi.Router) {
		r.Get("/xray/config/{nodeId}", getXrayConfig(cfg))
		r.Route("/cdn", func(r chi.Router) {
			r.Get("/providers", listCdnProviders(cfg))
			r.Post("/mapping", createCdnMapping(cfg))
		})
		r.Route("/relay", func(r chi.Router) {
			r.Get("/nodes", listRelayNodes(cfg))
			r.Post("/tunnel", createRelayTunnel(cfg))
		})
		r.Route("/warp", func(r chi.Router) {
			r.Get("/peers", listWarpPeers(cfg))
			r.Post("/configure", configureWarp(cfg))
		})
		r.Route("/bpb", func(r chi.Router) {
			r.Get("/policy", getBpbPolicy(cfg))
			r.Post("/policy", updateBpbPolicy(cfg))
		})
	})

	// 404
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	})

	_ = s // store is available via context middleware
	return r
}
