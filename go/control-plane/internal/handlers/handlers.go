package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"omnipanel/control-plane/config"
)

// Routes registers all v1 API routes on a chi router.
func Routes(cfg *config.Config) http.Handler {
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

	return r
}

// placeholder handlers return 501 until implemented.
func notImplemented(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not implemented"}`, http.StatusNotImplemented)
	}
}

var (
	setupAdmin         = notImplemented
	loginAdmin         = notImplemented
	logoutAdmin        = notImplemented
	enableTotp         = notImplemented
	verifyTotp         = notImplemented
	listPlans          = notImplemented
	createPlan         = notImplemented
	getPlan            = notImplemented
	listUsers          = notImplemented
	createUser         = notImplemented
	getUser            = notImplemented
	updateUserStatus   = notImplemented
	suspendUser        = notImplemented
	resumeUser         = notImplemented
	getMyUsage         = notImplemented
	getSubscription    = notImplemented
	listNodes          = notImplemented
	createNode         = notImplemented
	getNode            = notImplemented
	updateNodeAddress  = notImplemented
	quarantineNode     = notImplemented
	rotateNodeSecrets  = notImplemented
	createInbound      = notImplemented
	setInboundEnabled  = notImplemented
	enrollAgent        = notImplemented
	getDesiredState    = notImplemented
	agentReport        = notImplemented
	agentMetering      = notImplemented
	publishStructural  = notImplemented
	rollbackStructural = notImplemented
	declareRecoveryEpoch = notImplemented
	getUsage           = notImplemented
	listCapabilityEvidence = notImplemented
	recordHealthObservation = notImplemented
	getInboundHealth   = notImplemented
	listAlerts         = notImplemented
	listOutboxJobs     = notImplemented
	getXrayConfig      = notImplemented
	listCdnProviders   = notImplemented
	createCdnMapping   = notImplemented
	listRelayNodes     = notImplemented
	createRelayTunnel  = notImplemented
	listWarpPeers      = notImplemented
	configureWarp      = notImplemented
	getBpbPolicy       = notImplemented
	updateBpbPolicy    = notImplemented
)
