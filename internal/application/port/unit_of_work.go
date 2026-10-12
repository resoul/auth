package port

import "context"

// Stores is the set of repositories bound to one transaction. It is valid only
// inside the callback of UnitOfWork.Do. The groups tell which part of the service
// owns a repository; the fields are promoted, so a use case writes st.Users.
type Stores struct {
	AccountStores
	InfraStores
	AdminStores
	OIDCStores
}

// AccountStores hold the sign-in side: who the users are, how they proved it, and
// the sessions that came out of it.
type AccountStores struct {
	Flows       FlowRepository
	Users       UserRepository
	Recognized  RecognizedClientRepository
	Sessions    SessionRepository
	Tokens      RefreshTokenRepository
	Credentials CredentialRepository
	Challenges  ChallengeRepository
	Tickets     TicketRepository
	Recovery    RecoveryCodeRepository
	Invitations InvitationRepository
	Devices     DeviceRequestRepository
}

// InfraStores serve every use case: mail jobs, the audit trail and rate limits.
type InfraStores struct {
	Outbox     Outbox
	Audit      AuditLog
	AuditReads AuditReader
	Limiter    Limiter
}

// AdminStores hold the admin API's own data, kept apart from the users' sessions
// and credentials. Admin use cases also read AccountStores, for example to block a user.
type AdminStores struct {
	Operators          OperatorRepository
	OperatorSessions   OperatorSessionRepository
	OperatorChallenges ChallengeRepository
}

// OIDCStores hold the OpenID Provider's own data: clients, requests, the shared sign-in and what clients hold on it.
// Anything that ends a user's access (revoke all, recovery, a block) also ends OPSessions.RevokeAllForUser.
type OIDCStores struct {
	OIDCClients  OIDCClientRepository
	OIDCRequests OIDCRequestRepository
	OPSessions   OIDCSessionRepository
	OIDCGrants   OIDCGrantRepository
	OIDCCodes    OIDCCodeRepository
	OIDCRefresh  OIDCRefreshRepository
	OIDCLogout   OIDCLogoutRepository
	// OIDCResources are the APIs tokens are issued for; OIDCApps is what users have connected.
	OIDCResources OIDCResourceRepository
	OIDCApps      OIDCAppRepository
}

// UnitOfWork runs fn in one transaction. A nil result commits; an error rolls
// everything back. An expected denial is a result of the use case and fn returns
// nil, so protective changes (a spent attempt, an expired flow) are committed.
// fn must not start another transaction; the transaction is not passed through ctx.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, s Stores) error) error
}
