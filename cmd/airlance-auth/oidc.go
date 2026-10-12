package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"airlance.org/auth/internal/bootstrap"
	"airlance.org/auth/internal/config"
)

// newOIDCCommand manages the clients of the OpenID Provider. It is run on the server by the operator and talks to the
// database directly: there is no registration API.
func newOIDCCommand() *cobra.Command {
	oidc := &cobra.Command{
		Use:   "oidc",
		Short: "Manage the OpenID Provider (needs AIRLANCE_AUTH_DATABASE_URL)",
	}
	client := &cobra.Command{Use: "client", Short: "Register and manage the applications that sign users in through this provider"}
	run := func(cmd *cobra.Command, req bootstrap.OIDCClientRequest) error {
		cfg, err := config.Load(os.LookupEnv)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return bootstrap.OIDCClient(ctx, cfg, req, cmd.OutOrStdout())
	}

	create := &cobra.Command{
		Use:   "create ID",
		Short: "Register a first-party application, or a service with --service, and print its secret once",
		Long: "Registers a confidential web client with a backend: it authenticates with client_secret_basic and PKCE. " +
			"The ID is lower-case letters, digits, '-' and '_'. Redirect URIs are matched exactly and must be https " +
			"(http only for localhost).",
		Args: cobra.ExactArgs(1),
	}
	name := create.Flags().String("name", "", "the application's name (required)")
	redirects := create.Flags().StringArray("redirect-uri", nil, "an exact return address; repeat for more (required)")
	scopes := create.Flags().StringArray("scope", nil, "a scope the application may ask for; repeat for more (default: openid and email)")
	postLogout := create.Flags().StringArray("post-logout-redirect-uri", nil, "an exact address the browser may be sent to after logging out; repeat for more")
	backchannel := create.Flags().String("backchannel-logout-uri", "", "the application backend's address that is told when a sign-in ends (optional)")
	service := create.Flags().Bool("service", false, "register a service identity for the client_credentials grant: no redirect URIs, scopes or logout settings")
	create.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCClientRequest{
			Action: bootstrap.OIDCClientCreate, ID: args[0], Name: *name, RedirectURIs: *redirects, Scopes: *scopes,
			PostLogoutURIs: *postLogout, BackchannelURI: *backchannel, Service: *service,
		})
	}

	setLogout := &cobra.Command{
		Use:   "set-logout ID",
		Short: "Replace where an application is sent after logout and where it is told that a sign-in ended",
		Long: "Replaces both settings: what is not given is cleared. The back-channel address is called by this server, " +
			"so it must be https (http only for localhost) and, if it is on an internal network, listed in AIRLANCE_AUTH_OIDC_BACKCHANNEL_ALLOW.",
		Args: cobra.ExactArgs(1),
	}
	slPost := setLogout.Flags().StringArray("post-logout-redirect-uri", nil, "an exact return address; repeat for more")
	slBack := setLogout.Flags().String("backchannel-logout-uri", "", "the back-channel logout address; empty for none")
	setLogout.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCClientRequest{Action: bootstrap.OIDCClientLogout, ID: args[0], PostLogoutURIs: *slPost, BackchannelURI: *slBack})
	}

	rotate := &cobra.Command{
		Use:   "rotate-secret ID",
		Short: "Issue a new secret; the old ones keep working for the overlap",
		Args:  cobra.ExactArgs(1),
	}
	overlap := rotate.Flags().Duration("overlap", 24*time.Hour, "how long the previous secrets keep working, so the application can be redeployed")
	rotate.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCClientRequest{Action: bootstrap.OIDCClientRotate, ID: args[0], Overlap: *overlap})
	}

	simple := func(use, short string, action bootstrap.OIDCClientAction, args cobra.PositionalArgs) *cobra.Command {
		return &cobra.Command{
			Use: use, Short: short, Args: args,
			RunE: func(cmd *cobra.Command, a []string) error {
				req := bootstrap.OIDCClientRequest{Action: action}
				if len(a) == 1 {
					req.ID = a[0]
				}
				return run(cmd, req)
			},
		}
	}
	client.AddCommand(create, setLogout, rotate,
		simple("list", "List the registered applications", bootstrap.OIDCClientList, cobra.NoArgs),
		simple("disable ID", "Stop an application from signing users in and revoke every grant it holds", bootstrap.OIDCClientDisable, cobra.ExactArgs(1)),
		simple("enable ID", "Let a disabled application sign users in again (old grants stay revoked)", bootstrap.OIDCClientEnable, cobra.ExactArgs(1)),
	)
	oidc.AddCommand(client, newOIDCResourceCommand())
	return oidc
}

// newOIDCResourceCommand manages the APIs that access tokens are issued for, and what each application may ask of them.
func newOIDCResourceCommand() *cobra.Command {
	resource := &cobra.Command{
		Use:   "resource",
		Short: "Register the APIs tokens are issued for and decide what each application may ask of them",
		Long: "An application is registered with `oidc client`; an API (resource) is registered here, with its own audience and the " +
			"scopes its owner defined. An application may ask for a resource only after `oidc resource allow`.",
	}
	run := func(cmd *cobra.Command, req bootstrap.OIDCResourceRequest) error {
		cfg, err := config.Load(os.LookupEnv)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return bootstrap.OIDCResource(ctx, cfg, req, cmd.OutOrStdout())
	}

	register := &cobra.Command{
		Use:   "register ID",
		Short: "Register an API",
		Long: "The ID is lower-case letters, digits, '-' and '_'. The URI is the value applications send as the resource " +
			"parameter: absolute, https (http only for localhost), without a query or a fragment. The audience is the aud of " +
			"every token issued for it, such as platform-api; it differs from every other resource's and from every client_id. " +
			"Scopes are namespaced and lower-case, such as messages:send; one resource may stand for one service or for the common " +
			"API of several.",
		Args: cobra.ExactArgs(1),
	}
	name := register.Flags().String("name", "", "the API's name (required)")
	uri := register.Flags().String("uri", "", "the resource URI (required)")
	audience := register.Flags().String("audience", "", "the audience of its access tokens (required)")
	scopes := register.Flags().StringArray("scope", nil, "a scope of the API; repeat for more (required)")
	register.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: args[0], Name: *name, URI: *uri, Audience: *audience, Scopes: *scopes})
	}

	setScopes := &cobra.Command{
		Use:   "set-scopes ID",
		Short: "Replace the scopes an API defines",
		Long: "Replaces the whole list. A scope that is taken away is taken from every application that was allowed it, and every " +
			"grant that holds it is ended. A scope that is added is allowed to no application until `oidc resource allow`.",
		Args: cobra.ExactArgs(1),
	}
	ssScopes := setScopes.Flags().StringArray("scope", nil, "a scope of the API; repeat for more (required)")
	setScopes.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceSetScopes, ID: args[0], Scopes: *ssScopes})
	}

	allow := &cobra.Command{
		Use:   "allow RESOURCE",
		Short: "Allow an application to ask for scopes of an API",
		Long: "Replaces what the application was allowed of this resource. Rights taken away end the application's grants that hold " +
			"them; rights added reach authorizations made afterwards, never a grant that exists.",
		Args: cobra.ExactArgs(1),
	}
	alClient := allow.Flags().String("client", "", "the application's client ID (required)")
	alScopes := allow.Flags().StringArray("scope", nil, "a scope the application may ask; repeat for more (required)")
	allow.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: args[0], ClientID: *alClient, Scopes: *alScopes})
	}

	deny := &cobra.Command{
		Use:   "deny RESOURCE",
		Short: "Take every right of an API from an application and end its grants that hold it",
		Args:  cobra.ExactArgs(1),
	}
	dnClient := deny.Flags().String("client", "", "the application's client ID (required)")
	deny.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceDeny, ID: args[0], ClientID: *dnClient})
	}

	rotateSecret := &cobra.Command{
		Use:   "rotate-secret ID",
		Short: "Issue a secret the API introspects tokens with; the old ones keep working for the overlap",
		Args:  cobra.ExactArgs(1),
	}
	rsOverlap := rotateSecret.Flags().Duration("overlap", 24*time.Hour, "how long the previous secrets keep working, so the API can be redeployed")
	rotateSecret.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRotate, ID: args[0], Overlap: *rsOverlap})
	}

	simple := func(use, short string, action bootstrap.OIDCResourceAction, args cobra.PositionalArgs) *cobra.Command {
		return &cobra.Command{
			Use: use, Short: short, Args: args,
			RunE: func(cmd *cobra.Command, a []string) error {
				req := bootstrap.OIDCResourceRequest{Action: action}
				if len(a) == 1 {
					req.ID = a[0]
				}
				return run(cmd, req)
			},
		}
	}
	resource.AddCommand(register, setScopes, allow, deny, rotateSecret,
		simple("list", "List the APIs and what applications may ask of them", bootstrap.OIDCResourceList, cobra.NoArgs),
		simple("disable ID", "Stop issuing tokens for an API and end every grant that holds it", bootstrap.OIDCResourceDisable, cobra.ExactArgs(1)),
		simple("enable ID", "Issue tokens for a disabled API again (ended grants stay ended)", bootstrap.OIDCResourceEnable, cobra.ExactArgs(1)),
	)
	return resource
}
