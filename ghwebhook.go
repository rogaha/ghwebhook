package ghwebhook

import (
	"context"
	"errors"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"database/sql"

	"github.com/google/go-github/github"
)

// Webhook is a receiver for github webhook.
type Webhook struct {
	// Secret is Secret in Github Settings/Webhooks/Manage webhook
	Secret string

	// RestrictAddr enables restrict Service Hook IP Addresses
	// https://help.github.com/articles/github-s-ip-addresses/
	RestrictAddr bool

	// TrustAddrs is the list of trusted IP address (e.g. reverse proxies)
	TrustAddrs []string
	
	// Database
	DB *sql.DB

	CommitComment            func(e *github.CommitCommentEvent, db *sql.DB)
	Create                   func(e *github.CreateEvent, db *sql.DB)
	Delete                   func(e *github.DeleteEvent, db *sql.DB)
	Deployment               func(e *github.DeploymentEvent, db *sql.DB)
	DeploymentStatus         func(e *github.DeploymentStatusEvent, db *sql.DB)
	Fork                     func(e *github.ForkEvent, db *sql.DB)
	Gollum                   func(e *github.GollumEvent, db *sql.DB)
	Installation             func(e *github.InstallationEvent, db *sql.DB)
	InstallationRepositories func(e *github.InstallationRepositoriesEvent, db *sql.DB)
	IssueComment             func(e *github.IssueCommentEvent, db *sql.DB)
	Issues                   func(e *github.IssuesEvent, db *sql.DB)
	Label                    func(e *github.LabelEvent, db *sql.DB)
	Member                   func(e *github.MemberEvent, db *sql.DB)
	Membership               func(e *github.MembershipEvent, db *sql.DB)
	Milestone                func(e *github.MilestoneEvent, db *sql.DB)
	Organization             func(e *github.OrganizationEvent, db *sql.DB)
	OrgBlock                 func(e *github.OrgBlockEvent, db *sql.DB)
	PageBuild                func(e *github.PageBuildEvent, db *sql.DB)
	Ping                     func(e *github.PingEvent, db *sql.DB)
	Project                  func(e *github.ProjectEvent, db *sql.DB)
	ProjectCard              func(e *github.ProjectCardEvent, db *sql.DB)
	ProjectColumn            func(e *github.ProjectColumnEvent, db *sql.DB)
	Public                   func(e *github.PublicEvent, db *sql.DB)
	PullRequestReview        func(e *github.PullRequestReviewEvent, db *sql.DB)
	PullRequestReviewComment func(e *github.PullRequestReviewCommentEvent, db *sql.DB)
	PullRequest              func(e *github.PullRequestEvent, db *sql.DB)
	Push                     func(e *github.PushEvent, db *sql.DB)
	Repository               func(e *github.RepositoryEvent, db *sql.DB)
	Release                  func(e *github.ReleaseEvent, db *sql.DB)
	Status                   func(e *github.StatusEvent, db *sql.DB)
	Team                     func(e *github.TeamEvent, db *sql.DB)
	TeamAdd                  func(e *github.TeamAddEvent, db *sql.DB)
	Watch                    func(e *github.WatchEvent, db *sql.DB)

	mu         sync.RWMutex
	client     *github.Client
	trustAddrs []*net.IPNet
	expiresAt  time.Time
}

func (h *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.RestrictAddr {
		if err := h.updateTrustAddrs(r.Context()); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if err := h.validateAddr(r); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	var payload []byte
	switch t {
	case "application/x-www-form-urlencoded":
		if h.Secret != "" {
			payload, err = github.ValidatePayload(r, []byte(h.Secret))
			if err != nil {
				break
			}
			values, err := url.ParseQuery(string(payload))
			if err != nil {
				break
			}
			payload = []byte(values.Get("payload"))
		} else {
			payload = []byte(r.PostFormValue("payload"))
		}
	case "application/json":
		if h.Secret != "" {
			payload, err = github.ValidatePayload(r, []byte(h.Secret))
		} else {
			payload, err = ioutil.ReadAll(r.Body)
		}
	default:
		err = errors.New("unsupported content type")
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	e, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	go h.handle(e, h.DB)
	w.WriteHeader(http.StatusOK)
}

func (h *Webhook) handle(e interface{}, db *sql.DB) {
	switch e := e.(type) {
	case *github.CommitCommentEvent:
		if h.CommitComment != nil {
			h.CommitComment(e, db)
		}
	case *github.CreateEvent:
		if h.Create != nil {
			h.Create(e, db)
		}
	case *github.DeleteEvent:
		if h.Delete != nil {
			h.Delete(e, db)
		}
	case *github.DeploymentEvent:
		if h.Deployment != nil {
			h.Deployment(e, db)
		}
	case *github.DeploymentStatusEvent:
		if h.DeploymentStatus != nil {
			h.DeploymentStatus(e, db)
		}
	case *github.ForkEvent:
		if h.Fork != nil {
			h.Fork(e, db)
		}
	case *github.GollumEvent:
		if h.Gollum != nil {
			h.Gollum(e, db)
		}
	case *github.InstallationEvent:
		if h.Installation != nil {
			h.Installation(e, db)
		}
	case *github.InstallationRepositoriesEvent:
		if h.InstallationRepositories != nil {
			h.InstallationRepositories(e, db)
		}
	case *github.IssueCommentEvent:
		if h.IssueComment != nil {
			h.IssueComment(e, db)
		}
	case *github.IssuesEvent:
		if h.Issues != nil {
			h.Issues(e, db)
		}
	case *github.LabelEvent:
		if h.Label != nil {
			h.Label(e, db)
		}
	case *github.MemberEvent:
		if h.Member != nil {
			h.Member(e, db)
		}
	case *github.MembershipEvent:
		if h.Membership != nil {
			h.Membership(e, db)
		}
	case *github.MilestoneEvent:
		if h.Milestone != nil {
			h.Milestone(e, db)
		}
	case *github.OrganizationEvent:
		if h.Organization != nil {
			h.Organization(e, db)
		}
	case *github.OrgBlockEvent:
		if h.OrgBlock != nil {
			h.OrgBlock(e, db)
		}
	case *github.PageBuildEvent:
		if h.PageBuild != nil {
			h.PageBuild(e, db)
		}
	case *github.PingEvent:
		if h.Ping != nil {
			h.Ping(e, db)
		}
	case *github.ProjectEvent:
		if h.Project != nil {
			h.Project(e, db)
		}
	case *github.ProjectCardEvent:
		if h.ProjectCard != nil {
			h.ProjectCard(e, db)
		}
	case *github.ProjectColumnEvent:
		if h.ProjectColumn != nil {
			h.ProjectColumn(e, db)
		}
	case *github.PublicEvent:
		if h.Public != nil {
			h.Public(e, db)
		}
	case *github.PullRequestReviewEvent:
		if h.PullRequestReview != nil {
			h.PullRequestReview(e, db)
		}
	case *github.PullRequestReviewCommentEvent:
		if h.PullRequestReviewComment != nil {
			h.PullRequestReviewComment(e, db)
		}
	case *github.PullRequestEvent:
		if h.PullRequest != nil {
			h.PullRequest(e, db)
		}
	case *github.PushEvent:
		if h.Push != nil {
			h.Push(e, db)
		}
	case *github.RepositoryEvent:
		if h.Repository != nil {
			h.Repository(e, db)
		}
	case *github.ReleaseEvent:
		if h.Release != nil {
			h.Release(e, db)
		}
	case *github.StatusEvent:
		if h.Status != nil {
			h.Status(e, db)
		}
	case *github.TeamEvent:
		if h.Team != nil {
			h.Team(e, db)
		}
	case *github.TeamAddEvent:
		if h.TeamAdd != nil {
			h.TeamAdd(e, db)
		}
	case *github.WatchEvent:
		if h.Watch != nil {
			h.Watch(e, db)
		}
	}
}

func (h *Webhook) validateAddr(r *http.Request) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// validate X-Forwarded-For Header
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for _, forwardedIP := range forwarded {
		ip := net.ParseIP(strings.TrimSpace(forwardedIP))
		if err := h.validateIP(ip); err != nil {
			return err
		}
	}

	// validate RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if err := h.validateIP(ip); err != nil {
		return err
	}

	return nil
}

func (h *Webhook) validateIP(ip net.IP) error {
	for _, addr := range h.trustAddrs {
		if addr.Contains(ip) {
			return nil
		}
	}
	return errors.New("untrusted ip")
}

func (h *Webhook) updateTrustAddrs(ctx context.Context) error {
	if h.trustAddrs != nil && h.expiresAt.Before(time.Now()) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.expiresAt.Before(time.Now()) {
		return nil // updated TrustAddrs by another groutine
	}

	trustAddrs := make([]*net.IPNet, 0, len(h.TrustAddrs)+2)
	for _, addr := range h.TrustAddrs {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return err
		}
		trustAddrs = append(trustAddrs, ipNet)
	}

	if h.client == nil {
		h.client = github.NewClient(nil)
	}
	meta, _, err := h.client.APIMeta(ctx)
	if err != nil {
		return err
	}
	for _, addr := range meta.Hooks {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return err
		}
		trustAddrs = append(trustAddrs, ipNet)
	}
	h.trustAddrs = trustAddrs
	h.expiresAt = time.Now().Add(24 * time.Hour)
	return nil
}
