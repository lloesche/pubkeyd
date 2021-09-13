package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
	"strings"

	"github.com/fatz/ghpubkey-go/ghpubkey"
	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"github.com/oswell/onelogin-go"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type RoleList map[string][]string

var (
	log              = logging.MustGetLogger("pubkeyd")
	users            map[string]string
	roles 					 RoleList
	refreshMutex     = &sync.RWMutex{}
	pubkeyCache      *cache.Cache
	ol               *onelogin.OneLogin
	manualRefresh    chan (bool)
	metricKnownUsers = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pubkeyd_known_users",
		Help: "Number of currently known users.",
	})
	metricOneLoginRefreshesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pubkeyd_onelogin_refreshes_total",
		Help: "Number of OneLogin users refreshes.",
	})
	metricAuthorizedKeysRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pubkeyd_authorized_keys_requests_total",
		Help: "Number of authorized_keys requests, partitioned by status code and HTTP method.",
	}, []string{"code", "method"},
	)
	metricGithubNameRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pubkeyd_github_name_requests_total",
		Help: "Number of github_name requests, partitioned by status code and HTTP method.",
	}, []string{"code", "method"},
	)
)

func init() {
	prometheus.MustRegister(metricKnownUsers)
	prometheus.MustRegister(metricOneLoginRefreshesTotal)
	prometheus.MustRegister(metricAuthorizedKeysRequestsTotal)
	prometheus.MustRegister(metricGithubNameRequestsTotal)
}

// main function to boot up everything
func main() {
	shard := flag.String("shard", flagFromEnv("SHARD"), "OneLogin shard [env SHARD]")
	clientID := flag.String("client-id", flagFromEnv("CLIENT_ID"), "OneLogin Client ID [env CLIENT_ID]")
	clientSecret := flag.String("client-secret", flagFromEnv("CLIENT_SECRET"), "OneLogin Client Secret [env CLIENT_SECRET]")
	subdomain := flag.String("subdomain", flagFromEnv("SUBDOMAIN"), "OneLogin Subdomain [env SUBDOMAIN]")
	refreshInterval := flag.Int("refresh", 900, "OneLogin refresh interval in seconds")
	auth := flag.String("auth", flagFromEnv("AUTH"), "Authentication Token [env AUTH]")
	refreshAuth := flag.String("refresh-auth", flagFromEnv("REFRESH_AUTH"), "OneLogin Cache Refresh Authentication Token [env REFRESH_AUTH]")
	port := flag.Int("port", 2020, "TCP port to listen on")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	flag.Parse()

	loglevel := logging.ERROR
	if *verbose {
		loglevel = logging.DEBUG
	}

	if *clientID == "" || *clientSecret == "" {
		log.Error("Args client-id and client-secret are required")
		os.Exit(1)
	}
	ol = onelogin.New(*shard, *clientID, *clientSecret, *subdomain, loglevel)

	if err := refreshOneLoginUsers(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	refreshTicker := time.NewTicker(time.Duration(*refreshInterval) * time.Second)
	quit := make(chan struct{})
	manualRefresh = make(chan bool)
	go func() {
		for {
			select {
			case <-refreshTicker.C:
				refreshOneLoginUsers()
			case <-manualRefresh:
				refreshOneLoginUsers()
			case <-quit:
				refreshTicker.Stop()
				return
			}
		}
	}()

	pubkeyCache = cache.New(2*time.Minute, 10*time.Minute)
	router := mux.NewRouter()
	listenOn := ":" + strconv.Itoa(*port)
	router.HandleFunc("/health", getHealth).Methods("GET")
	router.PathPrefix("/metrics").Handler(promhttp.Handler())
	// fixme: refactor this
	if *auth == "" {
		router.HandleFunc("/authorized_keys/{id}", getAuthorizedKeys).Methods("GET")
		router.HandleFunc("/role_authorized_keys/{role}", getRoleAuthorizedKeys).Methods("GET")
		router.HandleFunc("/authorized_keys/{id}", deleteAuthorizedKeys).Methods("DELETE")
		router.HandleFunc("/github_name/{id}", getGithubName).Methods("GET")
	} else {
		router.HandleFunc("/authorized_keys/{id}", getAuthorizedKeys).Methods("GET").Queries("auth", *auth)
		router.HandleFunc("/authorized_keys/{id}", deleteAuthorizedKeys).Methods("DELETE").Queries("auth", *auth)
		router.HandleFunc("/github_name/{id}", getGithubName).Methods("GET").Queries("auth", *auth)
	}
	if *refreshAuth == "" {
		if *auth == "" {
			router.HandleFunc("/refresh", doRefresh).Methods("GET")
		} else {
			router.HandleFunc("/refresh", doRefresh).Methods("GET").Queries("auth", *auth)
		}
	} else {
		router.HandleFunc("/refresh", doRefresh).Methods("GET").Queries("auth", *refreshAuth)
	}
	log.Infof("Listening on %s", listenOn)
	log.Fatal(http.ListenAndServe(listenOn, router))
}

func refreshOneLoginUsers() error {
	log.Debug("Refreshing OneLogin users")
	githubUsers, roleList, err := getGithubUsers(*ol)
	if err != nil {
		return err
	}

	refreshMutex.Lock()
	users = githubUsers
	roles = roleList
	refreshMutex.Unlock()
	metricKnownUsers.Set(float64(len(githubUsers)))
	metricOneLoginRefreshesTotal.Inc()
	return nil
}

func deleteAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	user := params["id"]
	log.Debugf("Received request to purge authorized_keys cache of user %s", user)
	pubkeyCache.Delete(user)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Purging authorized_keys cache for user " + user + "\n"))
	metricAuthorizedKeysRequestsTotal.WithLabelValues("200", "DELETE").Inc()
}

func doRefresh(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to refresh OneLogin users")
	manualRefresh <- true
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Refreshing OneLogin users\n"))
}

func getGithubNamesForUsers(us []string) ([]string) {
	ghNames := make([]string, 0)

	refreshMutex.RLock()
	for _, u := range us {
		gh, ok := users[u]
		if !ok {
			continue
		}
		ghNames = append(ghNames, gh)
	}
	refreshMutex.RUnlock()

	return ghNames
}

func getKeys(keyNames []string) ([]string, error) {
	keys := make([]string, 0)

	for _, user := range keyNames {
		var authorizedKeys string
		cachedAuthorizedKeys, found := pubkeyCache.Get(user)
		if found {
			log.Debugf("authorized_keys for user %s found in cache", user)
			authorizedKeys  = cachedAuthorizedKeys.(string)
		} else {
			log.Debugf("authorized_keys for user %s not found in cache", user)
			var err error

			g := ghpubkey.NewGHPubKey()
			authorizedKeys, err = g.RequestKeysForUser(user)
			if err != nil {
				log.Errorf("User %s found but authorized_keys unretrievable", user)
				continue
			}

			pubkeyCache.Set(user, authorizedKeys, cache.DefaultExpiration)
		}

		keys = append(keys, authorizedKeys)
	}

	return keys, nil
}

func getRoleAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	role := params["role"]
	refreshMutex.RLock()
	roleUsers, ok := roles[role]
	refreshMutex.RUnlock()

	if ok {
		ghNames := getGithubNamesForUsers(roleUsers)
		if len(ghNames) > 0 {
			keys, err := getKeys(ghNames)
			if err != nil {
				log.Errorf("Role %s found but authorized_keys unretrievable", role)
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("503 couldn't retrieve roles authorized_keys\n"))
				metricAuthorizedKeysRequestsTotal.WithLabelValues("503", "GET").Inc()
				return
			}

			authorizedKeys := strings.Join(keys, "") //keys are engind with a new line
			log.Infof("Returning authorized_keys of role %s", role)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(authorizedKeys))
			metricAuthorizedKeysRequestsTotal.WithLabelValues("200", "GET").Inc()
			return
		}
	}
}

func getAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	user := params["id"]
	refreshMutex.RLock()
	githubName, ok := users[user]
	refreshMutex.RUnlock()
	w.Header().Set("Content-Type", "text/plain")
	if ok {
		log.Infof("Found user %s with github name %s", user, githubName)
		var authorizedKeys string
		cachedAuthorizedKeys, found := pubkeyCache.Get(user)
		if found {
			log.Debugf("authorized_keys for user %s found in cache", user)
			authorizedKeys = cachedAuthorizedKeys.(string)
		} else {
			log.Debugf("authorized_keys for user %s not found in cache", user)
			g := ghpubkey.NewGHPubKey()
			var err error
			authorizedKeys, err = g.RequestKeysForUser(githubName)
			if err != nil {
				log.Errorf("User %s found but authorized_keys unretrievable", user)
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("503 couldn't retrieve users authorized_keys\n"))
				metricAuthorizedKeysRequestsTotal.WithLabelValues("503", "GET").Inc()
				return
			}
			pubkeyCache.Set(user, authorizedKeys, cache.DefaultExpiration)
		}
		log.Infof("Returning authorized_keys of github user %s", githubName)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(authorizedKeys))
		metricAuthorizedKeysRequestsTotal.WithLabelValues("200", "GET").Inc()
		return
	}
	log.Errorf("User %s not found", user)
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 user not found\n"))
	metricAuthorizedKeysRequestsTotal.WithLabelValues("404", "GET").Inc()
}

func getGithubName(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	refreshMutex.RLock()
	githubName, ok := users[params["id"]]
	refreshMutex.RUnlock()
	w.Header().Set("Content-Type", "text/plain")
	if ok {
		log.Infof("Found user %s with github name %s", params["id"], githubName)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(githubName + "\n"))
		metricGithubNameRequestsTotal.WithLabelValues("200", "GET").Inc()
		return
	}
	log.Errorf("User %s not found", params["id"])
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 user not found\n"))
	metricGithubNameRequestsTotal.WithLabelValues("404", "GET").Inc()
}

func getHealth(w http.ResponseWriter, r *http.Request) {
	log.Debug("Returning health status")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func getUserRoleList(roleIDs []int, username string, roleList RoleList, onelogin onelogin.OneLogin) (RoleList, error) {
	for _, roleID := range roleIDs {
		rs, err := onelogin.Get_Roles("")
		if err != nil {
			return roleList, err
		}

		for _, r := range rs {
			if r.Id == roleID {
				if val, ok := roleList[r.Name]; ok {
					roleList[r.Name] = append(val, username)
				} else {
					roleList[r.Name] = []string{username}
				}
			}
		}
	}

	return roleList, nil
}

func getGithubUsers(onelogin onelogin.OneLogin) (map[string]string, RoleList, error) {
	log.Info("Updating users from OneLogin")
	githubUsers := make(map[string]string)
	roles := make(RoleList)
	filter := make(map[string]string)
	oneLoginUsers, err := onelogin.Get_Users(filter)
	if err != nil {
		return githubUsers, roles, fmt.Errorf("Failed to get users: %v", err)
	}
	for _, user := range *oneLoginUsers {
		if githubName, ok := user.Custom_attributes["githubname"]; ok {
			if githubName != "" && user.Status == 1 {
				log.Debugf("Setting github name for user %s to %s\n", user.Username, githubName)
				githubUsers[user.Username] = githubName

				roles, err = getUserRoleList(user.Role_id, user.Username, roles, onelogin)
				if err != nil {
					log.Errorf("Got error while getting Roles for user %s, %s",user.Username, err)
				}
			}
		}
	}
	return githubUsers, roles, nil
}

func flagFromEnv(envVar string) string {
	envValue := os.Getenv(envVar)
	if envValue == "" {
		switch envVar {
		case "SHARD":
			return "us"
		}
	}
	return envValue
}
