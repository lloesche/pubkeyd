package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fatz/ghpubkey-go/ghpubkey"
	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"github.com/oswell/onelogin-go"
	"github.com/patrickmn/go-cache"
)

var log = logging.MustGetLogger("pubkeyd")
var users map[string]string
var refreshMutex = &sync.RWMutex{}
var pubkeyCache *cache.Cache
var ol *onelogin.OneLogin
var manualRefresh chan (bool)

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
	// fixme: refactor this
	if *auth == "" {
		router.HandleFunc("/authorized_keys/{id}", getAuthorizedKeys).Methods("GET")
		router.HandleFunc("/authorized_keys/{id}", deleteAuthorizedKeys).Methods("DELETE")
		router.HandleFunc("/githubname/{id}", getGithubName).Methods("GET")
	} else {
		router.HandleFunc("/authorized_keys/{id}", getAuthorizedKeys).Methods("GET").Queries("auth", *auth)
		router.HandleFunc("/authorized_keys/{id}", deleteAuthorizedKeys).Methods("DELETE").Queries("auth", *auth)
		router.HandleFunc("/githubname/{id}", getGithubName).Methods("GET").Queries("auth", *auth)
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
	githubUsers, err := getGithubUsers(*ol)
	if err != nil {
		return err
	}
	refreshMutex.Lock()
	users = githubUsers
	refreshMutex.Unlock()
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
}

func doRefresh(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to refresh OneLogin users")
	manualRefresh <- true
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Refreshing OneLogin users\n"))
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
				return
			}
			pubkeyCache.Set(user, authorizedKeys, cache.DefaultExpiration)
		}
		log.Infof("Returning authorized_keys of github user %s", githubName)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(authorizedKeys))
		return
	}
	log.Errorf("User %s not found", user)
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 user not found\n"))
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
		return
	}
	log.Errorf("User %s not found", params["id"])
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 user not found\n"))
}

func getHealth(w http.ResponseWriter, r *http.Request) {
	log.Debug("Returning health status")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func getGithubUsers(onelogin onelogin.OneLogin) (map[string]string, error) {
	log.Info("Updating users from OneLogin")
	githubUsers := make(map[string]string)
	filter := make(map[string]string)
	oneLoginUsers, err := onelogin.Get_Users(filter)
	if err != nil {
		return githubUsers, fmt.Errorf("Failed to get users: %v", err)
	}
	for _, user := range *oneLoginUsers {
		if githubName, ok := user.Custom_attributes["githubname"]; ok {
			if githubName != "" && user.Status == 1 {
				log.Debugf("Setting github name for user %s to %s\n", user.Username, githubName)
				githubUsers[user.Username] = githubName
			}
		}
	}
	return githubUsers, nil
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
