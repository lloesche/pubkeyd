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
)

var log = logging.MustGetLogger("pubkeyd")
var users map[string]string
var mutex = &sync.Mutex{}

// main function to boot up everything
func main() {
	shard := flag.String("shard", flagFromEnv("SHARD"), "OneLogin shard [env SHARD]")
	clientID := flag.String("client-id", flagFromEnv("CLIENT_ID"), "OneLogin Client ID [env CLIENT_ID]")
	clientSecret := flag.String("client-secret", flagFromEnv("CLIENT_SECRET"), "OneLogin Client Secret [env CLIENT_SECRET]")
	subdomain := flag.String("subdomain", flagFromEnv("SUBDOMAIN"), "OneLogin Subdomain [env SUBDOMAIN]")
	refreshInterval := flag.Int("refresh", 900, "OneLogin refresh interval in seconds")
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

	onelogin := onelogin.New(*shard, *clientID, *clientSecret, *subdomain, loglevel)

	githubUsers, err := getGithubUsers(*onelogin)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	users = githubUsers

	ticker := time.NewTicker(time.Duration(*refreshInterval) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				githubUsers, err := getGithubUsers(*onelogin)
				if err != nil {
					log.Error(err)
					continue
				}
				mutex.Lock()
				users = githubUsers
				mutex.Unlock()

			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	router := mux.NewRouter()
	listenOn := ":" + strconv.Itoa(*port)
	router.HandleFunc("/authorized_keys/{id}", getAuthorizedKeys).Methods("GET")
	router.HandleFunc("/githubname/{id}", getGithubName).Methods("GET")
	router.HandleFunc("/health", getHealth).Methods("GET")
	log.Infof("Listening on %s", listenOn)
	log.Fatal(http.ListenAndServe(listenOn, router))
}

func getAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	mutex.Lock()
	githubName, ok := users[params["id"]]
	mutex.Unlock()
	if ok {
		log.Infof("Found user %s with github name %s", params["id"], githubName)
		g := ghpubkey.NewGHPubKey()
		authorizedKeys, err := g.RequestKeysForUser(githubName)
		if err != nil {
			log.Errorf("User %s found but pubkey unretrievable", params["id"])
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("503 couldn't retrieve users public key\n"))
			return
		}
		log.Infof("Returning public key of github user %s", githubName)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(authorizedKeys))
		return
	}
	log.Errorf("User %s not found", params["id"])
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 user not found\n"))
}

func getGithubName(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	mutex.Lock()
	githubName, ok := users[params["id"]]
	mutex.Unlock()
	if ok {
		log.Infof("Found user %s with github name %s", params["id"], githubName)
		w.Header().Set("Content-Type", "text/plain")
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
