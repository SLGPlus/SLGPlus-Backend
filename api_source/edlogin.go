package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	ApiVersion = "4.69.1"
	BaseURL    = "https://api.ecoledirecte.com/v3"
	UserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

// -----------------------------------------------------------------
// CLIENT ED — un par requête (pas de partage d'état entre users)
// -----------------------------------------------------------------

type Client struct {
	HTTPClient *http.Client
	GTK        string
	XToken     string
	TwoFAToken string
}

func NewClient() *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		HTTPClient: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second, // timeout global par requête ED
		},
	}
}

func (c *Client) DoRequest(method, path string, bodyData string, useTokens bool) ([]byte, error) {
	req, err := http.NewRequest(method, BaseURL+path, strings.NewReader(bodyData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.ecoledirecte.com")
	req.Header.Set("Referer", "https://www.ecoledirecte.com/")

	if c.GTK != "" {
		req.Header.Set("X-GTK", c.GTK)
	}
	if useTokens {
		req.Header.Set("X-Token", c.XToken)
		req.Header.Set("2FA-Token", c.TwoFAToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "gtk") {
			c.GTK = cookie.Value
		}
	}
	if xt := resp.Header.Get("X-Token"); xt != "" {
		c.XToken = xt
	}
	if ft := resp.Header.Get("2FA-Token"); ft != "" {
		c.TwoFAToken = ft
	}

	body, err := io.ReadAll(resp.Body)
	return body, err
}

// -----------------------------------------------------------------
// TYPES JSON pour les requêtes/réponses du serveur
// -----------------------------------------------------------------

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TwoFARequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	CN         string `json:"cn"`
	CV         string `json:"cv"`
	XToken     string `json:"x_token"`
	TwoFAToken string `json:"twofa_token"`
	GTK        string `json:"gtk"`
}

type LoginResponse struct {
	Success bool        `json:"success"`
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type TwoFAChallenge struct {
	Required   bool     `json:"required"`
	Question   string   `json:"question"`
	Choices    []string `json:"choices"`
	XToken     string   `json:"x_token"`
	TwoFAToken string   `json:"twofa_token"`
	GTK        string   `json:"gtk"`
}

// -----------------------------------------------------------------
// HANDLERS HTTP
// -----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// POST /login
// Flask envoie {"username": "...", "password": "..."}
// Le serveur tente le login et répond :
//   - success + données si ok
//   - 2FA challenge si double auth requise
//   - erreur sinon
// UN GRAND MERCI A ECOLEDIRECTEPLUS pour l'analyse de protocole.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, LoginResponse{Message: "Méthode non autorisée"})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, 400, LoginResponse{Message: "Body JSON invalide ou champs manquants (username, password)"})
		return
	}

	client := NewClient()

	// -- Étape 1 : Init GTK --------------------------------------
	if _, err := client.DoRequest("GET", "/login.awp?gtk=1&v="+ApiVersion, "", false); err != nil {
		writeJSON(w, 502, LoginResponse{Message: "Impossible de contacter EcoleDirecte : " + err.Error()})
		return
	}

	// -- Étape 2 : Login initial ---------------------------------
	safePass := strings.ReplaceAll(req.Password, "%", "%25")
	payload := fmt.Sprintf(`data={"identifiant":"%s","motdepasse":"%s","isReLogin":false,"fa":[]}`,
		req.Username, safePass)

	body, err := client.DoRequest("POST", "/login.awp?v="+ApiVersion, payload, false)
	if err != nil {
		writeJSON(w, 502, LoginResponse{Message: "Erreur login : " + err.Error()})
		return
	}

	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		writeJSON(w, 502, LoginResponse{Message: "Réponse ED non parseable"})
		return
	}

	code := int(res["code"].(float64))

	// -- Cas : 2FA requise ----------------------------------------
	if code == 250 {
		qBody, err := client.DoRequest("POST",
			"/connexion/doubleauth.awp?verbe=get&v="+ApiVersion,
			`data={}`, true)
		if err != nil {
			writeJSON(w, 502, LoginResponse{Message: "Erreur récupération 2FA : " + err.Error()})
			return
		}

		var qResp map[string]interface{}
		json.Unmarshal(qBody, &qResp)
		qData, ok := qResp["data"].(map[string]interface{})
		if !ok {
			writeJSON(w, 502, LoginResponse{Message: "Données 2FA invalides"})
			return
		}

		questionB64, _ := base64.StdEncoding.DecodeString(qData["question"].(string))
		rawProps := qData["propositions"].([]interface{})

		choices := make([]string, len(rawProps))
		decodedChoices := make([]string, len(rawProps))
		for i, p := range rawProps {
			choices[i] = p.(string) // base64 brut (à renvoyer pour le POST)
			dec, _ := base64.StdEncoding.DecodeString(p.(string))
			decodedChoices[i] = string(dec) // texte lisible pour Flask
		}

		// On renvoie le challenge + les tokens pour que Flask
		// puisse rappeler /login/2fa avec la réponse de l'utilisateur
		writeJSON(w, 200, map[string]interface{}{
			"success": false,
			"code":    250,
			"twofa": TwoFAChallenge{
				Required:   true,
				Question:   string(questionB64),
				Choices:    decodedChoices,
				XToken:     client.XToken,
				TwoFAToken: client.TwoFAToken,
				GTK:        client.GTK,
			},
			// choices_raw contient les base64 à renvoyer dans /login/2fa
			"choices_raw": choices,
		})
		return
	}

	// -- Cas : login direct réussi (code 200) ---------------------  
	if code == 200 {
		writeJSON(w, 200, LoginResponse{
			Success: true,
			Code:    200,
			Data:    res["data"],
		})
		return
	}

	// -- Cas : erreur (mauvais mot de passe etc.) -----------------
	msg, _ := res["message"].(string)
	writeJSON(w, 401, LoginResponse{
		Success: false,
		Code:    code,
		Message: msg,
	})
}

// POST /login/2fa
// Flask renvoie la réponse 2FA de l'utilisateur + les tokens récupérés
// depuis la première réponse (/login code 250)
func handleTwoFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, LoginResponse{Message: "Méthode non autorisée"})
		return
	}

	var req TwoFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, LoginResponse{Message: "Body JSON invalide"})
		return
	}

	// Reconstruit le client avec les tokens de la session 2FA
	client := NewClient()
	client.XToken = req.XToken
	client.TwoFAToken = req.TwoFAToken
	client.GTK = req.GTK

	// -- Étape 1 : Valide la réponse QCM (ca me pete les couilles) -------------------------
	// req.CV contient le base64 de la réponse choisie par l'utilisateur
	payloadQ := fmt.Sprintf(`data={"choix":"%s"}`, req.CV)
	qBody, err := client.DoRequest("POST",
		"/connexion/doubleauth.awp?verbe=post&v="+ApiVersion,
		payloadQ, true)
	if err != nil {
		writeJSON(w, 502, LoginResponse{Message: "Erreur validation 2FA : " + err.Error()})
		return
	}

	var vResp map[string]interface{}
	json.Unmarshal(qBody, &vResp)
	vData, ok := vResp["data"].(map[string]interface{})
	if !ok {
		writeJSON(w, 401, LoginResponse{Message: "Réponse 2FA incorrecte"})
		return
	}

	cn := vData["cn"].(string)
	cv := vData["cv"].(string)

	// -- Étape 2 : Refresh GTK + login final (fin je pense) --------------------- 
	client.DoRequest("GET", "/login.awp?gtk=1&v="+ApiVersion, "", false)

	safePass := strings.ReplaceAll(req.Password, "%", "%25")
	finalJSON := fmt.Sprintf(
		`{"identifiant":"%s","motdepasse":"%s","isReLogin":false,"cn":"%s","cv":"%s","fa":[{"cn":"%s","cv":"%s","uniq":"false"}]}`,
		req.Username, safePass, cn, cv, cn, cv,
	)
	finalBody, err := client.DoRequest("POST",
		"/login.awp?v="+ApiVersion,
		"data="+finalJSON, true)
	if err != nil {
		writeJSON(w, 502, LoginResponse{Message: "Erreur login final : " + err.Error()})
		return
	}

	var result map[string]interface{}
	json.Unmarshal(finalBody, &result)

	if code := int(result["code"].(float64)); code == 200 {
		writeJSON(w, 200, LoginResponse{
			Success: true,
			Code:    200,
			Data:    result["data"],
		})
	} else {
		msg, _ := result["message"].(string)
		writeJSON(w, 401, LoginResponse{Success: false, Code: code, Message: msg})
	}
}

// GET /health — pour vérifier que le serveur tourne sa race
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// CORS
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		switch origin {
		case "https://forum-slgplus.great-site.net":
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Répond au preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/login/2fa", handleTwoFA)
	mux.HandleFunc("/health", handleHealth)

	// Serveur optimisé pour ~400 connexions simultanées (au paf)
	srv := &http.Server{
		Addr:    "localhost:8080",
		Handler: cors(mux),

		// Timeouts pour éviter les goroutines bloquées indéfiniment
		ReadTimeout:    10 * time.Second, // temps max pour lire la requête entrante
		WriteTimeout:   30 * time.Second, // temps max pour écrire la réponse
		IdleTimeout:    60 * time.Second, // keep-alive max

		MaxHeaderBytes: 1 << 20, // 1 Mo max par header
	}

	log.Printf("Serveur ED démarré sur %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
