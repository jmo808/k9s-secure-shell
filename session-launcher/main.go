package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type SessionLauncher struct {
	clientset *kubernetes.Clientset
	namespace string
}

type SessionRequest struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

type SessionResponse struct {
	SessionID   string `json:"session_id"`
	PodName     string `json:"pod_name"`
	URL         string `json:"url"`
	TerminalURL string `json:"terminal_url,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

const (
	SESSION_NAMESPACE = "admin-web" 
	TTL_SECONDS      = 600  // 10 minutes for completed jobs
	ACTIVE_TTL_SECONDS = 3600 // 1 hour for active sessions
)

func NewSessionLauncher() (*SessionLauncher, error) {
	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %v", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	return &SessionLauncher{
		clientset: clientset,
		namespace: SESSION_NAMESPACE,
	}, nil
}

// sanitizeForLabel converts a string to be valid as a Kubernetes label value
func sanitizeForLabel(s string) string {
	// Replace invalid characters with hyphens and ensure valid start/end
	result := strings.ReplaceAll(s, "@", "-at-")
	result = strings.ReplaceAll(result, ".", "-dot-")
	result = strings.ReplaceAll(result, " ", "-")
	
	// Ensure it starts and ends with alphanumeric character
	if len(result) > 63 {
		result = result[:63]
	}
	return result
}

func (sl *SessionLauncher) createSessionJob(userID, sessionID string) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("k9s-session-%s", sessionID)
	
	// Sanitize userID for use in Kubernetes labels
	sanitizedUserID := sanitizeForLabel(userID)
	
	// Create unique labels for this session
	labels := map[string]string{
		"app":        "k9s-session",
		"session-id": sessionID,
		"user-id":    sanitizedUserID,
		"component":  "ephemeral-terminal",
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: sl.namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			// Job should complete when the terminal session ends
			Completions:  int32Ptr(1),
			Parallelism:  int32Ptr(1),
			BackoffLimit: int32Ptr(0), // Don't retry failed sessions
			
			// Clean up completed jobs after shorter TTL
			TTLSecondsAfterFinished: int32Ptr(TTL_SECONDS),
			
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					
					// Security: No service account access
					AutomountServiceAccountToken: boolPtr(false),
					
					Containers: []corev1.Container{
						{
							Name:            "k9s-ttyd",
							Image:           "harbor.bbmxclus1.blackbutterfly.mx/k9s/k9s-ephemeral:v0.50.12-latest",
							ImagePullPolicy: corev1.PullAlways,
							
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 7681,
									Name:          "ttyd",
								},
							},
							
							Env: []corev1.EnvVar{
								{
									Name:  "SESSION_ID",
									Value: sessionID,
								},
								{
									Name:  "USER_ID", 
									Value: userID,
								},
								{
									Name:  "SESSION_TIMEOUT",
									Value: fmt.Sprintf("%d", ACTIVE_TTL_SECONDS), // 1 hour
								},
							},
							
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "kubeconfig",
									MountPath: "/root/.kube/config",
									SubPath:   "config",
									ReadOnly:  true,
								},
							},
							
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
						},
					},
					
					Volumes: []corev1.Volume{
						{
							Name: "kubeconfig",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "k9s-kubeconfig",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return sl.clientset.BatchV1().Jobs(sl.namespace).Create(context.TODO(), job, metav1.CreateOptions{})
}

func (sl *SessionLauncher) rootHandler(w http.ResponseWriter, r *http.Request) {
	// Handle root path - redirect to create a new session
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	// For GET requests, show a simple web interface
	if r.Method == http.MethodGet {
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Admin Terminal</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Color Emoji', Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px; 
        }
        .button { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px;
        }
        .button:hover { background: #0056b3; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Admin Terminal</h1>
    <p>Welcome to the ephemeral admin terminal. Each session gets its own isolated container with kubectl, k9s, and other admin tools.</p>
    <button class="button" onclick="createSession()">Launch New Admin Session</button>
    
    <div id="status" style="display:none; text-align:center; margin-top:20px;">
        <h2>Creating Your Admin Session...</h2>
        <p id="statusMessage">Please wait while we prepare your isolated admin environment.</p>
        <div style="margin:20px 0;">
            <div style="display:inline-block; width:40px; height:40px; border:4px solid #f3f3f3; border-top:4px solid #007bff; border-radius:50%; animation:spin 1s linear infinite;"></div>
        </div>
        <style>
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </div>
    
    <script>
    function createSession() {
        // Hide main content, show status
        document.querySelector('h1').style.display = 'none';
        document.querySelector('p').style.display = 'none';
        document.querySelector('button').style.display = 'none';
        document.getElementById('status').style.display = 'block';
    
        // User info will be extracted from OAuth2-proxy headers on server side
        
        fetch('/session', { 
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sessionID: '' // Let server generate this
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.session_id) {
                    document.getElementById('statusMessage').textContent = 'Session created! Waiting for container to be ready...';
                    pollSessionStatus(data.session_id);
                } else {
                    showError('Failed to create session: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                showError('Error creating session: ' + error);
            });
    }
    
    function pollSessionStatus(sessionId) {
        fetch('/session/' + sessionId)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'running' && data.terminal_url) {
                    document.getElementById('statusMessage').textContent = 'Session ready! Redirecting to terminal...';
                    setTimeout(() => {
                        window.location.href = data.terminal_url;
                    }, 1000);
                } else if (data.status === 'failed') {
                    showError('Session failed to start: ' + (data.error || 'Unknown error'));
                } else {
                    // Still creating, check again in 2 seconds
                    document.getElementById('statusMessage').textContent = 'Starting container... (' + (data.status || 'preparing') + ')';
                    setTimeout(() => pollSessionStatus(sessionId), 2000);
                }
            })
            .catch(error => {
                showError('Error checking session status: ' + error);
            });
    }
    
    function showError(message) {
        document.getElementById('status').innerHTML = '<h2 style="color:red;">Error</h2><p>' + message + '</p><button class="button" onclick="location.reload()">Try Again</button>';
    }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}
	
	// For other methods, redirect to POST /session
	if r.Method == http.MethodPost {
		sl.createSessionHandler(w, r)
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (sl *SessionLauncher) createSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Extract user info from OAuth2-proxy headers - debug all headers first
	log.Printf("DEBUG: All request headers:")
	for name, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-") {
			log.Printf("  %s: %v", name, values)
		}
	}
	
	// Prioritize readable username/email over access token hash
	userID := r.Header.Get("X-Forwarded-Email")
	if userID == "" {
		userID = r.Header.Get("X-Auth-Request-Email")
	}
	if userID == "" {
		userID = r.Header.Get("X-Forwarded-Preferred-Username")
	}
	if userID == "" {
		userID = r.Header.Get("X-Auth-Request-Preferred-Username")
	}
	// Fall back to user hash only if no readable username is available
	if userID == "" {
		userID = r.Header.Get("X-Forwarded-User")
	}
	if userID == "" {
		userID = r.Header.Get("X-Auth-Request-User")
	}
	
	// Try to decode base64 if it looks encoded
	log.Printf("Raw userID received: '%s' (length: %d)", userID, len(userID))
	if len(userID) > 20 && !strings.Contains(userID, "@") && !strings.Contains(userID, " ") {
		if decoded, err := base64.StdEncoding.DecodeString(userID); err == nil {
			decodedStr := string(decoded)
			log.Printf("Base64 decoded '%s' -> '%s'", userID, decodedStr)
			if len(decodedStr) > 0 && decodedStr != userID {
				userID = decodedStr
				log.Printf("Using decoded userID: '%s'", userID)
			}
		} else {
			log.Printf("Failed to decode base64 userID '%s': %v", userID, err)
		}
	}
	
	if userID == "" {
		// Fallback to a more descriptive default
		userID = "admin-user"
	}
	
	// Override any userID from request body with header info
	req.UserID = userID

	// Generate session ID if not provided
	if req.SessionID == "" {
		// Generate a simple, valid session ID using timestamp and random string
		req.SessionID = fmt.Sprintf("s%d%s", time.Now().Unix(), 
			strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano()))[8:16])
	}

	// Create the job
	job, err := sl.createSessionJob(req.UserID, req.SessionID)
	if err != nil {
		log.Printf("Error creating session job: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create session"})
		return
	}

	response := SessionResponse{
		SessionID: req.SessionID,
		PodName:   job.Name,
		URL:       fmt.Sprintf("/session/%s", req.SessionID),
		Status:    "creating",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	log.Printf("Created session %s for user %s", req.SessionID, req.UserID)
}

func (sl *SessionLauncher) getSessionHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/session/")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Get job status
	jobName := fmt.Sprintf("k9s-session-%s", sessionID)
	job, err := sl.clientset.BatchV1().Jobs(sl.namespace).Get(context.TODO(), jobName, metav1.GetOptions{})
	if err != nil {
		log.Printf("Error getting job %s: %v", jobName, err)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Get pod status
	pods, err := sl.clientset.CoreV1().Pods(sl.namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("session-id=%s", sessionID),
	})
	if err != nil {
		log.Printf("Error listing pods for session %s: %v", sessionID, err)
		http.Error(w, "Error checking session status", http.StatusInternalServerError)
		return
	}

	status := "creating"
	var terminalURL string
	var errorMsg string
	
	if len(pods.Items) > 0 {
		pod := pods.Items[0]
		switch pod.Status.Phase {
		case corev1.PodRunning:
			status = "running"
			// Check if pod is actually ready (all containers running)
			ready := true
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if !containerStatus.Ready {
					ready = false
					status = "starting"
					break
				}
			}
			if ready {
				// Provide terminal URL - this will be proxied through the session launcher
				terminalURL = fmt.Sprintf("/terminal/%s", sessionID)
			}
		case corev1.PodSucceeded:
			status = "completed"
		case corev1.PodFailed:
			status = "failed"
			if pod.Status.Message != "" {
				errorMsg = pod.Status.Message
			}
		case corev1.PodPending:
			status = "pending"
			// Check for specific pending reasons
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.State.Waiting != nil {
					if containerStatus.State.Waiting.Reason == "ImagePullBackOff" || 
					   containerStatus.State.Waiting.Reason == "ErrImagePull" {
						status = "failed"
						errorMsg = "Failed to pull container image"
						break
					}
				}
			}
		}
	}

	response := SessionResponse{
		SessionID:   sessionID,
		PodName:     job.Name,
		URL:         fmt.Sprintf("/session/%s", sessionID),
		TerminalURL: terminalURL,
		Status:      status,
		Error:       errorMsg,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sl *SessionLauncher) checkSessionHealth(sessionID string, delay time.Duration) {
	// Wait for the delay to allow for temporary connection issues
	time.Sleep(delay)
	
	// Check if the pod for this session is still healthy
	pods, err := sl.clientset.CoreV1().Pods(sl.namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("session-id=%s", sessionID),
	})
	if err != nil {
		log.Printf("Error checking session health for %s: %v", sessionID, err)
		return
	}
	
	if len(pods.Items) == 0 {
		log.Printf("No pods found for session %s, already cleaned up", sessionID)
		return
	}
	
	pod := pods.Items[0]
	
	// Check if pod is in a failed state or containers have exited
	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
		log.Printf("Pod for session %s is in terminal state (%s), cleaning up job", sessionID, pod.Status.Phase)
		
		// Find and delete the associated job
		jobs, err := sl.clientset.BatchV1().Jobs(sl.namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("session-id=%s", sessionID),
		})
		if err != nil {
			log.Printf("Error finding job for session %s: %v", sessionID, err)
			return
		}
		
		for _, job := range jobs.Items {
			err := sl.clientset.BatchV1().Jobs(sl.namespace).Delete(context.TODO(), job.Name, metav1.DeleteOptions{})
			if err != nil {
				log.Printf("Error deleting job for session %s: %v", sessionID, err)
			} else {
				log.Printf("Immediately cleaned up job for terminated session %s", sessionID)
			}
		}
	}
}

func (sl *SessionLauncher) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// List all jobs older than TTL
		jobs, err := sl.clientset.BatchV1().Jobs(sl.namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=k9s-session",
		})
		if err != nil {
			log.Printf("Error listing jobs for cleanup: %v", err)
			continue
		}

		for _, job := range jobs.Items {
			// Check if job is older than active TTL (for running jobs) or completed TTL (for finished jobs)
			maxAge := time.Duration(ACTIVE_TTL_SECONDS) * time.Second
			if job.Status.CompletionTime != nil {
				// Job is completed, use shorter TTL
				maxAge = time.Duration(TTL_SECONDS) * time.Second
			}
			
			if time.Since(job.CreationTimestamp.Time) > maxAge {
				err := sl.clientset.BatchV1().Jobs(sl.namespace).Delete(context.TODO(), job.Name, metav1.DeleteOptions{})
				if err != nil {
					log.Printf("Error deleting expired job %s: %v", job.Name, err)
				} else {
					log.Printf("Cleaned up expired session job %s", job.Name)
				}
			}
		}
	}
}

func (sl *SessionLauncher) terminalHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/terminal/")
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Get the pod for this session
	pods, err := sl.clientset.CoreV1().Pods(sl.namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("session-id=%s", sessionID),
	})
	if err != nil || len(pods.Items) == 0 {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	pod := pods.Items[0]
	if pod.Status.Phase != corev1.PodRunning {
		http.Error(w, "Session not ready", http.StatusServiceUnavailable)
		return
	}

	// Redirect to the ttyd session via OAuth2-proxy
	// The OAuth2-proxy should be configured to route /ttyd/<session-id> to the pod
	redirectURL := fmt.Sprintf("/ttyd/%s/", sessionID)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (sl *SessionLauncher) ttydProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from path: /ttyd/<session-id>/...
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/ttyd/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}
	
	sessionID := pathParts[0]
	
	// Get the pod for this session
	pods, err := sl.clientset.CoreV1().Pods(sl.namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("session-id=%s", sessionID),
	})
	if err != nil || len(pods.Items) == 0 {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	pod := pods.Items[0]
	if pod.Status.Phase != corev1.PodRunning {
		http.Error(w, "Session not ready", http.StatusServiceUnavailable)
		return
	}

	// Create proxy to the pod's ttyd service using pod IP
	if pod.Status.PodIP == "" {
		http.Error(w, "Pod IP not available", http.StatusServiceUnavailable)
		return
	}
	
	targetURL := fmt.Sprintf("http://%s:7681", pod.Status.PodIP)
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Modify the request path to remove the /ttyd/<session-id> prefix
	originalPath := r.URL.Path
	if len(pathParts) > 1 {
		r.URL.Path = "/" + strings.Join(pathParts[1:], "/")
	} else {
		r.URL.Path = "/"
	}
	
	// Custom director to handle WebSocket upgrades and headers
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		
		// Preserve WebSocket headers for ttyd
		if req.Header.Get("Upgrade") == "websocket" {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
	}
	
	// Handle errors and connection issues
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error for session %s: %v", sessionID, err)
		
		// If WebSocket connection fails or ttyd is unavailable, consider cleanup
		if r.Header.Get("Upgrade") == "websocket" || strings.Contains(err.Error(), "connection refused") {
			log.Printf("Connection issue detected for session %s, scheduling cleanup check", sessionID)
			// Schedule an immediate cleanup check for this session
			go sl.checkSessionHealth(sessionID, 10*time.Second)
		}
		
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}
	
	log.Printf("Proxying request for session %s: %s -> %s", sessionID, originalPath, r.URL.Path)
	proxy.ServeHTTP(w, r)
}

func main() {
	launcher, err := NewSessionLauncher()
	if err != nil {
		log.Fatalf("Failed to create session launcher: %v", err)
	}

	// Start cleanup routine
	go launcher.cleanupExpiredSessions()

	// Set up HTTP handlers
	http.HandleFunc("/", launcher.rootHandler)
	http.HandleFunc("/session", launcher.createSessionHandler)
	http.HandleFunc("/session/", launcher.getSessionHandler)
	http.HandleFunc("/terminal/", launcher.terminalHandler)
	http.HandleFunc("/ttyd/", launcher.ttydProxyHandler)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Session launcher starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// Helper functions
func int32Ptr(i int32) *int32 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}