package client

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// ZValueTransitionManager handles the global transition state
type ZValueTransitionManager struct {
	mu               sync.RWMutex
	shouldTransition bool
	newZValue        uint8
}

// ZManager is our Global instance
var ZManager = &ZValueTransitionManager{
	shouldTransition: false,
	newZValue:        0,
}

// StartControlAPI exposes the client endpoint for Z-value switches
func StartControlAPI() {
	http.HandleFunc("/z", handleNewZValue)

	log.Println("Starting Control API on :8080")
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Printf("Control API error: %v", err)
		}
	}()
}

type ZRequest struct {
	Z int `json:"z"`
}

// handleNewZValue is the handler that will initiate Z-value change for server response
func handleNewZValue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ZRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Z < 0 || req.Z > 7 {
		http.Error(w, "Z value must be between 0 and 7", http.StatusBadRequest)
		return
	}

	zValue := uint8(req.Z)
	ZManager.TriggerNewZValue(zValue)

	response := "Protocol transition triggered"
	json.NewEncoder(w).Encode(response)
}

// TriggerNewZValue sets the transition flag
func (zm *ZValueTransitionManager) TriggerNewZValue(zValue uint8) {
	zm.mu.Lock()
	defer zm.mu.Unlock()

	zm.shouldTransition = true
	zm.newZValue = zValue

	log.Printf("| NEW Z VALUE INITIATED |\n->Global Flag: %t\n->New Z Value: %d\n",
		zm.shouldTransition, zm.newZValue)
}

// CheckAndReset atomically checks if Z-Value Update is needed and resets the flag
func (zm *ZValueTransitionManager) CheckAndReset() (bool, uint8) {
	zm.mu.Lock()
	defer zm.mu.Unlock()

	if zm.shouldTransition {
		zm.shouldTransition = false // Reset immediately
		log.Printf("ZValueUpdate signal consumed and reset")
		return true, zm.newZValue
	}

	return false, 0
}
