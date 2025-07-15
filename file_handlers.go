package secretr

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// FileResponse represents the API response for file operations
type FileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// FileHandler handles file-related HTTP endpoints
type FileHandler struct {
	secretr *Secretr
}

// NewFileHandler creates a new FileHandler instance
func NewFileHandler(s *Secretr) *FileHandler {
	return &FileHandler{secretr: s}
}

// RegisterFileRoutes registers all file-related routes
func (h *FileHandler) RegisterFileRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/secretr/files", h.handleFiles)
	mux.HandleFunc("/secretr/files/", h.handleFileOperations)
	mux.HandleFunc("/secretr/files/render/", h.handleFileRender)
}

// handleFiles handles POST (upload) and GET (list) requests
func (h *FileHandler) handleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handleFileUpload(w, r)
	case http.MethodGet:
		h.handleFileList(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFileUpload handles file upload requests
func (h *FileHandler) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form with 32MB max memory
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Get tags and properties from form
	tags := strings.Split(r.FormValue("tags"), ",")
	properties := make(map[string]string)
	for k, v := range r.Form {
		if strings.HasPrefix(k, "prop_") {
			properties[strings.TrimPrefix(k, "prop_")] = v[0]
		}
	}

	// Create temporary file
	tempFile, err := createTempFile(file)
	if err != nil {
		http.Error(w, "Failed to process file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile)

	// Store file in vault
	err = h.secretr.StoreFile(tempFile, tags, properties)
	if err != nil {
		http.Error(w, "Failed to store file", http.StatusInternalServerError)
		return
	}

	sendJSON(w, FileResponse{
		Success: true,
		Message: "File uploaded successfully",
		Data: map[string]string{
			"filename": header.Filename,
		},
	})
}

// handleFileList returns a list of all files
func (h *FileHandler) handleFileList(w http.ResponseWriter, r *http.Request) {
	files := h.secretr.ListFiles()
	sendJSON(w, FileResponse{
		Success: true,
		Data:    files,
	})
}

// handleFileOperations handles GET (download) and DELETE requests for specific files
func (h *FileHandler) handleFileOperations(w http.ResponseWriter, r *http.Request) {
	fileName := strings.TrimPrefix(r.URL.Path, "/secretr/files/")
	if fileName == "" {
		http.Error(w, "File name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleFileDownload(w, r, fileName)
	case http.MethodDelete:
		h.handleFileDelete(w, r, fileName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFileDownload handles file download requests
func (h *FileHandler) handleFileDownload(w http.ResponseWriter, r *http.Request, fileName string) {
	content, metadata, err := h.secretr.RetrieveFile(fileName)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", metadata.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", metadata.FileName))
	w.Write(content)
}

// handleFileDelete handles file deletion requests
func (h *FileHandler) handleFileDelete(w http.ResponseWriter, r *http.Request, fileName string) {
	err := h.secretr.DeleteFile(fileName)
	if err != nil {
		http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	sendJSON(w, FileResponse{
		Success: true,
		Message: "File deleted successfully",
	})
}

// handleFileRender handles image rendering requests
func (h *FileHandler) handleFileRender(w http.ResponseWriter, r *http.Request) {
	fileName := strings.TrimPrefix(r.URL.Path, "/secretr/files/render/")
	if fileName == "" {
		http.Error(w, "File name required", http.StatusBadRequest)
		return
	}

	content, metadata, err := h.secretr.RetrieveFile(fileName)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	ext := filepath.Ext(metadata.FileName)
	if ext == ".svg" {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(content)
		return
	}
	if !metadata.IsImage() {
		http.Error(w, "File is not an image", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", metadata.ContentType)
	w.Write(content)
}

// Helper functions
func createTempFile(src multipart.File) (string, error) {
	tempFile, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, src)
	if err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

func sendJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
