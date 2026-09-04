package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type internalQuotaHealthRequest struct {
	APIKey string   `json:"api_key"`
	Models []string `json:"models"`
}

func (s *Server) handleInternalQuotaHealth(c *gin.Context) {
	var req internalQuotaHealthRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"reason":  "invalid_request_body",
		})
		return
	}

	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		apiKey = bearerToken(c.GetHeader("Authorization"))
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(c.GetHeader("X-API-Key"))
	}
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"reason":  "missing_api_key",
		})
		return
	}
	if s == nil || s.handlers == nil || s.handlers.AuthManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"reason":  "auth_manager_unavailable",
		})
		return
	}

	result := s.handlers.AuthManager.ClientAPIKeyQuotaHealth(apiKey, req.Models)
	if !result.Authorized {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"reason":  "unauthorized",
		})
		return
	}
	result.Authorized = false
	c.JSON(http.StatusOK, result)
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
