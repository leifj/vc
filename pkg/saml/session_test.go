//go:build saml

package saml

import (
	"testing"
	"time"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore_SetAndGet(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := NewSessionStore(3600*time.Second, log)
	defer store.Close()

	session := &SAMLSession{
		ID:             "test-session-id",
		CredentialType: "pid",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	// Store session
	store.Set(session.ID, session)

	// Retrieve session
	retrieved, err := store.Get(session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, session.CredentialType, retrieved.CredentialType)
	assert.Equal(t, session.IDPEntityID, retrieved.IDPEntityID)
}

func TestSessionStore_GetNonExistent(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := NewSessionStore(3600*time.Second, log)
	defer store.Close()

	// Try to get non-existent session
	_, err = store.Get("non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestSessionStore_Expiration(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Create store with very short TTL (1 second)
	store := NewSessionStore(1*time.Second, log)
	defer store.Close()

	session := &SAMLSession{
		ID:             "expiring-session",
		CredentialType: "diploma",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	store.Set(session.ID, session)

	// Session should exist immediately
	retrieved, err := store.Get(session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Session should be expired
	_, err = store.Get(session.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

func TestSessionStore_Delete(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := NewSessionStore(3600*time.Second, log)
	defer store.Close()

	session := &SAMLSession{
		ID:             "deletable-session",
		CredentialType: "ehic",
		IDPEntityID:    "https://idp.example.com",
		CreatedAt:      time.Now(),
	}

	// Store and verify
	store.Set(session.ID, session)
	_, err = store.Get(session.ID)
	require.NoError(t, err)

	// Delete
	store.Delete(session.ID)

	// Should not exist
	_, err = store.Get(session.ID)
	assert.Error(t, err)
}

func TestSessionStore_MultipleSessionsIndependent(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := NewSessionStore(3600*time.Second, log)
	defer store.Close()

	session1 := &SAMLSession{
		ID:             "session-1",
		CredentialType: "pid",
		IDPEntityID:    "https://idp1.example.com",
		CreatedAt:      time.Now(),
	}

	session2 := &SAMLSession{
		ID:             "session-2",
		CredentialType: "diploma",
		IDPEntityID:    "https://idp2.example.com",
		CreatedAt:      time.Now(),
	}

	// Store both
	store.Set(session1.ID, session1)
	store.Set(session2.ID, session2)

	// Retrieve independently
	retrieved1, err := store.Get(session1.ID)
	require.NoError(t, err)
	assert.Equal(t, "pid", retrieved1.CredentialType)

	retrieved2, err := store.Get(session2.ID)
	require.NoError(t, err)
	assert.Equal(t, "diploma", retrieved2.CredentialType)

	// Delete one shouldn't affect the other
	store.Delete(session1.ID)

	_, err = store.Get(session1.ID)
	assert.Error(t, err)

	retrieved2Again, err := store.Get(session2.ID)
	require.NoError(t, err)
	assert.Equal(t, session2.ID, retrieved2Again.ID)
}
