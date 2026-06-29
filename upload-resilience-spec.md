# Upload Resilience & Backend Connection Handling — Specification

> **Status:** Draft  
> **Created:** 2026-06-26  
> **Scope:** Frontend (`frontend/src/App.jsx`, `frontend/src/components/UploadPanel.jsx`) + Backend (`backend/main.py`)

---

## 1. Problem Statement

When a user attempts to upload an APK via the DroidForensix frontend, the upload fails if the backend at `http://localhost:8000` is not reachable. Currently:

- The error is surfaced via a raw `alert()` with a generic "Cannot reach the backend" message
- No auto-retry mechanism exists — the user must manually re-upload
- No structured error codes or detailed feedback are provided to the user
- File validation is minimal (extension + rough size check only)
- No mechanism to auto-start or prompt the user to start the backend
- The WebSocket connection and HTTP upload are not coordinated in retry logic

**User-reported symptom:**  
> "Upload failed: Cannot reach the backend. Ensure the backend is running at http://localhost:8000 (run run_backend.bat or 'python -m uvicorn backend.main:app --port 8000' from the backend/ directory)."

---

## 2. Goals

| # | Goal | Priority |
|---|------|----------|
| G1 | Fix root cause: ensure backend connection is robust and diagnosable | High |
| G2 | Replace `alert()` errors with structured inline error messages + toast notifications | High |
| G3 | Implement auto-retry with visible progress bar for failed uploads | High |
| G4 | Add full client + server-side file validation with clear error feedback | High |
| G5 | Add an "Auto-start Backend" button in the UI | Medium |
| G6 | Maintain unified retry logic for both HTTP and WebSocket connections | Medium |
| G7 | Remember the selected file during retry attempts (don't discard it) | High |

---

## 3. Current Architecture (As-Is)

### 3.1 Upload Flow
```
User selects file (UploadPanel)
  → onUpload(file) callback
    → handleUpload(file) in App.jsx
      → Frontend validation: .apk extension + 100MB size check
      → POST ${API_URL}/api/upload (FormData)
        → On success: update state, trigger analyzeUpload()
        → On failure: alert() with generic message
```

### 3.2 Error Handling
- **Backend unreachable:** Catches `Failed to fetch` → `alert("Upload failed: Cannot reach the backend...")`
- **Timeout:** Catches `AbortError` after 5min → `alert("Upload timed out...")`
- **Other errors:** `alert("Upload failed: " + error.message)`
- **No structured error codes** returned from the server

### 3.3 Backend Health Check
- One-time `fetch(${API_URL}/)` on component mount
- Sets `backendReady` boolean → status dot in topbar
- No periodic re-checks

### 3.4 WebSocket
- Connects on mount, auto-reconnects on close (3s delay)
- Independent of HTTP upload flow

---

## 4. Desired Architecture (To-Be)

### 4.1 Enhanced Error Feedback (G2)

#### 4.1.1 Toast Notifications
- Use a lightweight toast system (e.g., `react-hot-toast` or a custom implementation)
- Toasts auto-dismiss after 5 seconds for transient errors
- Toasts remain until dismissed for critical errors (e.g., "Backend unreachable")
- Toast categories: `info`, `warning`, `error`, `success`

#### 4.1.2 Inline Error Messages
- Display errors directly below the upload dropzone
- Error messages are structured and actionable:
  - **File too large:** "File is 120MB. Maximum allowed size is 100MB."
  - **Invalid file type:** "Only .apk files are supported. Your file is .zip."
  - **Backend unreachable:** "Cannot reach the backend at http://localhost:8000. Check that the backend is running."
  - **Server error (500):** "The server encountered an error. Check the backend logs for details."
  - **Rate limited (429):** "Too many requests. Please wait a moment and try again."
  - **File corrupted:** "The uploaded file appears to be corrupted or incomplete."

#### 4.1.3 Error Code Mapping
| HTTP Status | Frontend Message | Toast Type |
|-------------|------------------|------------|
| 400 | "Invalid request: {detail}" | error |
| 413 | "File too large ({size}MB). Maximum: {max}MB" | error |
| 422 | "Validation failed: {detail}" | error |
| 429 | "Too many requests. Please wait." | warning |
| 500 | "Server error. Check backend logs." | error |
| 503 | "Backend is starting up. Retrying..." | info |
| Network | "Cannot reach backend. Retrying..." | warning |

---

### 4.2 Auto-Retry Mechanism (G3, G7)

#### 4.2.1 Retry Behavior
- **Initial attempt:** Immediate on file selection
- **On failure:** Auto-retry after 2-second delay
- **Max retries:** 5 attempts (configurable)
- **Backoff:** Exponential backoff with jitter (2s, 4s, 8s, 16s, 32s max)
- **File retention:** Selected file is kept in memory during all retry attempts
- **Abort:** User can click "Cancel" to abort retry loop

#### 4.2.2 Retry UI — Progress Bar
- A visible progress bar appears below the upload dropzone during retries
- Shows:
  - Current attempt number (e.g., "Attempt 3 of 5")
  - Time since first attempt
  - A "Cancel" button to abort
- Visual states:
  - **Idle:** No progress bar shown
  - **Retrying:** Progress bar with attempt count and backoff timer
  - **Failed (exhausted):** Error message with "Try Again" and "Start Backend" buttons
  - **Succeeded:** Success toast + transition to analysis view

#### 4.2.3 Retry Flow Diagram
```
User selects file
  → Client validation
    → Fail? → Show inline error, stop
    → Pass? → POST /api/upload
      → Success → trigger analysis
      → Network error / 5xx / timeout
        → Show toast: "Retrying... attempt 1/5"
        → Show progress bar
        → Wait (exponential backoff)
        → Retry POST /api/upload
          → ... (repeat up to 5 times)
        → All retries exhausted
          → Show error: "Upload failed after 5 attempts"
          → Show buttons: [Try Again] [Start Backend]
```

---

### 4.3 Client + Server File Validation (G4)

#### 4.3.1 Client-Side Validation (Before Upload)
| Check | Condition | Error |
|-------|-----------|-------|
| File extension | Must be `.apk` | "Only .apk files are supported" |
| MIME type | `application/vnd.android.package-archive` | "File doesn't appear to be an APK" |
| File size | ≤ 100MB | "File is too large ({size}MB). Max: 100MB" |
| File header (magic bytes) | ZIP header `PK\x03\x04` | "File is not a valid APK (bad header)" |
| Non-empty | `file.size > 0` | "File is empty" |

#### 4.3.2 Server-Side Validation (On Upload)
| Check | Condition | HTTP Status | Response |
|-------|-----------|-------------|----------|
| File size | ≤ MAX_UPLOAD_SIZE_MB | 413 | `{ detail: "File too large..." }` |
| Valid ZIP/APK | Read header bytes | 400 | `{ detail: "Invalid APK file..." }` |
| Filename | Non-empty, valid chars | 400 | `{ detail: "Invalid filename..." }` |
| Disk space | Sufficient space | 507 | `{ detail: "Insufficient disk space..." }` |
| Duplicate hash | SHA-256 exists | 200 | Return existing upload_id (dedup) |

---

### 4.4 Auto-Start Backend Button (G5)

#### 4.4.1 Behavior
- When backend is unreachable, show a "Start Backend" button in the upload area
- Button triggers a `POST /api/start-backend` endpoint (new backend endpoint)
- The backend cannot self-start, so this button should:
  1. Attempt to reach the backend
  2. If unreachable, show instructions: "Run `run_backend.bat` from the project root"
  3. Display the exact command in a copyable code block
- The button then starts polling the backend health endpoint every 2 seconds
- Once backend responds, auto-dismiss the instruction panel

#### 4.4.2 Backend Health Endpoint
```
GET / → { "status": "ok", "version": "1.0.0" }
```
- Frontend polls this endpoint every 5 seconds when backend is offline
- On first successful response, show toast: "Backend is online"

---

### 4.5 Unified HTTP + WebSocket Retry (G6)

#### 4.5.1 Coordinated Connection State
- Introduce a `connectionState` context that tracks:
  - `http`: "connected" | "reconnecting" | "failed"
  - `websocket`: "connected" | "reconnecting" | "failed"
- The status dot in the topbar reflects the combined state:
  - 🟢 Green: Both HTTP and WS connected
  - 🟡 Yellow: One or both reconnecting
  - 🔴 Red: Both failed

#### 4.5.2 Retry Coordination
- HTTP upload retry and WS reconnect are independent but share the same backoff state
- When either reconnects, reset the backoff for the other
- Both use the same max retry count (5 attempts)

---

## 5. UI Mockups

### 5.1 Upload Area — Error State
```
┌─────────────────────────────────────────────┐
│           📦 Drop your APK here              │
│     or click below to browse your device     │
│                                              │
│            [ Browse Files ]                  │
│                                              │
│      APK files only • Max 100MB              │
├─────────────────────────────────────────────┤
│ ⚠️ Cannot reach backend at localhost:8000    │
│ Attempt 3 of 5 • Retrying in 8s...          │
│ [████████░░░░░░░░░░░░] 40%                  │
│                        [ Cancel ]            │
├─────────────────────────────────────────────┤
│ ℹ️ Run: python -m uvicorn backend.main:app  │
│    --port 8000                              │
│                          [ Copy ] [ Start Backend ] │
└─────────────────────────────────────────────┘
```

### 5.2 Upload Area — Validation Error
```
┌─────────────────────────────────────────────┐
│           📦 Drop your APK here              │
│     or click below to browse your device     │
│                                              │
│            [ Browse Files ]                  │
│                                              │
│      APK files only • Max 100MB              │
├─────────────────────────────────────────────┤
│ ❌ File too large: 120MB. Maximum: 100MB     │
└─────────────────────────────────────────────┘
```

### 5.3 Status Dot (Topbar) — Reconnecting
```
┌─────────────────────────────────────────────┐
│ ☰  Upload & Analyze                         │
│                     🟡 Reconnecting...       │
└─────────────────────────────────────────────┘
```

---

## 6. Toast Notification System

### 6.1 Toast Types
| Type | Icon | Color | Auto-dismiss |
|------|------|-------|--------------|
| `success` | ✅ | Green | 3 seconds |
| `info` | ℹ️ | Blue | 5 seconds |
| `warning` | ⚠️ | Yellow | 8 seconds |
| `error` | ❌ | Red | Manual dismiss |

### 6.2 Toast Examples
| Event | Toast |
|-------|-------|
| Upload started | ℹ️ "Uploading APK..." (info) |
| Upload succeeded | ✅ "Upload complete. Starting analysis..." (success) |
| Backend unreachable | ⚠️ "Cannot reach backend. Retrying..." (warning) |
| Upload failed (exhausted) | ❌ "Upload failed after 5 attempts" (error) |
| Backend came back online | ✅ "Backend is online" (success) |
| File too large | ❌ "File is 120MB. Max: 100MB" (error) |
| Invalid file type | ❌ "Only .apk files are supported" (error) |

---

## 7. Files to Modify

| File | Changes |
|------|---------|
| `frontend/src/App.jsx` | Refactor `handleUpload`, add retry logic, connection state, toast integration |
| `frontend/src/components/UploadPanel.jsx` | Add inline error display, progress bar, validation UI, "Start Backend" button |
| `frontend/src/styles/UploadPanel.css` | New styles for error states, progress bar, retry UI |
| `backend/main.py` | Add server-side validation improvements, structured error responses |
| `backend/config.py` | Ensure `MAX_UPLOAD_SIZE_MB` is consistent with frontend |

---

## 8. New Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| `react-hot-toast` | Toast notification system | `npm install react-hot-toast` |

> Note: If avoiding new dependencies, a lightweight custom toast component (~50 lines) can be used instead.

---

## 9. Success Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| SC1 | No `alert()` calls remain in upload flow | `grep -r "alert(" frontend/src/App.jsx` returns 0 matches |
| SC2 | Inline error messages shown for all validation failures | Manual test: try uploading .zip, >100MB, empty file |
| SC3 | Auto-retry works with progress bar | Manual test: stop backend, upload file, verify retry UI |
| SC4 | File is remembered during retry | Manual test: upload, stop backend mid-retry, verify file not lost |
| SC5 | Backend auto-start button works | Manual test: click button, see instructions, verify polling |
| SC6 | Status dot reflects connection state | Manual test: stop/start backend, verify dot changes color |
| SC7 | Toasts appear for all upload events | Manual test: verify each event from Section 6.2 |
| SC8 | Server returns structured error JSON | `curl -X POST /api/upload -F "file=@large.apk"` returns `{ detail: "..." }` |
| SC9 | WebSocket reconnect coordinates with HTTP retry | Manual test: verify both retry independently |
| SC10 | All existing tests pass | `npm test` (if tests exist) |

---

## 10. Edge Cases & Constraints

| Case | Expected Behavior |
|------|-------------------|
| User selects file while retry is in progress | Ignore new selection until retry completes or is cancelled |
| Backend returns 413 (too large) | Show error immediately, don't retry |
| Backend returns 500 (internal error) | Retry up to 5 times, then show error |
| Backend returns 422 (validation error) | Show error immediately, don't retry |
| Network timeout (>30s) | Treat as connection failure, retry |
| User navigates away during retry | Cancel retry, discard file |
| Multiple rapid file selections | Only process the most recent selection |
| Backend is behind a proxy/load balancer | Health check must succeed through the proxy |
| Ollama not running (backend starts but LLM fails) | Backend is "online" but LLM features degrade gracefully |
| File is a valid APK but backend rejects it | Show server's error message, don't retry |

---

## 11. Open Questions

| # | Question | Status |
|---|----------|--------|
| OQ1 | Should the toast system be a new component or use an existing library? | Pending — suggest `react-hot-toast` or custom |
| OQ2 | Should the "Start Backend" button attempt to execute a command or just show instructions? | Resolved — show instructions + polling |
| OQ3 | What is the max file size the backend actually supports? | Check `settings.MAX_UPLOAD_SIZE_MB` in `backend/config.py` |
| OQ4 | Should the retry count be configurable via `.env` or hardcoded? | Pending — suggest hardcoded at 5 |
| OQ5 | Is the upload progress bar realistic (actual bytes sent) or simulated? | Currently simulated — consider real XHR progress |

---

## 12. Implementation Order

| Phase | Tasks | Estimated Effort |
|-------|-------|------------------|
| **Phase 1** | Toast system + inline errors (replace all `alert()` calls) | Small |
| **Phase 2** | Client-side validation (extension, MIME, size, header) | Small |
| **Phase 3** | Server-side validation + structured error responses | Small |
| **Phase 4** | Auto-retry with progress bar | Medium |
| **Phase 5** | "Start Backend" button + health polling | Small |
| **Phase 6** | Unified connection state (HTTP + WS) | Medium |
| **Phase 7** | Testing + polish | Small |

---

## 13. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Adding `react-hot-toast` increases bundle size | Low | Use custom toast (~50 lines) if bundle size is a concern |
| Auto-retry floods backend with requests | Medium | Exponential backoff + max 5 retries |
| File retention during retry uses memory | Low | Files are small APKs (<100MB), memory is fine |
| Backend auto-start instructions may be wrong on different OS | Medium | Detect OS and show correct command |
| Retry state lost on page refresh | Low | Acceptable — user re-selects file |
