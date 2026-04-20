# Changelog

All notable changes to the NSD v19 Prototype will be documented in this file.

## [1.0.1-patch] - 2026-04-20

### Fixed
- **Globals Order**: Moved metrics declarations before class usage in `fusion_pipeline.py` to prevent `NameError`.
- **Unique IDs**: Updated `alert_id` generation to use `uuid4` for sub-millisecond uniqueness.
- **FastAPI Modernization**: Replaced deprecated `@app.on_event("startup")` with `lifespan` context manager.
- **Logging Cleanliness**: Removed redundant `logging.basicConfig` from library modules; centralized in `main.py`.
- **CoT Safety**: Switched to `xml.etree.ElementTree` for CoT XML generation to avoid injection risks from string interpolation.
- **Robust Broadcaster**: Wrapped background broadcaster in try/except to prevent silent crashes on inference errors.
- **Race Condition**: Replaced `clients` list with `asyncio.Lock` protected set for WebSocket management.
- **Swarm Count Clarification**: Renamed `swarm_count` to `swarm_estimate_index` to reflect its heuristic nature.

### Changed
- **Modular API**: Moved route logic from `backend/` to `api/routes.py` and converted `main.py` into a clean entrypoint.
- **Dependency Splitting**: Created `requirements-ml.txt` for optional ML dependencies (onnxruntime, scikit-learn).
- **Security**: Added `APIKeyHeader` dependency for all POST endpoints and sensitive GET routes.

### Removed
- **Security Cleanup**: Removed tracked `.pem` certificate and key files from the repository index.
- **Redundant Code**: Deleted `backend/nsd_api.py` in favor of the unified `api/` package.
