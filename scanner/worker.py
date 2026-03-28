"""
scanner/worker.py — NSD v19 Background Scan Worker
ChaosTech Defense LLC

This module is retained for reference / legacy compatibility but is
NO LONGER THE PRIMARY SCAN DRIVER in v19.

In v19, the scan loop runs as an asyncio task inside api/routes.py
(_broadcast_loop). SDRScanner + ThreatClassifier handle all RF work.
NSDState.cache is updated by _broadcast_loop, not this file.

This file is kept so that any code still importing from scanner.worker
does not throw an ImportError at startup.
"""

import logging
logger = logging.getLogger("nsd.worker")


def start_scanner():
    """
    No-op stub. In v19, the scanner is started by the FastAPI lifespan
    in api/routes.py. Calling this function has no effect.
    """
    logger.warning(
        "scanner.worker.start_scanner() called but has no effect in v19. "
        "The scanner is managed by the FastAPI lifespan context."
    )
