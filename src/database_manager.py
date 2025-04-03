# src/database_manager.py

import sqlite3
import time
import logging
import asyncio
import json 
import os
from typing import Optional, Dict, Any

# Use aiosqlite for async database operations
try:
    import aiosqlite
except ImportError:
    aiosqlite = None # Flag that it's missing

logger = logging.getLogger(__name__)

# --- Database Schema Reminder ---
# CREATE TABLE IF NOT EXISTS vt_cache (
#     indicator TEXT PRIMARY KEY, -- IP, URL, or hash
#     indicator_type TEXT NOT NULL CHECK(indicator_type IN ('ip', 'url', 'hash')),
#     result TEXT NOT NULL, -- JSON string of the VT result attributes
#     timestamp INTEGER NOT NULL -- Unix timestamp of when the result was stored
# );
# CREATE INDEX IF NOT EXISTS idx_vt_cache_timestamp ON vt_cache (timestamp);

class DatabaseManager:
    """
    Manages the SQLite database connection and caching operations for VirusTotal results
    using asynchronous I/O with aiosqlite.

    Handles creating the necessary table, storing results, retrieving fresh results,
    and pruning old entries based on a configurable cache duration.
    """

    def __init__(self, db_path: str, cache_duration_seconds: int):
        """
        Initializes the DatabaseManager.

        Args:
            db_path (str): The file path for the SQLite database.
            cache_duration_seconds (int): How long cache entries should be considered valid (in seconds).
        """
        if aiosqlite is None:
            # Log an error, but allow the class to instantiate. 
            logger.error("aiosqlite library is not installed. Database caching will be DISABLED.")
            # raise ImportError("aiosqlite is required for DatabaseManager but not found.")
        self.db_path = db_path
        self.cache_duration_seconds = cache_duration_seconds
        
        self._init_lock = asyncio.Lock()
        self._db_initialized = False # Flag to avoid repeated init attempts after first success/failure

    async def _get_connection(self) -> Optional[aiosqlite.Connection]:
        """
        Establishes and returns an async database connection.

        Ensures the parent directory for the database file exists.

        Returns:
            Optional[aiosqlite.Connection]: An active aiosqlite connection object, or None if aiosqlite
                                             is not installed or connection fails.
        """
        if aiosqlite is None:
            return None

        try:
            # Ensure the directory for the database file exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, exist_ok=True)
                    logger.info(f"Created database directory: {db_dir}")
                except OSError as e:
                    logger.error(f"Failed to create database directory {db_dir}: {e}")
                    return None 

            # Connect using aiosqlite
            
            conn = await aiosqlite.connect(self.db_path, isolation_level=None)
            # Using Row factory allows accessing columns by name (e.g., row['timestamp'])
            conn.row_factory = aiosqlite.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database {self.db_path}: {e}")
            return None
        except Exception as e: # Catch other potential errors like file system permissions
            logger.error(f"Unexpected error connecting to database {self.db_path}: {e}")
            return None


    async def init_db(self) -> None:
        """
        Initializes the database by creating the cache table and index if they don't exist.

        This method uses a lock and a flag to ensure it only attempts initialization once effectively.
        """
        if aiosqlite is None or self._db_initialized:
             # Skip if library missing or already initialized (or failed initialization)
             return

        async with self._init_lock: # Ensure only one coroutine initializes
             if self._db_initialized: # Double-check inside lock
                  return

             conn = await self._get_connection()
             if not conn:
                 logger.error("Database connection not available, cannot initialize DB schema.")
                 self._db_initialized = True # Mark as 'initialization attempted' even on failure to prevent retries
                 return
             try:
                 # Use async cursor for executing SQL commands
                 async with conn.cursor() as cursor:
                     # Create the cache table if it doesn't exist
                     await cursor.execute("""
                         CREATE TABLE IF NOT EXISTS vt_cache (
                             indicator TEXT PRIMARY KEY,
                             indicator_type TEXT NOT NULL CHECK(indicator_type IN ('ip', 'url', 'hash')),
                             result TEXT NOT NULL, -- Storing VT result attributes as JSON string
                             timestamp INTEGER NOT NULL -- Unix timestamp
                         )
                     """)
                     # Create an index on the timestamp for efficient pruning
                     await cursor.execute("""
                         CREATE INDEX IF NOT EXISTS idx_vt_cache_timestamp ON vt_cache (timestamp)
                     """)
                 await conn.commit() # Explicit commit (though autocommit might be active)
                 self._db_initialized = True # Mark initialization as successful
                 logger.info(f"Database schema initialized successfully at {self.db_path}")
             except sqlite3.Error as e:
                 logger.error(f"Failed to initialize database schema: {e}")
                 self._db_initialized = True # Mark as attempted even on failure
             finally:
                  if conn:
                      await conn.close()


    async def get_cached_result(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a cached VirusTotal result if it exists and is within the cache duration.

        Args:
            indicator (str): The indicator (IP, URL, hash) to look up.
            indicator_type (str): The type of indicator ('ip', 'url', 'hash').

        Returns:
            Optional[Dict[str, Any]]: The cached result dictionary (parsed from JSON) if found
                                      and fresh, otherwise None.
        """
        if aiosqlite is None:
            return None

        # Ensure DB schema is initialized before trying to query
        await self.init_db()
        if not self._db_initialized: # Check if initialization succeeded
             logger.warning("Database not initialized, cannot retrieve cached result.")
             # This condition might be too strict if init failed due to transient issues,
             # but safer than trying to query a non-existent table.

             return None


        conn = await self._get_connection()
        if not conn:
             return None # Connection failed

        cached_data = None
        try:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT result, timestamp FROM vt_cache WHERE indicator = ? AND indicator_type = ?",
                    (indicator, indicator_type)
                )
                row = await cursor.fetchone()

            if row:
                timestamp = row["timestamp"]
                current_time = time.time()
                # Check if the cached entry is still valid based on duration
                if (current_time - timestamp) < self.cache_duration_seconds:
                    logger.debug(f"Cache hit for {indicator_type}: {indicator}")
                    try:
                        # Parse the stored JSON string back into a Python dictionary
                        cached_data = json.loads(row["result"])
                    except json.JSONDecodeError as e:
                         logger.error(f"Failed to decode cached JSON for {indicator_type} '{indicator}': {e}. Discarding corrupted cache entry.")
                         # Proactively delete the corrupted entry
                         await self.delete_cached_result(indicator, indicator_type)
                         cached_data = None # Ensure None is returned
                    except Exception as e: # Catch other potential errors during loading
                         logger.error(f"Unexpected error loading cached data for {indicator_type} '{indicator}': {e}")
                         cached_data = None
                else:
                    logger.debug(f"Cache expired for {indicator_type}: {indicator} (age: {current_time - timestamp:.0f}s > threshold: {self.cache_duration_seconds}s)")
                    
                    
                    cached_data = None
            else:
                logger.debug(f"Cache miss for {indicator_type}: {indicator}")
                cached_data = None
        except sqlite3.Error as e:
            logger.error(f"Database error retrieving cached result for {indicator_type} '{indicator}': {e}")
            cached_data = None
        except Exception as e:
            logger.error(f"Unexpected error retrieving cached result for {indicator_type} '{indicator}': {e}")
            cached_data = None
        finally:
             if conn:
                 await conn.close()

        return cached_data

    async def store_result(self, indicator: str, indicator_type: str, result: Dict[str, Any]) -> None:
        """
        Stores or updates a VirusTotal result in the cache database.

        Args:
            indicator (str): The indicator (IP, URL, hash) being stored.
            indicator_type (str): The type of indicator ('ip', 'url', 'hash').
            result (Dict[str, Any]): The VirusTotal result attributes dictionary to store (will be JSON serialized).
        """
        if aiosqlite is None:
            return # Caching disabled

        await self.init_db()
        if not self._db_initialized:
             logger.warning("Database not initialized, cannot store result.")
             return

        conn = await self._get_connection()
        if not conn:
             return

        try:
            # Convert the result dictionary to a JSON string for database storage
            result_json = json.dumps(result)
            current_time = int(time.time()) # Use integer timestamp

            async with conn.cursor() as cursor:
                # Use INSERT OR REPLACE to handle both new entries and updates to existing ones based on the PRIMARY KEY (indicator)
                await cursor.execute(
                    "INSERT OR REPLACE INTO vt_cache (indicator, indicator_type, result, timestamp) VALUES (?, ?, ?, ?)",
                    (indicator, indicator_type, result_json, current_time)
                )
            await conn.commit() # Ensure change is saved (though autocommit might be active)
            logger.debug(f"Stored/Updated cache for {indicator_type}: {indicator}")
        except sqlite3.Error as e:
            logger.error(f"Database error storing result for {indicator_type} '{indicator}': {e}")
        except TypeError as e: # Could happen if 'result' is not JSON serializable
            logger.error(f"Failed to serialize result to JSON for {indicator_type} '{indicator}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error storing result for {indicator_type} '{indicator}': {e}")
        finally:
             if conn:
                 await conn.close()

    async def delete_cached_result(self, indicator: str, indicator_type: str) -> None:
        """
        Deletes a specific cached result from the database.

        Args:
            indicator (str): The indicator (IP, URL, hash) to delete.
            indicator_type (str): The type of indicator ('ip', 'url', 'hash').
        """
        if aiosqlite is None:
            return

        # No need to wait for init_db here, deleting non-existent rows is fine.
        conn = await self._get_connection()
        if not conn:
             return
        try:
            async with conn.cursor() as cursor:
                 await cursor.execute(
                    "DELETE FROM vt_cache WHERE indicator = ? AND indicator_type = ?",
                    (indicator, indicator_type)
                 )
            await conn.commit()
            logger.debug(f"Deleted cached result (if existed) for {indicator_type}: {indicator}")
        except sqlite3.Error as e:
            logger.error(f"Database error deleting cached result for {indicator_type} '{indicator}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error deleting cache for {indicator_type} '{indicator}': {e}")
        finally:
             if conn:
                 await conn.close()

    async def prune_old_cache(self) -> None:
        """
        Removes cache entries older than the configured cache duration threshold.
        """
        if aiosqlite is None:
            return

        # Ensure DB is initialized before pruning, otherwise the table might not exist.
        await self.init_db()
        if not self._db_initialized:
             logger.warning("Database not initialized, cannot prune cache.")
             return

        conn = await self._get_connection()
        if not conn:
             return

        cutoff_time = int(time.time()) - self.cache_duration_seconds
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("DELETE FROM vt_cache WHERE timestamp < ?", (cutoff_time,))
                changes = conn.total_changes 
                
            await conn.commit()
            # cursor.rowcount might be unreliable for DELETE in sqlite
            
            logger.info(f"Pruned cache entries older than {self.cache_duration_seconds} seconds (timestamp < {cutoff_time}).")
        except sqlite3.Error as e:
            logger.error(f"Database error pruning old cache entries: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during cache pruning: {e}")

        finally:
             if conn:
                 await conn.close()


