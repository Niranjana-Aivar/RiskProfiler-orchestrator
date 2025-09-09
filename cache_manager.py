import logging
from typing import Dict, Any, Optional
from datetime import datetime

from config import settings

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages in-memory cache for organization and scan data"""
    
    def __init__(self):
        self.cache_enabled = settings.CACHE_ENABLED
        self.log_level = settings.CACHE_LOG_LEVEL
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_stats = {
            "hits": 0,
            "misses": 0,
            "builds": 0,
            "errors": 0
        }
    
    def _log(self, level: str, message: str):
        """Log cache operations based on configured log level"""
        if not self.cache_enabled:
            return
            
        log_levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
        current_level = log_levels.get(self.log_level, 20)
        message_level = log_levels.get(level, 20)
        
        if message_level >= current_level:
            logger.log(message_level, f"[CACHE] {message}")
    
    def get_cache_key(self, organization_id: str, scan_id: str) -> str:
        """Generate cache key for organization and scan"""
        return f"{organization_id}:{scan_id}"
    
    def has_cache(self, organization_id: str, scan_id: str) -> bool:
        """Check if cache exists for organization and scan"""
        cache_key = self.get_cache_key(organization_id, scan_id)
        has_cache = cache_key in self._cache
        if has_cache:
            self._cache_stats["hits"] += 1
            self._log("DEBUG", f"Cache HIT for {cache_key}")
        else:
            self._cache_stats["misses"] += 1
            self._log("DEBUG", f"Cache MISS for {cache_key}")
        return has_cache
    
    def get_cache(self, organization_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get cache for organization and scan"""
        cache_key = self.get_cache_key(organization_id, scan_id)
        return self._cache.get(cache_key)
    
    def set_cache(self, organization_id: str, scan_id: str, cache_data: Dict[str, Any]):
        """Set cache for organization and scan"""
        if not self.cache_enabled:
            return
            
        cache_key = self.get_cache_key(organization_id, scan_id)
        self._cache[cache_key] = cache_data
        self._cache_stats["builds"] += 1
        self._log("INFO", f"Cache BUILT for {cache_key} with {len(cache_data)} tables")
    
    def clear_cache(self, organization_id: str, scan_id: str):
        """Clear cache for specific organization and scan"""
        cache_key = self.get_cache_key(organization_id, scan_id)
        if cache_key in self._cache:
            del self._cache[cache_key]
            self._log("DEBUG", f"Cache CLEARED for {cache_key}")
    
    def clear_all_cache(self):
        """Clear all cached data"""
        cache_count = len(self._cache)
        self._cache.clear()
        self._log("INFO", f"All cache cleared ({cache_count} entries)")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._cache_stats["hits"] + self._cache_stats["misses"]
        hit_rate = (self._cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "enabled": self.cache_enabled,
            "cache_entries": len(self._cache),
            "hits": self._cache_stats["hits"],
            "misses": self._cache_stats["misses"],
            "builds": self._cache_stats["builds"],
            "errors": self._cache_stats["errors"],
            "hit_rate_percent": round(hit_rate, 2)
        }
    
    def log_cache_stats(self):
        """Log current cache statistics"""
        stats = self.get_cache_stats()
        self._log("INFO", f"Cache Stats: {stats}")


async def build_org_data_cache(db_manager, organization_id: str, scan_id: str) -> Dict[str, Any]:
    """Build comprehensive cache for organization and scan data"""
    cache_manager = CacheManager()
    
    if not cache_manager.cache_enabled:
        cache_manager._log("DEBUG", "Cache disabled, returning empty cache")
        return {}
    
    cache_key = cache_manager.get_cache_key(organization_id, scan_id)
    cache_manager._log("INFO", f"Building cache for {cache_key}")
    
    cache = {}
    start_time = datetime.now()
    
    try:
        # PostgreSQL tables (require scan_id)
        try:
            cache['Findings'] = await db_manager.get_findings_by_scan(scan_id)
            cache_manager._log("DEBUG", f"Fetched {len(cache['Findings'])} findings")
        except Exception as e:
            cache_manager._log("ERROR", f"Failed to fetch Findings: {e}")
            cache_manager._cache_stats["errors"] += 1
            # Fallback: will be handled by individual DB calls
        
        # DynamoDB tables (require organization_id)
        dynamodb_tables = [
            ('OrganizationCVEsV2', 'get_organization_cves'),
            ('OrganizationDNS', 'get_organization_dns'),
            ('OrganizationIPRanges', 'get_organization_ip_ranges'),
            ('OrganizationLoginURLs', 'get_organization_login_urls'),
            ('OrganizationEmailAddresses', 'get_organization_email_addresses'),
            ('OrganizationEmailBreaches', 'get_organization_email_breaches'),
            ('OrganizationAPIs', 'get_organization_apis'),
            ('OrganizationObjectStorages', 'get_organization_object_storages'),
            ('OrganizationCDNs', 'get_organization_cdns'),
            ('OrganizationDomainNames', 'get_organization_domain_names'),
        ]
        
        for table_name, method_name in dynamodb_tables:
            try:
                method = getattr(db_manager, method_name)
                data = await method(organization_id)
                cache[table_name] = data
                cache_manager._log("DEBUG", f"Fetched {len(data)} records from {table_name}")
            except Exception as e:
                cache_manager._log("ERROR", f"Failed to fetch {table_name}: {e}")
                cache_manager._cache_stats["errors"] += 1
                # Fallback: will be handled by individual DB calls
        
        # PostgreSQL tables (require organization_id)
        postgresql_tables = [
            ('PhishingResults', 'get_phishing_results'),
            ('OrganizationTyposquattingDomain', 'get_typosquatting_domains'),
            ('LogoAbuseFindings', 'get_logo_abuse_findings'),
            ('PortfolioDomains', 'get_portfolio_domains'),
        ]
        
        for table_name, method_name in postgresql_tables:
            try:
                method = getattr(db_manager, method_name)
                data = await method(organization_id)
                cache[table_name] = data
                cache_manager._log("DEBUG", f"Fetched {len(data)} records from {table_name}")
            except Exception as e:
                cache_manager._log("ERROR", f"Failed to fetch {table_name}: {e}")
                cache_manager._cache_stats["errors"] += 1
                # Fallback: will be handled by individual DB calls
        
        # Store cache
        cache_manager.set_cache(organization_id, scan_id, cache)
        
        # Log build completion
        build_time = (datetime.now() - start_time).total_seconds()
        cache_manager._log("INFO", f"Cache build completed in {build_time:.2f}s for {cache_key}")
        
        return cache
        
    except Exception as e:
        cache_manager._log("ERROR", f"Failed to build cache for {cache_key}: {e}")
        cache_manager._cache_stats["errors"] += 1
        return {}


# Global cache manager instance
cache_manager = CacheManager()
