import asyncio
import asyncpg
import boto3
import aioboto3
from typing import List, Dict, Any, Optional, Tuple
import json
import logging
from datetime import datetime, timedelta

from config import settings
from database_config import is_postgresql_table, is_dynamodb_table
# Removed Pydantic model imports - returning raw dictionaries instead

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self):
        self.pg_pool = None
        self.dynamo_session = None
        self.dynamo_client = None
        
    async def initialize(self):
        """Initialize database connections"""
        try:
            # Initialize PostgreSQL connection pool
            self.pg_pool = await asyncpg.create_pool(
                host=settings.POSTGRES_HOST,
                port=settings.POSTGRES_PORT,
                database=settings.POSTGRES_DB,
                user=settings.POSTGRES_USER,
                password=settings.POSTGRES_PASSWORD,
                min_size=5,
                max_size=20
            )
            
            # Initialize DynamoDB session
            session = aioboto3.Session()
            self.dynamo_session = session
            # Note: We don't create a client here to avoid un-awaited coroutine warnings
            # Clients are created per-query using async with self.dynamo_session.client(...)
            
            logger.info("Database connections initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database connections: {e}")
            raise
    
    async def get_data_dynamic_postgres(self, table: str, organization_id: str, scan_id: str, where_conditions: Dict[str, List[Any]] = None, columns: List[str] = None) -> List[Dict[str, Any]]:
        """Dynamic PostgreSQL query with WHERE conditions"""
        logger.debug(f"Dynamic PostgreSQL query for table {table}")
        
        if not self.pg_pool:
            logger.error("PostgreSQL connection not available")
            return []
        
        try:
            # Special handling for Findings table
            if table == "Findings":
                # Build column selection for Findings
                if columns:
                    column_list = ', '.join([f'"{col}"' for col in columns])
                    base_query = f'SELECT {column_list} FROM "{table}" WHERE scan_id = $1'
                    logger.debug(f"Selecting specific columns for Findings: {columns}")
                else:
                    base_query = f'SELECT * FROM "{table}" WHERE scan_id = $1'
                    logger.debug("Selecting all columns for Findings table")
                
                args = [scan_id]
                param_count = 1
                
                # Add is_snoozed and is_whitelisted filters for Findings
                param_count += 1
                base_query += f' AND (is_snoozed IS NULL OR is_snoozed = ${param_count})'
                args.append(False)
                
                param_count += 1
                base_query += f' AND (is_whitelisted IS NULL OR is_whitelisted = ${param_count})'
                args.append(False)
                
            else:
                # Standard handling for other tables
                if columns:
                    column_list = ', '.join([f'"{col}"' for col in columns])
                    base_query = f'SELECT {column_list} FROM "{table}" WHERE organization_id = $1'
                    logger.debug(f"Selecting specific columns: {columns}")
                else:
                    base_query = f'SELECT * FROM "{table}" WHERE organization_id = $1'
                    logger.debug("Selecting all columns (no specific columns provided)")
                
                args = [organization_id]
                param_count = 1
                
                # Add scan_id condition if provided for non-Findings tables
                if scan_id:
                    param_count += 1
                    base_query += f' AND scan_id = ${param_count}'
                    args.append(scan_id)
            
            # Add WHERE conditions
            if where_conditions:
                for field, values in where_conditions.items():
                    if values:  # Only add condition if we have values
                        # Create placeholders starting from the next parameter number
                        placeholders = ','.join([f'${param_count + i + 1}' for i in range(len(values))])
                        base_query += f' AND "{field}" IN ({placeholders})'
                        args.extend(values)
                        param_count += len(values)
            
            logger.debug(f"Executing query: {base_query}")
            logger.debug(f"Query args: {args}")
            
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(base_query, *args)
                
                # Convert to list of dictionaries
                results = []
                for row in rows:
                    result = dict(row)
                    results.append(result)
                
                logger.info(f"Dynamic PostgreSQL query returned {len(results)} records for table {table}")
                return results
                    
        except Exception as e:
            logger.error(f"Error in dynamic PostgreSQL query for table {table}: {e}")
            return []
    
    async def get_data_dynamic_dynamodb(self, table: str, organization_id: str, scan_id: str, where_conditions: Dict[str, List[Any]] = None, columns: List[str] = None) -> List[Dict[str, Any]]:
        """Dynamic DynamoDB query with WHERE conditions"""
        logger.debug(f"Dynamic DynamoDB query for table {table}")
        
        if not self.dynamo_session:
            logger.error("DynamoDB connection not available")
            return []
        
        # Check if we need to batch the WHERE conditions due to size limits
        if where_conditions:
            total_values = sum(len(values) for values in where_conditions.values())
            if total_values > 100:  # DynamoDB limit is around 100-200 values in FilterExpression
                logger.info(f"Batching DynamoDB query for table {table}: {total_values} values")
                return await self._query_dynamodb_batched(table, organization_id, where_conditions, columns)
        
        try:
            # Build DynamoDB query parameters
            query_params = {
                'TableName': table,
                'KeyConditionExpression': 'organization_id = :org_id',
                'ExpressionAttributeValues': {
                    ':org_id': {'S': organization_id}
                }
            }
            
            # Query all fields (no ProjectionExpression to avoid reserved keyword issues)
            
            # Add WHERE conditions using FilterExpression
            if where_conditions:
                filter_expressions = []
                for field, values in where_conditions.items():
                    if values:
                        # Create placeholder for each value
                        value_placeholders = []
                        for i, value in enumerate(values):
                            placeholder = f':{field}_{i}'
                            # Convert to DynamoDB format
                            if isinstance(value, str):
                                query_params['ExpressionAttributeValues'][placeholder] = {'S': value}
                            elif isinstance(value, (int, float)):
                                query_params['ExpressionAttributeValues'][placeholder] = {'N': str(value)}
                            elif isinstance(value, bool):
                                query_params['ExpressionAttributeValues'][placeholder] = {'BOOL': value}
                            else:
                                query_params['ExpressionAttributeValues'][placeholder] = {'S': str(value)}
                            value_placeholders.append(placeholder)
                        
                        # Add IN condition
                        filter_expressions.append(f'{field} IN ({",".join(value_placeholders)})')
                
                if filter_expressions:
                    query_params['FilterExpression'] = ' AND '.join(filter_expressions)
            
            logger.debug(f"DynamoDB query params: {query_params}")
            
            # Execute query
            async with self.dynamo_session.client('dynamodb') as client:
                response = await client.query(**query_params)
                raw_items = response.get('Items', [])
            
            # Parse DynamoDB items to regular dictionaries
            results = []
            for item in raw_items:
                parsed_item = {}
                for key, value in item.items():
                    if 'S' in value:
                        parsed_item[key] = value['S']
                    elif 'N' in value:
                        try:
                            parsed_item[key] = float(value['N'])
                        except ValueError:
                            parsed_item[key] = value['N']
                    elif 'BOOL' in value:
                        parsed_item[key] = value['BOOL']
                    elif 'L' in value:
                        # Handle lists
                        parsed_item[key] = [self._parse_dynamo_value(v) for v in value['L']]
                    else:
                        parsed_item[key] = value
                results.append(parsed_item)
            
            # Filter columns if specified (since we query all fields)
            if columns:
                filtered_results = []
                for item in results:
                    filtered_item = {col: item.get(col) for col in columns if col in item}
                    filtered_results.append(filtered_item)
                logger.debug(f"Filtered DynamoDB results to columns: {columns}")
                results = filtered_results
            
            logger.info(f"Dynamic DynamoDB query returned {len(results)} records for table {table}")
            return results
            
        except Exception as e:
            logger.error(f"Error in dynamic DynamoDB query for table {table}: {e}")
            return []

    async def _query_dynamodb_batched(self, table: str, organization_id: str, where_conditions: Dict[str, List[Any]], columns: List[str] = None) -> List[Dict[str, Any]]:
        """Batched DynamoDB query to handle large WHERE conditions"""
        all_results = []
        
        # For each field with WHERE conditions, batch the values
        for field, values in where_conditions.items():
            if not values:
                continue
            
            # Check if this field is a primary key (common primary key fields)
            # Note: asset is NOT a primary key for OrganizationCVEsV2 (it's organization_id + date_cve)
            is_primary_key = field in ['ip_range', 'name', 'value', 'domain', 'email']
            
            if is_primary_key:
                # For primary keys, use BatchGetItem for efficient retrieval
                logger.info(f"Using BatchGetItem for {len(values)} primary key values")
                
                # Split into batches of 100 (DynamoDB BatchGetItem limit)
                batch_get_size = 100
                for i in range(0, len(values), batch_get_size):
                    batch_values = values[i:i + batch_get_size]
                    
                    # Prepare keys for BatchGetItem
                    keys = []
                    for value in batch_values:
                        key = {
                            'organization_id': {'S': organization_id},
                            field: {'S': str(value)} if isinstance(value, str) else {'N': str(value)}
                        }
                        keys.append(key)
                    
                    # Prepare request items (no ProjectionExpression to avoid reserved keyword issues)
                    request_item = {'Keys': keys}
                    
                    request_items = {table: request_item}
                    
                    async with self.dynamo_session.client('dynamodb') as client:
                        response = await client.batch_get_item(RequestItems=request_items)
                        raw_items = response.get('Responses', {}).get(table, [])
                        batch_results = self._parse_dynamodb_items(raw_items)
                        all_results.extend(batch_results)
                    
                    logger.info(f"BatchGetItem returned {len(batch_results)} records for batch {i//batch_get_size + 1}")
            else:
                # For non-primary keys, use FilterExpression with IN
                # Split values into batches of 50 (safe size for DynamoDB)
                batch_size = 50
                for i in range(0, len(values), batch_size):
                    batch_values = values[i:i + batch_size]
                    
                    query_params = {
                        'TableName': table,
                        'KeyConditionExpression': 'organization_id = :org_id',
                        'FilterExpression': f'{field} IN ({",".join([f":{field}_{j}" for j in range(len(batch_values))])})',
                        'ExpressionAttributeValues': {
                            ':org_id': {'S': organization_id}
                        }
                    }
                    
                    # Add batch values to expression
                    for j, value in enumerate(batch_values):
                        if isinstance(value, str):
                            query_params['ExpressionAttributeValues'][f':{field}_{j}'] = {'S': value}
                        elif isinstance(value, (int, float)):
                            query_params['ExpressionAttributeValues'][f':{field}_{j}'] = {'N': str(value)}
                        elif isinstance(value, bool):
                            query_params['ExpressionAttributeValues'][f':{field}_{j}'] = {'BOOL': value}
                        else:
                            query_params['ExpressionAttributeValues'][f':{field}_{j}'] = {'S': str(value)}
                    
                    async with self.dynamo_session.client('dynamodb') as client:
                        response = await client.query(**query_params)
                        raw_items = response.get('Items', [])
                        batch_results = self._parse_dynamodb_items(raw_items)
                        all_results.extend(batch_results)
        
        # Remove duplicates (same record might match multiple batches)
        seen = set()
        unique_results = []
        for result in all_results:
            # Create a unique key for each record (handle nested dicts)
            key_items = []
            for k, v in sorted(result.items()):
                if isinstance(v, dict):
                    # Convert dict to string for hashing
                    key_items.append((k, str(sorted(v.items()))))
                else:
                    key_items.append((k, v))
            key = tuple(key_items)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        # Filter columns if specified (since we query all fields)
        if columns:
            filtered_results = []
            for item in unique_results:
                filtered_item = {col: item.get(col) for col in columns if col in item}
                filtered_results.append(filtered_item)
            logger.debug(f"Filtered batched DynamoDB results to columns: {columns}")
            unique_results = filtered_results
        
        logger.info(f"Batched DynamoDB query returned {len(unique_results)} unique records for table {table}")
        return unique_results
    
    def _parse_dynamodb_items(self, raw_items: List[Dict]) -> List[Dict[str, Any]]:
        """Parse DynamoDB items to regular dictionaries"""
        results = []
        for item in raw_items:
            parsed_item = {}
            for key, value in item.items():
                parsed_item[key] = self._parse_dynamo_value(value)
            results.append(parsed_item)
        return results

    async def close(self):
        """Close database connections"""
        if self.pg_pool:
            await self.pg_pool.close()
        logger.info("Database connections closed")
    
    async def get_organization_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get organization by domain from DynamoDB Organizations table"""
        if self.dynamo_session is None:
            raise RuntimeError("DatabaseManager not initialized: dynamo_session is None")
        try:
            # Use boto3 to query DynamoDB
            import boto3
            from boto3.dynamodb.conditions import Key
            
            # Create DynamoDB client
            dynamodb = boto3.resource('dynamodb')
            org_table = dynamodb.Table('Organizations')
            
            # Query the Organizations table using domain as partition key
            response = org_table.query(
                KeyConditionExpression=Key('domain').eq(domain.lower())
            )
            
            items = response.get('Items', [])
            if items:
                # Return the first matching organization ID and latest scan ID
                org_id = items[0].get('id')
                latest_scan_id = items[0].get('latest_scan_id')
                logger.info(f"Found organization: {domain} -> {org_id}, latest_scan_id: {latest_scan_id}")
                return {
                    "id": org_id,
                    "domain": domain,
                    "latest_scan_id": latest_scan_id
                }
            else:
                # If not found by exact domain match, try scanning for partial matches
                scan_response = org_table.scan(
                    FilterExpression="contains(#domain, :org_name)",
                    ExpressionAttributeNames={'#domain': 'domain'},
                    ExpressionAttributeValues={':org_name': domain.lower()}
                )
                
                scan_items = scan_response.get('Items', [])
                if scan_items:
                    org_id = scan_items[0].get('id')
                    latest_scan_id = scan_items[0].get('latest_scan_id')
                    logger.info(f"Found organization by partial match: {domain} -> {org_id}, latest_scan_id: {latest_scan_id}")
                    return {
                        "id": org_id,
                        "domain": domain,
                        "latest_scan_id": latest_scan_id
                    }
                
                # If still not found, return None
                logger.warning(f"No organization found for domain: {domain}")
                return None
                
        except Exception as e:
            logger.error(f"Error querying Organizations table for domain {domain}: {e}")
            raise
    
    async def get_findings_by_scan(self, scan_id: str, rule_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get findings by scan ID with optional rule filtering - matches agent pattern"""
        if self.pg_pool is None:
            raise RuntimeError("DatabaseManager not initialized: pg_pool is None")
        try:
            async with self.pg_pool.acquire() as conn:
                # Base query with whitelist/snooze filtering - matches agent pattern
                base_query = """
                    SELECT scan_id, service_id, rule_id, rule_severity, asset, 
                           additional_info, is_whitelisted, is_snoozed, last_seen
                    FROM "Findings" 
                    WHERE scan_id = $1 
                    AND (is_whitelisted = FALSE OR is_whitelisted IS NULL)
                    AND (is_snoozed = FALSE OR is_snoozed IS NULL)
                """
                
                params = [scan_id]
                
                if rule_ids:
                    placeholders = ','.join(f'${i+2}' for i in range(len(rule_ids)))
                    base_query += f" AND rule_id IN ({placeholders})"
                    params.extend(rule_ids)
                
                base_query += " ORDER BY last_seen DESC"
                
                rows = await conn.fetch(base_query, *params)
                
                findings = []
                for row in rows:
                    additional_info = row['additional_info']
                    if isinstance(additional_info, str):
                        try:
                            additional_info = json.loads(additional_info)
                        except json.JSONDecodeError:
                            additional_info = {}
                    
                    findings.append({
                        "scan_id": row['scan_id'],
                        "service_id": row['service_id'],
                        "rule_id": row['rule_id'],
                        "rule_severity": row['rule_severity'],
                        "asset": row['asset'],
                        "additional_info": additional_info,
                        "is_whitelisted": row['is_whitelisted'],
                        "is_snoozed": row['is_snoozed'],
                        "last_seen": row['last_seen']
                    })
                
                return findings
                
        except Exception as e:
            logger.error(f"Error fetching findings for scan {scan_id}: {e}")
            raise
    
    async def get_organization_cves(self, organization_id: str, assets: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get CVEs for organization from DynamoDB"""
        if self.dynamo_session is None:
            raise RuntimeError("DatabaseManager not initialized: dynamo_session is None")
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                # Build query parameters
                query_params = {
                    'TableName': 'OrganizationCVEsV2',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id}
                    }
                }
                
                # Build filter expressions
                filter_expressions = []
                
                if assets:
                    # Filter by assets if provided
                    asset_placeholders = [f':asset{i}' for i in range(len(assets))]
                    asset_values = {f':asset{i}': {'S': asset} for i, asset in enumerate(assets)}
                    
                    filter_expressions.append(f"asset IN ({', '.join(asset_placeholders)})")
                    query_params['ExpressionAttributeValues'].update(asset_values)
                
                # Combine all filter expressions (only if there are any)
                if filter_expressions:
                    query_params['FilterExpression'] = " AND ".join(filter_expressions)
                
                response = await client.query(**query_params)
                
                cves = []
                for item in response.get('Items', []):
                    try:
                        cve = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "asset": item.get('asset', {}).get('S', ''),
                            "cve": item.get('cve', {}).get('S', ''),
                            "cpe": item.get('cpe', {}).get('S'),
                            "baseSeverity": item.get('baseSeverity', {}).get('S'),
                            "exploitabilityScore": self._parse_dynamo_number(item.get('exploitabilityScore')),
                            "exploit_available": item.get('exploit_available', {}).get('BOOL', False),
                            "is_cisa_kev": item.get('is_cisa_kev', {}).get('BOOL', False),
                            "attackVector": item.get('attackVector', {}).get('S'),
                            "attackComplexity": item.get('attackComplexity', {}).get('S'),
                            "privilegesRequired": item.get('privilegesRequired', {}).get('S'),
                            "scope": item.get('scope', {}).get('S'),
                            "userInteraction": item.get('userInteraction', {}).get('S'),
                            "published_date": self._parse_dynamo_date(item.get('published_date')),
                            "last_modified_date": self._parse_dynamo_date(item.get('last_modified_date')),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        cves.append(cve)
                    except Exception as e:
                        logger.warning(f"Error parsing CVE item: {e}")
                        continue
                
                return cves
                
        except Exception as e:
            logger.error(f"Error fetching CVEs for organization {organization_id}: {e}")
            raise
    
    async def get_organization_dns(self, organization_id: str, record_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get DNS records for organization from DynamoDB"""
        if self.dynamo_session is None:
            raise RuntimeError("DatabaseManager not initialized: dynamo_session is None")
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationDNS',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id}
                    }
                }
                
                if record_types:
                    # Filter by record types if provided
                    type_placeholders = [f':type{i}' for i in range(len(record_types))]
                    type_values = {f':type{i}': {'S': record_type} for i, record_type in enumerate(record_types)}
                    
                    query_params['FilterExpression'] = f"record_type IN ({', '.join(type_placeholders)})"
                    query_params['ExpressionAttributeValues'].update(type_values)
                
                response = await client.query(**query_params)
                
                dns_records = []
                for item in response.get('Items', []):
                    try:
                        dns = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "record_type": item.get('record_type', {}).get('S', ''),
                            "name": item.get('name', {}).get('S', ''),
                            "value": item.get('value', {}).get('S', ''),
                            "asset": item.get('asset', {}).get('S', ''),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        dns_records.append(dns)
                    except Exception as e:
                        logger.warning(f"Error parsing DNS item: {e}")
                        continue
                
                return dns_records
                
        except Exception as e:
            logger.error(f"Error fetching DNS records for organization {organization_id}: {e}")
            raise
    
    async def get_organization_ip_ranges(self, organization_id: str, ip_addresses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get IP ranges for organization from DynamoDB"""
        if self.dynamo_session is None:
            raise RuntimeError("DatabaseManager not initialized: dynamo_session is None")
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationIPRanges',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                if ip_addresses:
                    # Filter by specific IP addresses if provided
                    ip_placeholders = [f':ip{i}' for i in range(len(ip_addresses))]
                    ip_values = {f':ip{i}': {'S': ip} for i, ip in enumerate(ip_addresses)}
                    
                    query_params['FilterExpression'] += f" AND ip_range IN ({', '.join(ip_placeholders)})"
                    query_params['ExpressionAttributeValues'].update(ip_values)
                
                response = await client.query(**query_params)
                
                ip_ranges = []
                for item in response.get('Items', []):
                    try:
                        cidr = item.get('cidr', {}).get('L', [])
                        cidr_list = [c.get('S', '') for c in cidr if 'S' in c] if cidr else []
                        
                        ip_range = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "ip_range": item.get('ip_range', {}).get('S', ''),
                            "asn": item.get('asn', {}).get('S'),
                            "cidr": cidr_list,
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        ip_ranges.append(ip_range)
                    except Exception as e:
                        logger.warning(f"Error parsing IP range item: {e}")
                        continue
                
                return ip_ranges
                
        except Exception as e:
            logger.error(f"Error fetching IP ranges for organization {organization_id}: {e}")
            raise
    
    async def get_organization_login_urls(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get login URLs for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationLoginURLs',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                login_urls = []
                for item in response.get('Items', []):
                    try:
                        login_url = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "url": item.get('url', {}).get('S', ''),
                            "description": item.get('description', {}).get('S'),
                            "template_id": item.get('template_id', {}).get('S'),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        login_urls.append(login_url)
                    except Exception as e:
                        logger.warning(f"Error parsing login URL item: {e}")
                        continue
                
                return login_urls
                
        except Exception as e:
            logger.error(f"Error fetching login URLs for organization {organization_id}: {e}")
            raise
    
    async def get_organization_email_addresses(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get email addresses for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationEmailAddresses',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                email_addresses = []
                for item in response.get('Items', []):
                    try:
                        email_address = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "email": item.get('email', {}).get('S', ''),
                            "status": item.get('status', {}).get('S', ''),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        email_addresses.append(email_address)
                    except Exception as e:
                        logger.warning(f"Error parsing email address item: {e}")
                        continue
                
                return email_addresses
                
        except Exception as e:
            logger.error(f"Error fetching email addresses for organization {organization_id}: {e}")
            raise
    
    async def get_organization_email_breaches(self, organization_id: str, emails: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get email breaches for organization from DynamoDB - matches agent pattern with resolution_status filter"""
        if self.dynamo_session is None:
            raise RuntimeError("DatabaseManager not initialized: dynamo_session is None")
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                # Use agent pattern: FilterExpression for resolution_status
                query_params = {
                    'TableName': 'OrganizationEmailBreaches',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'attribute_not_exists(resolution_status) OR resolution_status = :open_status',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':open_status': {'S': 'open'}
                    }
                }
                
                if emails:
                    # Filter by specific emails if provided
                    email_placeholders = [f':email{i}' for i in range(len(emails))]
                    email_values = {f':email{i}': {'S': email} for i, email in enumerate(emails)}
                    
                    query_params['FilterExpression'] += f" AND email IN ({', '.join(email_placeholders)})"
                    query_params['ExpressionAttributeValues'].update(email_values)
                
                response = await client.query(**query_params)
                
                email_breaches = []
                for item in response.get('Items', []):
                    try:
                        email_breach = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "email": item.get('email', {}).get('S', ''),
                            "password": item.get('password', {}).get('S'),
                            "password_type": item.get('password_type', {}).get('S'),
                            "total_breaches": int(item.get('total_breaches', {}).get('N', 0)),
                            "leak_date": self._parse_dynamo_date(item.get('leak_date')),
                            "latest_breach_date": self._parse_dynamo_date(item.get('latest_breach_date')),
                            "is_password_breached": item.get('is_password_breached', {}).get('BOOL', False),
                            "is_personal_info_breached": item.get('is_personal_info_breached', {}).get('BOOL', False),
                            "source": item.get('source', {}).get('S')
                        }
                        email_breaches.append(email_breach)
                    except Exception as e:
                        logger.warning(f"Error parsing email breach item: {e}")
                        continue
                
                # logger.info(f"Email breaches for org {organization_id}: {len(email_breaches)} active records processed")
                return email_breaches
                
        except Exception as e:
            logger.error(f"Error fetching email breaches for organization {organization_id}: {e}")
            raise
    
    async def get_organization_apis(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get APIs for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationAPIs',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                apis = []
                for item in response.get('Items', []):
                    try:
                        api = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "root_endpoint": item.get('root_endpoint', {}).get('S', ''),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        apis.append(api)
                    except Exception as e:
                        logger.warning(f"Error parsing API item: {e}")
                        continue
                
                return apis
                
        except Exception as e:
            logger.error(f"Error fetching APIs for organization {organization_id}: {e}")
            raise
    
    async def get_organization_object_storages(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get object storages for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationObjectStorages',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                object_storages = []
                for item in response.get('Items', []):
                    try:
                        object_storage = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "endpoint": item.get('endpoint', {}).get('S', ''),
                            "cloud_provider": item.get('cloud_provider', {}).get('S'),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        object_storages.append(object_storage)
                    except Exception as e:
                        logger.warning(f"Error parsing object storage item: {e}")
                        continue
                
                return object_storages
                
        except Exception as e:
            logger.error(f"Error fetching object storages for organization {organization_id}: {e}")
            raise
    
    async def get_organization_cdns(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get CDNs for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationCDNs',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                cdns = []
                for item in response.get('Items', []):
                    try:
                        cdn = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "endpoint": item.get('endpoint', {}).get('S', ''),
                            "provider": item.get('provider', {}).get('S'),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        cdns.append(cdn)
                    except Exception as e:
                        logger.warning(f"Error parsing CDN item: {e}")
                        continue
                
                return cdns
                
        except Exception as e:
            logger.error(f"Error fetching CDNs for organization {organization_id}: {e}")
            raise
    
    async def get_organization_domain_names(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get domain names for organization from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'OrganizationDomainNames',
                    'KeyConditionExpression': 'organization_id = :org_id',
                    'FilterExpression': 'active = :active',
                    'ExpressionAttributeValues': {
                        ':org_id': {'S': organization_id},
                        ':active': {'S': 'true'}
                    }
                }
                
                response = await client.query(**query_params)
                
                domain_names = []
                for item in response.get('Items', []):
                    try:
                        domain_name = {
                            "organization_id": item.get('organization_id', {}).get('S', ''),
                            "domain": item.get('domain', {}).get('S', ''),
                            "ip_address": item.get('ip_address', {}).get('S'),
                            "source": item.get('source', {}).get('S', ''),
                            "severity": item.get('severity', {}).get('S'),
                            "active": item.get('active', {}).get('S'),
                            "last_seen": self._parse_dynamo_date(item.get('last_seen'))
                        }
                        domain_names.append(domain_name)
                    except Exception as e:
                        logger.warning(f"Error parsing domain name item: {e}")
                        continue
                
                return domain_names
                
        except Exception as e:
            logger.error(f"Error fetching domain names for organization {organization_id}: {e}")
            raise
    
    async def get_phishing_results(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get phishing results for organization from PostgreSQL - matches agent pattern"""
        if self.pg_pool is None:
            raise RuntimeError("DatabaseManager not initialized: pg_pool is None")
        try:
            async with self.pg_pool.acquire() as conn:
                # Use agent pattern: (is_whitelisted = FALSE OR is_whitelisted IS NULL) ORDER BY text_similarity_percentage DESC
                query = """
                    SELECT organization_id, phishing_url, actual_url, text_similarity_percentage, 
                           is_whitelisted, alert_time
                    FROM "PhishingResults"
                    WHERE organization_id = $1 
                    AND (is_whitelisted = FALSE OR is_whitelisted IS NULL)
                    ORDER BY text_similarity_percentage DESC
                """
                rows = await conn.fetch(query, organization_id)
                
                phishing_results = []
                for row in rows:
                    try:
                        phishing_result = {
                            "organization_id": row['organization_id'],
                            "phishing_url": row['phishing_url'],
                            "actual_url": row['actual_url'],
                            "text_similarity_percentage": float(row.get('text_similarity_percentage', 0)),
                            "is_whitelisted": row['is_whitelisted'],
                            "alert_time": row.get('alert_time')
                        }
                        phishing_results.append(phishing_result)
                    except Exception as e:
                        logger.warning(f"Error parsing phishing result row: {e}")
                        continue
                
                return phishing_results
                
        except Exception as e:
            logger.error(f"Error fetching phishing results for organization {organization_id}: {e}")
            raise
    
    async def get_whois_records(self, domain_or_ip: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS record for domain or IP from DynamoDB"""
        try:
            async with self.dynamo_session.client('dynamodb') as client:
                query_params = {
                    'TableName': 'WhoisRecords',
                    'Key': {
                        'domain_or_ip': {'S': domain_or_ip}
                    }
                }
                
                response = await client.get_item(**query_params)
                
                if 'Item' not in response:
                    return None
                
                item = response['Item']
                
                # Parse name servers, email, and phone lists
                name_servers = []
                if 'name_servers' in item and 'L' in item['name_servers']:
                    name_servers = [ns.get('S', '') for ns in item['name_servers']['L'] if 'S' in ns]
                
                emails = []
                if 'email' in item and 'L' in item['email']:
                    emails = [email.get('S', '') for email in item['email']['L'] if 'S' in email]
                
                phones = []
                if 'phone' in item and 'L' in item['phone']:
                    phones = [phone.get('S', '') for phone in item['phone']['L'] if 'S' in phone]
                
                whois_record = {
                    "domain_or_ip": item.get('domain_or_ip', {}).get('S', ''),
                    "creation_date": self._parse_dynamo_date(item.get('creation_date')),
                    "expiration_date": self._parse_dynamo_date(item.get('expiration_date')),
                    "registrar": item.get('registrar', {}).get('S'),
                    "name_servers": name_servers,
                    "email": emails,
                    "phone": phones
                }
                
                return whois_record
                
        except Exception as e:
            logger.error(f"Error fetching WHOIS record for {domain_or_ip}: {e}")
            raise
    
    def _parse_dynamo_date(self, date_value) -> Optional[datetime]:
        """Parse DynamoDB date value to Python datetime"""
        if not date_value:
            return None
        
        try:
            if 'S' in date_value:
                # String date
                return datetime.fromisoformat(date_value['S'].replace('Z', '+00:00'))
            elif 'N' in date_value:
                # Numeric timestamp
                return datetime.fromtimestamp(int(date_value['N']))
            else:
                return None
        except Exception:
            return None
    
    def _parse_dynamo_number(self, number_value) -> Optional[float]:
        """Parse DynamoDB number value to Python float"""
        if not number_value:
            return None
        
        try:
            if 'N' in number_value:
                return float(number_value['N'])
            else:
                return None
        except Exception:
            return None
    
    def _parse_dynamo_value(self, value) -> Any:
        """Parse a single DynamoDB value to Python type"""
        if 'S' in value:
            return value['S']
        elif 'N' in value:
            try:
                return float(value['N'])
            except ValueError:
                return value['N']
        elif 'BOOL' in value:
            return value['BOOL']
        else:
            return value
    
    async def get_typosquatting_domains(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get typosquatting domains for organization from PostgreSQL - matches agent pattern"""
        if self.pg_pool is None:
            raise RuntimeError("DatabaseManager not initialized: pg_pool is None")
        try:
            async with self.pg_pool.acquire() as conn:
                # Use agent pattern: status_code IS NOT NULL ORDER BY similarity DESC
                query = """
                    SELECT organization_id, typosquatting_domain, actual_domain, parked_domain, 
                           registered_typo, registered_on, registrar_name, status_code, ip_address,
                           dns_ns, dns_mx, dns_aaaa, similarity, fuzzer, found_on, last_seen
                    FROM "OrganizationTyposquattingDomain" 
                    WHERE organization_id = $1 
                    AND status_code IS NOT NULL
                    ORDER BY similarity DESC
                """
                rows = await conn.fetch(query, organization_id)
                
                typosquatting_domains = []
                for row in rows:
                    try:
                        # Parse array fields (dns_ns, dns_mx, dns_aaaa)
                        dns_ns = row.get('dns_ns', []) if row.get('dns_ns') else []
                        dns_mx = row.get('dns_mx', []) if row.get('dns_mx') else []
                        dns_aaaa = row.get('dns_aaaa', []) if row.get('dns_aaaa') else []
                        
                        typosquatting_domain = {
                            'organization_id': row['organization_id'],
                            'typosquatting_domain': row['typosquatting_domain'],
                            'actual_domain': row['actual_domain'],
                            'parked_domain': row.get('parked_domain', False),
                            'registered_typo': row.get('registered_typo', False),
                            'registered_on': row.get('registered_on'),
                            'registrar_name': row.get('registrar_name'),
                            'status_code': row.get('status_code', 0),
                            'ip_address': row.get('ip_address'),
                            'dns_ns': dns_ns,
                            'dns_mx': dns_mx,
                            'dns_aaaa': dns_aaaa,
                            'similarity': float(row.get('similarity', 0) or 0.0),
                            'fuzzer': row.get('fuzzer'),
                            'found_on': row.get('found_on'),
                            'last_seen': row.get('last_seen')
                        }
                        typosquatting_domains.append(typosquatting_domain)
                    except Exception as e:
                        logger.warning(f"Error parsing typosquatting domain row: {e}")
                        continue
                
                return typosquatting_domains
                
        except Exception as e:
            logger.error(f"Error fetching typosquatting domains for organization {organization_id}: {e}")
            raise
    
    async def get_logo_abuse_findings(self, organization_id: str, abuse_types: Optional[List[str]] = None, 
                                    alert_locations: Optional[List[str]] = None, 
                                    status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get logo abuse findings for organization from PostgreSQL - matches agent pattern"""
        try:
            async with self.pg_pool.acquire() as conn:
                # Use agent pattern: status_code IS NOT NULL ORDER BY logo_domain
                query = """
                    SELECT organization_id, logo_id, abuse_type, logo_domain, alert_location, 
                           url, ip_address, language, sentiment, description, 
                           alert_time, last_seen, risk, status
                    FROM "LogoAbuseFindings"
                    WHERE organization_id = $1
                    AND status_code IS NOT NULL
                """
                
                params = [organization_id]
                param_count = 1
                
                # Add abuse_type filter if provided
                if abuse_types:
                    param_count += 1
                    placeholders = ','.join(f'${i+param_count}' for i in range(len(abuse_types)))
                    query += f" AND abuse_type IN ({placeholders})"
                    params.extend(abuse_types)
                    param_count += len(abuse_types)
                
                # Add alert_location filter if provided
                if alert_locations:
                    placeholders = ','.join(f'${i+param_count}' for i in range(len(alert_locations)))
                    query += f" AND alert_location IN ({placeholders})"
                    params.extend(alert_locations)
                
                # Add status filter if provided (treat null as active)
                if status_filter:
                    if status_filter.lower() == 'active':
                        query += " AND (status IS NULL OR status = 'Active')"
                    else:
                        query += f" AND status = ${len(params) + 1}"
                        params.append(status_filter)
                
                query += " ORDER BY logo_domain"
                
                rows = await conn.fetch(query, *params)
                
                logo_abuse_findings = []
                for row in rows:
                    try:
                        logo_abuse_finding = {
                            "organization_id": row['organization_id'],
                            "logo_id": row['logo_id'],
                            "abuse_type": row['abuse_type'],
                            "logo_domain": row['logo_domain'],
                            "alert_location": row['alert_location'],
                            "url": row['url'],
                            "ip_address": row.get('ip_address'),
                            "language": row.get('language'),
                            "sentiment": row.get('sentiment'),
                            "description": row.get('description'),
                            "alert_time": row.get('alert_time'),
                            "last_seen": row.get('last_seen'),
                            "risk": row.get('risk'),
                            "status": row.get('status')
                        }
                        logo_abuse_findings.append(logo_abuse_finding)
                    except Exception as e:
                        logger.warning(f"Error parsing logo abuse finding row: {e}")
                        continue
                
                # logger.info(f"Retrieved {len(logo_abuse_findings)} logo abuse findings for organization {organization_id}")
                return logo_abuse_findings
                
        except Exception as e:
            logger.error(f"Error fetching logo abuse findings for organization {organization_id}: {e}")
            raise
    
    async def get_portfolio_domains(self, organization_id: str, organization_types: Optional[List[str]] = None,
                                  severity_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get portfolio domains for organization from PostgreSQL - matches agent pattern"""
        try:
            async with self.pg_pool.acquire() as conn:
                # Use agent pattern: inherent_risk IN ('critical', 'high','MEDIUM') ORDER BY CASE inherent_risk
                query = """
                    SELECT organization_id, domain, organization_type, severity
                    FROM "PortfolioDomains"
                    WHERE organization_id = $1
                    AND severity IN ('critical', 'high', 'medium')
                """
                
                params = [organization_id]
                param_count = 1
                
                # Add organization_type filter if provided
                if organization_types:
                    param_count += 1
                    placeholders = ','.join(f'${i+param_count}' for i in range(len(organization_types)))
                    query += f" AND organization_type IN ({placeholders})"
                    params.extend(organization_types)
                    param_count += len(organization_types)
                
                # Add severity filter if provided
                if severity_levels:
                    placeholders = ','.join(f'${i+param_count}' for i in range(len(severity_levels)))
                    query += f" AND severity IN ({placeholders})"
                    params.extend(severity_levels)
                
                query += """ ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        ELSE 4
                    END,
                    domain ASC"""
                
                rows = await conn.fetch(query, *params)
                
                portfolio_domains = []
                for row in rows:
                    try:
                        portfolio_domain = {
                            "organization_id": row['organization_id'],
                            "domain": row['domain'],
                            "organization_type": row['organization_type'],
                            "severity": row['severity']
                        }
                        portfolio_domains.append(portfolio_domain)
                    except Exception as e:
                        logger.warning(f"Error parsing portfolio domain row: {e}")
                        continue
                
                # logger.info(f"Retrieved {len(portfolio_domains)} portfolio domains for organization {organization_id}")
                return portfolio_domains
                
        except Exception as e:
            logger.error(f"Error fetching portfolio domains for organization {organization_id}: {e}")
            raise


# Global database manager instance
db_manager = DatabaseManager() 