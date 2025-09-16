import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import asyncio

from models import (
    AttackPath, AttackPathNode, AttackPathInstance
)
from database import db_manager
from config import settings
from database_config import get_database_type, is_postgresql_table, is_dynamodb_table

logger = logging.getLogger(__name__)
debug_logger = logging.getLogger("attackpath.debug")

# Set debug level based on config
if settings.SELECTOR_DEBUG:
    debug_logger.setLevel(logging.DEBUG)
else:
    debug_logger.setLevel(logging.WARNING)


class AttackPathEngine:
    def __init__(self):
        self.path_templates: List[AttackPath] = []
        self.table_columns_canonical: Dict[str, List[str]] = {}
        
    async def load_attack_path_templates(self, templates_file: str = "attack_paths_rules_enhanced_updated.json"):
        """Load attack path templates from JSON file (for local development)"""
        try:
            logger.info(f"Loading attack path templates from {templates_file}")
            with open(templates_file, 'r') as f:
                data = json.load(f)
            
            await self._parse_templates_data(data)
            
        except Exception as e:
            logger.error(f"Error loading attack path templates: {e}")
            raise
    
    async def load_attack_path_templates_from_data(self, templates_data: Dict[str, Any]):
        """Load attack path templates from S3 data (for AWS Batch)"""
        try:
            logger.info("Loading attack path templates from S3 data")
            await self._parse_templates_data(templates_data)
            
        except Exception as e:
            logger.error(f"Error loading attack path templates from S3 data: {e}")
            raise
    
    async def _parse_templates_data(self, data: Dict[str, Any]):
        """Parse templates data from either local file or S3"""
        # Clear existing templates
        self.path_templates = []
        
        # Parse the templates
        for path_data in data.get('paths', []):
            # Filter out supporting_findings nodes from all templates
            filtered_nodes = []
            for node in path_data.get('nodes', []):
                if node.get('node_type') != 'supporting_findings':
                    filtered_nodes.append(node)
                else:
                    logger.debug(f"Filtered out supporting_findings node from template {path_data.get('id')}")

            # Update the path data with filtered nodes
            path_data['nodes'] = filtered_nodes
            
            path = AttackPath(**path_data)
            self.path_templates.append(path)
        
        self.table_columns_canonical = data.get('table_columns_canonical', {})
        logger.info(f"Loaded {len(self.path_templates)} attack path templates (supporting_findings nodes filtered out)")
    
    async def instantiate_attack_paths(self, organization_id: str, scan_id: str) -> List[AttackPathInstance]:
        """Instantiate all possible attack paths for an organization"""
        logger.info(f"Instantiating attack paths: loaded template count = {len(self.path_templates)}")
        instances = []
        successful_templates = 0
        failed_templates = 0
        
        for path_template in self.path_templates:
            try:
                # Try to instantiate this path
                path_instances = await self._instantiate_single_path(
                    path_template, organization_id, scan_id
                )
                if path_instances:
                    instances.extend(path_instances)
                    successful_templates += 1
                    logger.debug(f"Successfully instantiated template {path_template.id}: {len(path_instances)} instances")
                else:
                    logger.debug(f"Template {path_template.id} generated 0 instances (no data or failed validation)")
                
            except Exception as e:
                failed_templates += 1
                logger.warning(f"Error instantiating path {path_template.id}: {e}")
                continue
        
        logger.info(f"Template processing summary: {successful_templates} successful, {failed_templates} failed, {len(self.path_templates) - successful_templates - failed_templates} with no data")
        logger.info(f"Generated {len(instances)} attack path instances")
        return instances

    async def generate_attack_paths_json(self, db_manager, organization_id: str, scan_id: str) -> List[Dict[str, Any]]:
        """Generate attack paths and return JSON-ready format with nodes field"""
        logger.info(f"Generating attack paths JSON: loaded template count = {len(self.path_templates)}")
        
        # Get the raw instances
        # Store db_manager for use in methods
        self.db_manager = db_manager
        instances = await self.instantiate_attack_paths(organization_id, scan_id)
        
        # Convert to JSON format
        json_output = []
        skipped_count = 0
        
        for path_instance in instances:
            # Check if this instance has any findings
            has_findings = False
            total_findings = 0
            
            if hasattr(path_instance, 'nodes_data') and path_instance.nodes_data:
                if 'possible_paths' in path_instance.nodes_data:
                    total_findings = len(path_instance.nodes_data['possible_paths'])
                    has_findings = total_findings > 0
                elif 'total_possible_paths' in path_instance.nodes_data:
                    total_findings = path_instance.nodes_data['total_possible_paths']
                    has_findings = total_findings > 0
            
            # Only include instances with findings
            if has_findings:
                # Find the corresponding path template to get node names
                path_template = None
                for template in self.path_templates:
                    if template.id == path_instance.path_id:
                        path_template = template
                        break
                
                # Extract node names from the path template
                node_names = []
                if path_template:
                    node_names = [node.node_type for node in path_template.nodes]
                else:
                    logger.warning(f"Could not find template for path_id: {path_instance.path_id}")
                
                path_json = {
                    "path_id": path_instance.path_id,
                    "name": path_instance.path_name,
                    "description": path_instance.path_description,
                    "goals": path_instance.goals,
                    "outcomes": path_instance.outcomes,
                    "nodes": node_names,  # NEW FIELD: List of node names
                    "possible_paths": [],
                    "total_possible_paths": total_findings
                }
                
                # Add possible paths if available
                if hasattr(path_instance, 'nodes_data') and path_instance.nodes_data:
                    if 'possible_paths' in path_instance.nodes_data:
                        path_json["possible_paths"] = path_instance.nodes_data['possible_paths']
                        path_json["total_possible_paths"] = len(path_instance.nodes_data['possible_paths'])
                    elif 'total_possible_paths' in path_instance.nodes_data:
                        path_json["total_possible_paths"] = path_instance.nodes_data['total_possible_paths']
                
                json_output.append(path_json)
            else:
                skipped_count += 1
                logger.debug(f"Skipping {path_instance.path_id} - no findings ({total_findings} paths)")
        
        logger.info(f"JSON generation summary: {len(json_output)} instances with findings, {skipped_count} skipped")
        return json_output
    
    async def _instantiate_single_path(self, path_template: AttackPath, organization_id: str, scan_id: str) -> List[AttackPathInstance]:
        """Instantiate a single attack path template using dynamic query processing"""
        instances = []
        
        try:
            # Guard against Cartesian products: skip multi-node templates with no joins
            if self._should_skip_due_to_no_joins(path_template):
                return []
            
            # Use dynamic sequential processing
            debug_logger.info("🚀 Using NEW dynamic sequential processing for template: %s", path_template.id)
            path_data = await self._process_nodes_sequentially(path_template, organization_id, scan_id)
            
            if not path_data:
                logger.warning(f"No data found for path template {path_template.id}")
                return []
            
            # Check if all required nodes are present
            required_nodes_present = self._check_required_nodes_present(path_template, path_data)
            
            if not required_nodes_present:
                logger.warning(f"Required nodes not present for path template {path_template.id}")
                return []
            
            # Create the new joined data structure
            joined_data = self._create_joined_data_structure(path_template, path_data)
            
            # Create path instance
            instance = AttackPathInstance(
                path_id=path_template.id,
                path_name=path_template.name,
                path_description=path_template.description,
                goals=path_template.goals,
                nodes_data=joined_data,  # Use the new joined structure
                required_nodes_present=True,
                optional_nodes_present=self._get_optional_nodes_present(path_template, path_data),
                mitigating_evidence=self._get_mitigating_evidence(path_template, path_data),
                outcomes=path_template.outcomes
            )
            
            instances.append(instance)
            
        except Exception as e:
            logger.warning(f"Template {path_template.id} has invalid selector/join: {e}. Skipping template.")
            debug_logger.error("Error processing template %s: %s", path_template.id, e)
        
        return instances

    def _should_skip_due_to_no_joins(self, path_template: AttackPath) -> bool:
        """Return True if a multi-node template lacks joins, which would create a Cartesian product."""
        try:
            ordered_nodes = sorted(path_template.nodes, key=lambda n: n.order)
            # Single-node templates are always safe
            if len(ordered_nodes) <= 1:
                return False
            
            # If none of the nodes define any join, skip to prevent Cartesian product
            any_joins_defined = any(getattr(node, 'join', None) for node in ordered_nodes)
            if not any_joins_defined:
                logger.warning(
                    "Skipping template %s: multi-node template without joins would create a Cartesian product",
                    path_template.id,
                )
                return True
            
            # Additionally, if any required non-first node has no join, skip as it can explode combinations
            for idx, node in enumerate(ordered_nodes[1:], start=1):
                if not node.optional and (not getattr(node, 'join', None)):
                    logger.warning(
                        "Skipping template %s: required node '%s' has no join; would create a Cartesian product",
                        path_template.id,
                        node.node_type,
                    )
                    return True
            return False
        except Exception as e:
            logger.warning(
                "Validation error while checking joins for template %s: %s. Proceeding cautiously.",
                getattr(path_template, 'id', 'unknown'),
                e,
            )
            return False
    
    async def _process_nodes_sequentially(self, path_template: AttackPath, organization_id: str, scan_id: str) -> Dict[str, Any]:
        """Process nodes in order, passing results as WHERE conditions to next node"""
        debug_logger.debug("Processing nodes sequentially for template: %s", path_template.id)
        
        # Get nodes in order
        ordered_nodes = sorted(path_template.nodes, key=lambda n: n.order)
        debug_logger.debug("Ordered nodes: %r", [n.node_type for n in ordered_nodes])
        
        current_results = None
        node_data = {}
        
        for i, node in enumerate(ordered_nodes):
            debug_logger.debug("Processing node %d: %s (table: %s)", i, node.node_type, node.table)
            
            # Determine database type
            db_type = get_database_type(node.table)
            debug_logger.debug("Database type for %s: %s", node.table, db_type)
            
            # Build WHERE conditions from previous node results
            where_conditions = self._build_where_conditions(current_results, node, path_template)
            debug_logger.debug("WHERE conditions for %s: %r", node.node_type, where_conditions)
            
            # Query current node with conditions
            node_results = await self._query_node_dynamic(
                node, organization_id, scan_id, where_conditions, db_type
            )
            
            debug_logger.info("Node %s: fetched %d records", node.node_type, len(node_results) if node_results else 0)
            
            # Store results
            node_data[node.node_type] = node_results
            current_results = node_results  # Pass to next node
            
            # If no results and node is required, stop processing
            if not node_results and not node.optional:
                debug_logger.warning("Required node %s has no data, stopping processing", node.node_type)
                break
        
        return node_data
    
    def _build_where_conditions(self, previous_results: List[Dict[str, Any]], current_node: AttackPathNode, path_template: AttackPath) -> Dict[str, List[Any]]:
        """Build WHERE conditions for current node based on previous results and join rules"""
        where_conditions = {}
        
        # First, convert node selectors to WHERE conditions (for first node or nodes without joins)
        if current_node.selector:
            for field, selector_def in current_node.selector.items():
                if selector_def.get("op") == "=":
                    # Convert single value to list for consistency with IN operations
                    where_conditions[field] = [selector_def["value"]]
                elif selector_def.get("op") == "in":
                    where_conditions[field] = selector_def["value"]
                else:
                    debug_logger.warning("Unsupported selector operation: %s for field %s", selector_def.get("op"), field)
        
        # If no previous results or no joins, return selector-based conditions
        if not previous_results or not current_node.join:
            return where_conditions
        
        # Find the join rule for this node
        for join_def in current_node.join:
            from_table = join_def["from"].split(".", 1)[0]
            from_field = join_def["from"].split(".", 1)[1]
            to_field = join_def["to"].split(".", 1)[1]
            
            debug_logger.debug("Join rule: %s.%s -> %s.%s", from_table, from_field, current_node.table, to_field)
            
            # Extract values from previous results
            values = []
            for result in previous_results:
                value = result.get(from_field)
                if value is not None:
                    values.append(value)
            
            if values:
                # Deduplicate values to reduce DynamoDB FilterExpression size
                unique_values = list(set(values))
                where_conditions[to_field] = unique_values
                
                # Log the deduplication for debugging
                if len(values) != len(unique_values):
                    debug_logger.debug("Deduplicated %s: %d -> %d values", to_field, len(values), len(unique_values))
                else:
                    debug_logger.debug("Built WHERE condition: %s IN (%d values)", to_field, len(values))
        
        return where_conditions
    
    def _find_matching_item_for_combination(self, previous_item: Dict[str, Any], node_data: List[Dict[str, Any]], node: AttackPathNode, path_template: AttackPath) -> Optional[Dict[str, Any]]:
        """Find the matching item from node_data that relates to previous_item based on join relationships"""
        if not node.join or not previous_item:
            # If no join or no previous item, return the first item
            return node_data[0] if node_data else None
        
        # Find the join rule for this node
        for join_def in node.join:
            from_table = join_def["from"].split(".", 1)[0]
            from_field = join_def["from"].split(".", 1)[1]
            to_table = join_def["to"].split(".", 1)[0]
            to_field = join_def["to"].split(".", 1)[1]
            
            # Debug logging
            debug_logger.debug("Join rule: %s.%s = %s.%s", from_table, from_field, to_table, to_field)
            debug_logger.debug("Previous item keys: %s", list(previous_item.keys()))
            debug_logger.debug("Node data sample keys: %s", list(node_data[0].keys()) if node_data else "No data")
            
            # The join rule is: from_table.from_field = to_table.to_field
            # previous_item is from the previous node (to_table)
            # We need to get the value from previous_item that corresponds to the field in to_table
            # and then find the item in node_data (from_table) that has from_field with that value
            
            # The join rule is: from_table.from_field = to_table.to_field
            # previous_item is from to_table, so we need to get the field that corresponds to to_table
            # But the field name in previous_item might be different from to_field
            
            # For DNS -> IP: OrganizationDNS.value = OrganizationIPRanges.ip_range
            # previous_item is from OrganizationDNS, so we need to get "value" from it
            # and find an item in node_data (OrganizationIPRanges) where "ip_range" matches that value
            
            # For IP -> CVE: OrganizationIPRanges.ip_range = OrganizationCVEsV2.asset  
            # previous_item is from OrganizationIPRanges, so we need to get "ip_range" from it
            # and find an item in node_data (OrganizationCVEsV2) where "asset" matches that value
            
            # The key insight: we need to get the field from previous_item that corresponds to the join
            # This is the field name in the previous table that should match the current table's field
            
            # Get the value from previous_item using the field that should match
            # This is the field from the previous table that should match the current table's field
            previous_value = previous_item.get(from_field)
            if previous_value is None:
                debug_logger.debug("No value found for field %s in previous item", from_field)
                continue
            
            debug_logger.debug("Looking for matches with value: %s", previous_value)
            
            # Find matching item in node_data where to_field matches previous_value
            for item in node_data:
                item_value = item.get(to_field)
                if item_value == previous_value:
                    debug_logger.debug("Found match: %s = %s", item_value, previous_value)
                    return item
            
            debug_logger.debug("No match found for value: %s", previous_value)
        
        # If no match found, return None (don't create invalid combinations)
        debug_logger.debug("No valid join found for node %s", node.node_type)
        return None
    
    def _find_all_matching_items_for_combination(self, previous_item: Dict[str, Any], node_data: List[Dict[str, Any]], node: AttackPathNode, path_template: AttackPath) -> List[Dict[str, Any]]:
        """Find ALL matching items from node_data that relate to previous_item based on join relationships"""
        if not node.join or not previous_item:
            # If no join or no previous item, return all items
            return node_data
        
        matching_items = []
        
        # Find the join rule for this node
        for join_def in node.join:
            from_table = join_def["from"].split(".", 1)[0]
            from_field = join_def["from"].split(".", 1)[1]
            to_table = join_def["to"].split(".", 1)[0]
            to_field = join_def["to"].split(".", 1)[1]
            
            # Get the value from previous_item using the field that should match
            previous_value = previous_item.get(from_field)
            if previous_value is None:
                continue
            
            # Find ALL matching items in node_data where to_field matches previous_value
            for item in node_data:
                item_value = item.get(to_field)
                if item_value == previous_value:
                    matching_items.append(item)
        
        return matching_items
    
    def _build_all_combinations_from_first_node(self, first_item: Dict[str, Any], first_node: AttackPathNode, ordered_nodes: List[AttackPathNode], path_data: Dict[str, Any], path_template: AttackPath) -> List[Dict[str, Any]]:
        """Build ALL possible combinations starting from the first node and following join relationships"""
        combinations = []
        
        # Start with the first node
        base_combination = {first_node.node_type: first_item}
        
        # Recursively build all combinations
        self._build_combinations_recursive(base_combination, first_item, ordered_nodes[1:], path_data, path_template, combinations)
        
        return combinations
    
    def _build_cve_exploit_combinations(self, first_item: Dict[str, Any], first_node: AttackPathNode, ordered_nodes: List[AttackPathNode], path_data: Dict[str, Any], path_template: AttackPath) -> List[Dict[str, Any]]:
        """Special logic for cve_exploit_internet_host: Group all CVEs per asset into one path"""
        debug_logger.info("🚀 CVE EXPLOIT GROUPING: Building CVE exploit combinations with asset grouping")
        debug_logger.info("🚀 Template ID: %s", path_template.id)
        debug_logger.info("🚀 First item: %s", "None (processing entire dataset)" if first_item is None else "Single item")
        
        combinations = []
        
        # For cve_exploit_internet_host, the flow is: dns_to_ip -> ip_asset -> vulnerability_on_asset
        # We want to group all CVEs for each unique asset into one path
        
        # Get the data for each node
        dns_data = path_data.get('dns_to_ip', [])
        ip_data = path_data.get('ip_asset', [])
        cve_data = path_data.get('vulnerability_on_asset', [])
        
        debug_logger.debug("CVE exploit data: DNS=%d, IP=%d, CVE=%d", len(dns_data), len(ip_data), len(cve_data))
        
        # Group CVEs by asset (IP)
        cves_by_asset = {}
        for cve in cve_data:
            asset = cve.get('asset')
            if asset:
                if asset not in cves_by_asset:
                    cves_by_asset[asset] = []
                cves_by_asset[asset].append(cve)
        
        debug_logger.debug("Grouped CVEs by asset: %d unique assets", len(cves_by_asset))
        
        # For each unique asset, create one path with all its CVEs
        for asset, asset_cves in cves_by_asset.items():
            debug_logger.info("Processing asset: %s with %d CVEs", asset, len(asset_cves))
            
            # Find the corresponding IP asset record
            matching_ip = None
            for ip_record in ip_data:
                if ip_record.get('ip_range') == asset:
                    matching_ip = ip_record
                    break
            
            if not matching_ip:
                debug_logger.warning("No matching IP record found for asset: %s", asset)
                continue
            
            # Find the corresponding DNS record
            matching_dns = None
            for dns_record in dns_data:
                if dns_record.get('value') == asset:
                    matching_dns = dns_record
                    break
            
            if not matching_dns:
                debug_logger.warning("No matching DNS record found for asset: %s", asset)
                continue
            
            # Create one combination with all CVEs for this asset
            combination = {
                'dns_to_ip': matching_dns,
                'ip_asset': matching_ip,
                'vulnerability_on_asset': asset_cves  # Array of all CVEs for this asset
            }
            
            combinations.append(combination)
            debug_logger.info("✅ Created combination for asset %s with %d CVEs", asset, len(asset_cves))
        
        debug_logger.info("CVE exploit combinations: %d unique assets with grouped CVEs", len(combinations))
        return combinations
    
    def _build_combinations_recursive(self, current_combination: Dict[str, Any], current_item: Dict[str, Any], remaining_nodes: List[AttackPathNode], path_data: Dict[str, Any], path_template: AttackPath, combinations: List[Dict[str, Any]]):
        """Recursively build all possible combinations"""
        if not remaining_nodes:
            # No more nodes to process, add this combination
            combinations.append(current_combination.copy())
            return
        
        current_node = remaining_nodes[0]
        current_node_data = path_data.get(current_node.node_type, [])
        
        if not current_node_data:
            # If no data for this node, continue with remaining nodes
            self._build_combinations_recursive(current_combination, current_item, remaining_nodes[1:], path_data, path_template, combinations)
            return
        
        # Find ALL matching items for the current node
        matching_items = self._find_all_matching_items_for_combination(
            current_item, current_node_data, current_node, path_template
        )
        
        if not matching_items:
            # If no matches found, this combination path is invalid
            return
        
        # For each matching item, create a new combination and continue recursively
        for matching_item in matching_items:
            new_combination = current_combination.copy()
            new_combination[current_node.node_type] = matching_item
            
            # Continue with remaining nodes
            self._build_combinations_recursive(new_combination, matching_item, remaining_nodes[1:], path_data, path_template, combinations)
    
    async def _query_node_dynamic(self, node: AttackPathNode, organization_id: str, scan_id: str, where_conditions: Dict[str, List[Any]], db_type: str) -> List[Dict[str, Any]]:
        """Query a node with dynamic WHERE conditions based on database type"""
        debug_logger.debug("Querying node %s with database type %s", node.node_type, db_type)
        
        if db_type == "postgresql":
            return await self._query_postgres_dynamic(node, organization_id, scan_id, where_conditions)
        elif db_type == "dynamodb":
            return await self._query_dynamodb_dynamic(node, organization_id, scan_id, where_conditions)
        else:
            logger.warning(f"Unknown database type '{db_type}' for table {node.table}")
            return []
    
    async def _query_postgres_dynamic(self, node: AttackPathNode, organization_id: str, scan_id: str, where_conditions: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
        """Query PostgreSQL table with dynamic WHERE conditions"""
        debug_logger.debug("Querying PostgreSQL table %s", node.table)
        
        # Use the database manager's dynamic query function with specific columns
        return await self.db_manager.get_data_dynamic_postgres(
            node.table, organization_id, scan_id, where_conditions, node.columns
        )
    
    async def _query_dynamodb_dynamic(self, node: AttackPathNode, organization_id: str, scan_id: str, where_conditions: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
        """Query DynamoDB table with dynamic WHERE conditions"""
        debug_logger.debug("Querying DynamoDB table %s", node.table)
        
        # Use the database manager's dynamic query function with specific columns
        return await self.db_manager.get_data_dynamic_dynamodb(
            node.table, organization_id, scan_id, where_conditions, node.columns
        )
    
    async def _gather_path_data(self, path_template: AttackPath, organization_id: str, scan_id: str, cache: Dict[str, Any] = None) -> Dict[str, Any]:
        """Gather all data needed for a specific attack path and apply joins"""
        debug_logger.debug("Gathering path data for template: %s", path_template.id)
        path_data = {}
        
        # First, gather all node data
        for node in path_template.nodes:
            try:
                node_data = await self._get_node_data(node, organization_id, scan_id, cache)
                if node_data:
                    path_data[node.node_type] = node_data
                    debug_logger.info("Node %s: loaded %d records", node.node_type, len(node_data) if node_data else 0)
                else:
                    debug_logger.warning("Node %s: no data found", node.node_type)
                    
            except Exception as e:
                logger.warning(f"Error gathering data for node {node.node_type}: {e}")
                debug_logger.error("Error gathering data for node %s: %s", node.node_type, e)
                if not node.optional:
                    # If required node fails, skip this path
                    debug_logger.error("Required node %s failed, skipping path", node.node_type)
                    return {}
        
        # Apply joins to get all valid combinations
        try:
            debug_logger.debug("Applying joins to path data with %d node types", len(path_data))
            valid_combinations = self.apply_joins(path_data, path_template)
            debug_logger.info("Join processing completed: %d valid combinations", len(valid_combinations))
            
            # Return the joined data structure
            return {
                "raw_data": path_data,  # Keep original data for reference
                "valid_combinations": valid_combinations,
                "total_combinations": len(valid_combinations)
            }
            
        except Exception as e:
            logger.warning(f"Error applying joins for path {path_template.id}: {e}")
            debug_logger.error("Error applying joins for path %s: %s", path_template.id, e)
            # Return raw data without joins if join processing fails
            return {
                "raw_data": path_data,
                "valid_combinations": [],
                "total_combinations": 0
            }
    
    def build_field_index(self, table_data: List[dict], field: str) -> Dict[str, List[dict]]:
        """Build an index on a field for fast lookups"""
        index = {}
        for row in table_data:
            key = row.get(field)
            if key is not None:
                index.setdefault(key, []).append(row)
        return index
    
    def normalize_join_key(self, key: str, field_type: str = "default") -> str:
        """Normalize join keys for matching (e.g., email cleaning)"""
        if not key:
            return key
        
        # Handle email normalization (split on ::: and use first part)
        if ":::" in str(key):
            return str(key).split(":::")[0]
        
        # Convert to string and strip whitespace
        return str(key).strip()
    
    def perform_join(self, left_data: List[dict], left_field: str, right_data: List[dict], right_field: str) -> List[dict]:
        """Perform a join between two datasets"""
        debug_logger.debug("Joining field '%s' (left) to field '%s' (right)", left_field, right_field)
        debug_logger.debug("Left data count: %d, Right data count: %d", len(left_data), len(right_data))
        
        if not left_data or not right_data:
            debug_logger.warning("Empty data for join: left=%d, right=%d", len(left_data), len(right_data))
            return []
        
        # Log sample data for debugging
        for i, left_row in enumerate(left_data[:3]):  # Show first 3
            debug_logger.debug("LEFT[%d][%s]: %r", i, left_field, left_row.get(left_field))
        for i, right_row in enumerate(right_data[:3]):  # Show first 3
            debug_logger.debug("RIGHT[%d][%s]: %r", i, right_field, right_row.get(right_field))
        
        # Build index on right table for fast lookups
        right_index = self.build_field_index(right_data, right_field)
        debug_logger.debug("Built right index with %d keys: %r", len(right_index), list(right_index.keys())[:5])
        
        results = []
        
        for left_row in left_data:
            left_key = self.normalize_join_key(left_row.get(left_field))
            debug_logger.debug("Processing left key: %r", left_key)
            
            if left_key in right_index:
                debug_logger.debug("Found %d matches for key %r", len(right_index[left_key]), left_key)
                for right_row in right_index[left_key]:
                    results.append({
                        "from_item": left_row,
                        "to_item": right_row,
                        "join_value": left_key
                    })
            else:
                debug_logger.warning("NO JOIN MATCH: left_key=%r, available_keys=%r", left_key, list(right_index.keys())[:10])
        
        debug_logger.info("Join completed: %d results from %d left x %d right", len(results), len(left_data), len(right_data))
        return results
    
    def apply_joins(self, path_data: Dict[str, Any], path_template: AttackPath) -> List[Dict[str, Any]]:
        """Apply all joins for a path template and return all valid combinations"""
        debug_logger.debug("Applying joins for path template: %s", path_template.id)
        debug_logger.debug("Path data keys: %r", list(path_data.keys()))
        
        if not path_data:
            debug_logger.warning("No path data provided for joins")
            return []
        
        # Get nodes in order
        ordered_nodes = sorted(path_template.nodes, key=lambda n: n.order)
        debug_logger.debug("Ordered nodes: %r", [n.node_type for n in ordered_nodes])
        
        # Start with the first node's data
        if not ordered_nodes:
            return []
        
        first_node = ordered_nodes[0]
        first_data = path_data.get(first_node.node_type, [])
        
        if not first_data:
            return []
        
        # Initialize with first node data
        current_combinations = []
        for item in first_data:
            current_combinations.append({
                first_node.node_type: item
            })
        
        # Process each subsequent node with joins - STANDARD EXPANSION LOGIC
        for i in range(1, len(ordered_nodes)):
            current_node = ordered_nodes[i]
            current_data = path_data.get(current_node.node_type, [])
            
            debug_logger.debug("Processing node %d: %s with %d data items", i, current_node.node_type, len(current_data))
            
            if not current_data:
                if current_node.optional:
                    # Optional nodes: just add None for this node in all combos
                    debug_logger.debug("Optional node %s has no data, adding None to all combos", current_node.node_type)
                    for combo in current_combinations:
                        combo[current_node.node_type] = None
                    continue
                else:
                    # If this chain can't be completed, kill all combos
                    debug_logger.debug("Required node %s has no data, returning empty list", current_node.node_type)
                    return []
            
            if not current_node.join:
                # If this node is not joined to previous, cartesian product
                debug_logger.debug("Node %s has no joins, creating cartesian product", current_node.node_type)
                new_combinations = []
                for combo in current_combinations:
                    for item in current_data:
                        new_combo = combo.copy()
                        new_combo[current_node.node_type] = item  # ONE item per hop
                        new_combinations.append(new_combo)
                current_combinations = new_combinations
                debug_logger.debug("Cartesian product created %d combinations", len(current_combinations))
            else:
                # Joined: Only expand correct links
                debug_logger.debug("Node %s has joins, expanding based on join conditions", current_node.node_type)
                new_combinations = []
                
                for combo in current_combinations:
                    # Find last node with data in combo before this (by node order)
                    last_node_with_data = None
                    for j in range(i-1, -1, -1):
                        prev_node_type = ordered_nodes[j].node_type
                        if combo.get(prev_node_type) is not None:
                            last_node_with_data = prev_node_type
                            break
                    
                    if not last_node_with_data:
                        debug_logger.debug("No previous node with data found for combo, skipping")
                        continue
                    
                    last_item = combo[last_node_with_data]
                    debug_logger.debug("Joining from %s to %s", last_node_with_data, current_node.node_type)
                    
                    # Debug: Show join field mapping
                    if current_node.join:
                        join_def = current_node.join[0]
                        from_field = join_def["from"].split(".", 1)[1]
                        to_field = join_def["to"].split(".", 1)[1]
                        debug_logger.debug("Join mapping: %s.%s -> %s.%s", 
                                         last_node_with_data, from_field, 
                                         current_node.node_type, to_field)
                        
                        # Debug: Show sample values
                        debug_logger.debug("Sample left item keys: %r", list(last_item.keys()))
                        debug_logger.debug("Sample left value for %s: %r", from_field, last_item.get(from_field))
                        
                        if current_data:
                            debug_logger.debug("Sample right item keys: %r", list(current_data[0].keys()))
                            debug_logger.debug("Sample right value for %s: %r", to_field, current_data[0].get(to_field))
                    
                    # For every item in current_data that joins with last_item, expand
                    join_matches = []
                    for item in current_data:
                        if self._items_match_on_joins(last_item, item, current_node.join):
                            join_matches.append(item)
                    
                    debug_logger.debug("Found %d join matches for %s", len(join_matches), current_node.node_type)
                    
                    # CRITICAL FIX: Only create combinations if we have valid join matches
                    if join_matches:
                        for match in join_matches:
                            new_combo = combo.copy()
                            new_combo[current_node.node_type] = match  # ONE dict per hop
                            new_combinations.append(new_combo)
                    else:
                        # No join matches found - this combination path is invalid, prune it
                        debug_logger.debug("No join matches found for combo, pruning this path")
                        # Don't add anything to new_combinations - this prunes the path
                
                # Track pruning effect
                input_combinations = len(current_combinations)
                current_combinations = new_combinations
                output_combinations = len(current_combinations)
                debug_logger.debug("Join expansion: %d input -> %d output combinations (pruned %d invalid paths)", 
                                 input_combinations, output_combinations, input_combinations - output_combinations)
        
        # VALIDATION: Ensure no lists in chain node values
        required_nodes = [n.node_type for n in ordered_nodes if not n.optional]
        debug_logger.debug("Validating %d combinations for required nodes: %r", len(current_combinations), required_nodes)
        
        for combo in current_combinations:
            for node in required_nodes:
                if node in combo:
                    assert not isinstance(combo[node], list), f"Node {node} in chain is a list! Value: {combo[node]}"
                    debug_logger.debug("Node %s is valid dict: %r", node, type(combo[node]))
        
        debug_logger.info("Join processing completed: %d valid combinations", len(current_combinations))
        
        # STRICT FILTERING: Only return complete chains with all required nodes
        required_nodes = [node.node_type for node in ordered_nodes if not node.optional]
        debug_logger.info("Filtering combinations: %d total, %d required nodes: %r", 
                         len(current_combinations), len(required_nodes), required_nodes)
        
        filtered_combinations = []
        filtered_out_count = 0
        
        for combo in current_combinations:
            # Check if all required nodes are present and not None
            if all(node in combo and combo[node] is not None for node in required_nodes):
                # Additional validation: ensure join relationships are meaningful
                if self._validate_join_relationships(combo, path_template):
                    filtered_combinations.append(combo)
                else:
                    filtered_out_count += 1
                    debug_logger.debug("Filtered out combo due to invalid join relationships: %r", 
                                     {k: v for k, v in combo.items() if k in required_nodes})
            else:
                filtered_out_count += 1
                missing_nodes = [node for node in required_nodes if node not in combo or combo[node] is None]
                debug_logger.debug("Filtered out combo due to missing required nodes: %r", missing_nodes)
        
        debug_logger.info("Final filtering results: %d valid combinations, %d filtered out", 
                         len(filtered_combinations), filtered_out_count)
        
        return filtered_combinations
    
    def _items_match_on_joins(self, left_item: Dict[str, Any], right_item: Dict[str, Any], join_defs: List[Dict[str, str]]) -> bool:
        """Check if two items match on all join conditions"""
        for join_def in join_defs:
            # Extract field names from table.field format
            left_field = join_def["from"].split(".", 1)[1]
            right_field = join_def["to"].split(".", 1)[1]
            
            # Get values from the items
            left_val = left_item.get(left_field)
            right_val = right_item.get(right_field)
            
            # Debug logging for join matching
            debug_logger.debug("Join comparison: %s=%r vs %s=%r", 
                             left_field, left_val, right_field, right_val)
            
            # Normalize and compare
            left_normalized = self.normalize_join_key(str(left_val)) if left_val is not None else None
            right_normalized = self.normalize_join_key(str(right_val)) if right_val is not None else None
            
            debug_logger.debug("Normalized comparison: %r vs %r", left_normalized, right_normalized)
            
            if left_normalized != right_normalized:
                debug_logger.debug("Join match failed: %r != %r", left_normalized, right_normalized)
                return False
            else:
                debug_logger.debug("Join match succeeded: %r == %r", left_normalized, right_normalized)
        
        return True
    
    def _validate_join_relationships(self, combo: Dict[str, Any], path_template: AttackPath) -> bool:
        """Validate that join relationships are meaningful and connected"""
        debug_logger.debug("Validating join relationships for combo with keys: %r", list(combo.keys()))
        
        # Get nodes with joins
        nodes_with_joins = [node for node in path_template.nodes if node.join]
        
        for node in nodes_with_joins:
            if node.node_type not in combo or combo[node.node_type] is None:
                continue
                
            join = node.join
            from_field = join[0].get('from', '').split('.')[-1]  # FIX: handle as list
            to_field = join[0].get('to', '').split('.')[-1]
            
            # Get the data for this node and the target node
            current_data = combo[node.node_type]
            if not isinstance(current_data, dict):   # <-- skip list nodes
                debug_logger.debug("Skipping validation for non-dict node %s (type: %s)", 
                                 node.node_type, type(current_data).__name__)
                continue
                
            target_node_type = join[0].get('to', '').split('.')[0]  # Get target table name
            
            if target_node_type not in combo or combo[target_node_type] is None:
                debug_logger.debug("Target node %s not found in combo", target_node_type)
                continue
            
            target_data = combo[target_node_type]
            if not isinstance(target_data, dict):    # <-- skip list nodes
                debug_logger.debug("Skipping validation for non-dict target node %s (type: %s)", 
                                 target_node_type, type(target_data).__name__)
                continue
            
            # Extract values for comparison
            current_value = current_data.get(from_field)
            target_value = target_data.get(to_field)
            
            if current_value is None or target_value is None:
                debug_logger.debug("Missing values for join validation: %s=%r, %s=%r", 
                                 from_field, current_value, to_field, target_value)
                continue
            
            # Normalize values for comparison (handle email splitting, etc.)
            current_normalized = self.normalize_join_key(str(current_value))
            target_normalized = self.normalize_join_key(str(target_value))
            
            # Check if values match
            if current_normalized != target_normalized:
                debug_logger.debug("Join validation failed: %s=%r != %s=%r", 
                                 from_field, current_normalized, to_field, target_normalized)
                return False
            else:
                debug_logger.debug("Join validation passed: %s=%r == %s=%r", 
                                 from_field, current_normalized, to_field, target_normalized)
        
        debug_logger.debug("All join relationships validated successfully")
        return True
    
    async def _get_cached_data(self, cache: Dict[str, Any], table_name: str, fallback_func, *args):
        """Helper function to get data from cache or fallback to database"""
        if cache and table_name in cache:
            return cache[table_name]
        else:
            # Fallback to database call
            return await fallback_func(*args)
    
    async def _get_node_data(self, node: AttackPathNode, organization_id: str, scan_id: str, cache: Dict[str, Any] = None) -> Optional[Any]:
        """Get data for a specific node based on its table and selectors"""
        debug_logger.debug("Getting data for node: %s (table: %s)", node.node_type, node.table)
        try:
            if node.table == "Findings":
                return await self._get_findings_data(node, scan_id, cache)
            elif node.table == "OrganizationCVEsV2":
                return await self._get_cves_data(node, organization_id, cache)
            elif node.table == "OrganizationDNS":
                return await self._get_dns_data(node, organization_id, cache)
            elif node.table == "OrganizationIPRanges":
                return await self._get_ip_ranges_data(node, organization_id, cache)
            elif node.table == "OrganizationLoginURLs":
                return await self._get_login_urls_data(node, organization_id, cache)
            elif node.table == "OrganizationEmailAddresses":
                return await self._get_email_addresses_data(node, organization_id, cache)
            elif node.table == "OrganizationEmailBreaches":
                return await self._get_email_breaches_data(node, organization_id, cache)
            elif node.table == "OrganizationAPIs":
                return await self._get_apis_data(node, organization_id, cache)
            elif node.table == "OrganizationObjectStorages":
                return await self._get_object_storages_data(node, organization_id, cache)
            elif node.table == "OrganizationCDNs":
                return await self._get_cdns_data(node, organization_id, cache)
            elif node.table == "OrganizationDomainNames":
                return await self._get_domain_names_data(node, organization_id, cache)
            elif node.table == "PhishingResults":
                return await self._get_phishing_results_data(node, organization_id, cache)
            elif node.table == "WhoisRecords":
                return await self._get_whois_data(node, organization_id, cache)
            else:
                logger.warning(f"Unknown table {node.table} for node {node.node_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting data for node {node.node_type}: {e}")
            return None
    
    async def _get_findings_data(self, node: AttackPathNode, scan_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get findings data with rule filtering"""
        # Try to get from cache first
        if cache and 'Findings' in cache:
            findings = cache['Findings']
        else:
            # Fallback to database call
            findings = await db_manager.get_findings_by_scan(scan_id)
        
        # Apply rule filtering
        rule_ids = []
        if node.selector and 'rule_id' in node.selector:
            rule_selector = node.selector['rule_id']
            if rule_selector.get('op') == 'in':
                rule_ids = rule_selector.get('value', [])
            elif rule_selector.get('op') == '=':
                rule_ids = [rule_selector.get('value', '')]
        
        if rule_ids:
            findings = [f for f in findings if f.get('rule_id') in rule_ids]
        
        # Apply additional selectors if present
        if node.selector:
            findings = self._apply_selectors_dynamic(findings, node.selector)
        
        return findings
    
    async def _get_cves_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get CVEs data with filtering"""
        # Try to get from cache first
        if cache and 'OrganizationCVEsV2' in cache:
            cves = cache['OrganizationCVEsV2']
        else:
            # Fallback to database call
            cves = await db_manager.get_organization_cves(organization_id)
        
        # Apply selectors if present
        if node.selector:
            cves = self._apply_selectors_dynamic(cves, node.selector)
        
        return cves
    
    async def _get_dns_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get DNS data with filtering"""
        # Try to get from cache first
        if cache and 'OrganizationDNS' in cache:
            dns_records = cache['OrganizationDNS']
        else:
            # Fallback to database call
            dns_records = await db_manager.get_organization_dns(organization_id)
        
        # Apply record type filtering
        record_types = []
        if node.selector and 'record_type' in node.selector:
            record_selector = node.selector['record_type']
            if record_selector.get('op') == 'in':
                record_types = record_selector.get('value', [])
            elif record_selector.get('op') == '=':
                record_types = [record_selector.get('value', '')]
        
        if record_types:
            dns_records = [d for d in dns_records if d.get('record_type') in record_types]
        return dns_records
    
    async def _get_ip_ranges_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get IP ranges data"""
        # Try to get from cache first
        if cache and 'OrganizationIPRanges' in cache:
            ip_ranges = cache['OrganizationIPRanges']
        else:
            # Fallback to database call
            ip_ranges = await db_manager.get_organization_ip_ranges(organization_id)
        return ip_ranges
    
    async def _get_login_urls_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get login URLs data"""
        login_urls = await self._get_cached_data(cache, 'OrganizationLoginURLs', db_manager.get_organization_login_urls, organization_id)
        return login_urls
    
    async def _get_email_addresses_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get email addresses data"""
        email_addresses = await self._get_cached_data(cache, 'OrganizationEmailAddresses', db_manager.get_organization_email_addresses, organization_id)
        return email_addresses
    
    async def _get_email_breaches_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get email breaches data"""
        email_breaches = await self._get_cached_data(cache, 'OrganizationEmailBreaches', db_manager.get_organization_email_breaches, organization_id)
        return email_breaches
    
    async def _get_apis_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get APIs data"""
        apis = await self._get_cached_data(cache, 'OrganizationAPIs', db_manager.get_organization_apis, organization_id)
        return apis
    
    async def _get_object_storages_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get object storages data"""
        object_storages = await self._get_cached_data(cache, 'OrganizationObjectStorages', db_manager.get_organization_object_storages, organization_id)
        return object_storages
    
    async def _get_cdns_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get CDNs data"""
        cdns = await self._get_cached_data(cache, 'OrganizationCDNs', db_manager.get_organization_cdns, organization_id)
        return cdns
    
    async def _get_domain_names_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get domain names data"""
        domain_names = await self._get_cached_data(cache, 'OrganizationDomainNames', db_manager.get_organization_domain_names, organization_id)
        return domain_names
    
    async def _get_phishing_results_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get phishing results data"""
        phishing_results = await self._get_cached_data(cache, 'PhishingResults', db_manager.get_phishing_results, organization_id)
        return phishing_results
    
    async def _get_whois_data(self, node: AttackPathNode, organization_id: str, cache: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Get WHOIS data"""
        # For WHOIS, we need to determine the domain/IP to query
        # This would need to be handled based on the specific path context
        # For now, return None as it requires additional logic
        return None
    
    def _apply_selectors_dynamic(self, data: List[Dict[str, Any]], selector: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generic selector that works with any field/operator combination"""
        debug_logger.debug("Applying dynamic selectors: %r", selector)
        
        if not data or not selector:
            return data
        
        # Log raw data
        for item in data[:3]:  # Show first 3
            debug_logger.debug("[RAW DATA] %r", item)
        
        filtered_data = data
        
        for field, condition in selector.items():
            debug_logger.debug("Selector for field '%s': %r", field, condition)
            
            op = condition.get('op')
            value = condition.get('value')
            
            if op == 'in':
                if isinstance(value, list):
                    filtered_data = [item for item in filtered_data if item.get(field) in value]
                    debug_logger.debug("Filtering %s IN: %r", field, value)
                else:
                    debug_logger.warning("IN operator requires list value, got: %r", value)
            elif op == '=':
                filtered_data = [item for item in filtered_data if item.get(field) == value]
                debug_logger.debug("Filtering %s EQUALS: %r", field, value)
            elif op == 'not in':
                if isinstance(value, list):
                    filtered_data = [item for item in filtered_data if item.get(field) not in value]
                    debug_logger.debug("Filtering %s NOT IN: %r", field, value)
                else:
                    debug_logger.warning("NOT IN operator requires list value, got: %r", value)
            elif op == '>':
                filtered_data = [item for item in filtered_data if item.get(field) > value]
                debug_logger.debug("Filtering %s > %r", field, value)
            elif op == '<':
                filtered_data = [item for item in filtered_data if item.get(field) < value]
                debug_logger.debug("Filtering %s < %r", field, value)
            elif op == '>=':
                filtered_data = [item for item in filtered_data if item.get(field) >= value]
                debug_logger.debug("Filtering %s >= %r", field, value)
            elif op == '<=':
                filtered_data = [item for item in filtered_data if item.get(field) <= value]
                debug_logger.debug("Filtering %s <= %r", field, value)
            else:
                debug_logger.warning("Unknown operator '%s' for field '%s'", op, field)
        
        # Log filtered data
        for item in filtered_data[:3]:  # Show first 3
            debug_logger.debug("[FILTERED DATA] %r", item)
        
        debug_logger.info("Dynamic filtering: %d -> %d records", len(data), len(filtered_data))
        return filtered_data
    
    def _apply_cve_selectors(self, cves: List[Dict[str, Any]], selector: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply selectors to CVE data"""
        debug_logger.debug("Applying CVE selectors: %r", selector)
        
        # Log raw CVEs
        for cve in cves:
            debug_logger.debug("[CVEs RAW] %r", cve)
        
        filtered_cves = cves
        
        for field, condition in selector.items():
            debug_logger.debug("Selector for field '%s': %r", field, condition)
            
            if field == 'attackVector':
                if condition.get('op') == 'in':
                    vecs = [v.upper() for v in condition.get('value', [])]
                    debug_logger.debug("Filtering attackVector IN: %r", vecs)
                    filtered_cves = [c for c in filtered_cves if (c.get('attackVector') or '').upper() in vecs]
                elif condition.get('op') == '=':
                    target_vec = condition.get('value', '').upper()
                    debug_logger.debug("Filtering attackVector EQUALS: %r", target_vec)
                    filtered_cves = [c for c in filtered_cves if (c.get('attackVector') or '').upper() == target_vec]
        
        # Log filtered CVEs
        for cve in filtered_cves:
            debug_logger.debug("[CVEs AFTER SELECTOR] %r", cve)
        
        debug_logger.info("CVE filtering: %d -> %d records", len(cves), len(filtered_cves))
        return filtered_cves
    
    def _check_required_nodes_present(self, path_template: AttackPath, path_data: Dict[str, Any]) -> bool:
        """Check if all required nodes are present in the path data"""
        # Handle new joined data structure
        raw_data = path_data.get("raw_data", path_data)
        for node in path_template.nodes:
            if not node.optional:
                # Required node must be present AND non-empty
                if node.node_type not in raw_data:
                    return False
                node_values = raw_data.get(node.node_type)
                if not node_values:
                    return False
        return True
    
    def _get_optional_nodes_present(self, path_template: AttackPath, path_data: Dict[str, Any]) -> List[str]:
        """Get list of optional nodes that are present"""
        # Handle new joined data structure
        raw_data = path_data.get("raw_data", path_data)
        present_nodes = []
        for node in path_template.nodes:
            if node.optional and node.node_type in raw_data:
                present_nodes.append(node.node_type)
        return present_nodes
    
    def _create_joined_data_structure(self, path_template: AttackPath, path_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create the new joined data structure with possible_paths"""
        debug_logger.info("🔧 Creating joined data structure for template: %s", path_template.id)
        
        # Handle both old and new data structures
        if "valid_combinations" in path_data:
            # Old structure with joins
            debug_logger.info("📊 Using OLD structure with valid_combinations")
            valid_combinations = path_data.get("valid_combinations", [])
            total_combinations = path_data.get("total_combinations", 0)
        else:
            # New dynamic structure - create combinations by following join relationships sequentially
            debug_logger.info("🚀 Using NEW dynamic structure - creating combinations sequentially")
            valid_combinations = []
            if path_data:
                ordered_nodes = sorted(path_template.nodes, key=lambda n: n.order)
                debug_logger.info("📋 Ordered nodes: %s", [n.node_type for n in ordered_nodes])
                if ordered_nodes:
                    # Start with the first node and build combinations sequentially
                    first_node = ordered_nodes[0]
                    first_node_data = path_data.get(first_node.node_type, [])
                    debug_logger.info("🎯 First node: %s with %d items", first_node.node_type, len(first_node_data))
                    
                    # For cve_exploit_internet_host, use special grouping logic (call once, not per item)
                    if path_template.id == "cve_exploit_internet_host":
                        debug_logger.info("🎯 CVE EXPLOIT: Using special grouping logic (call once for entire dataset)")
                        combinations = self._build_cve_exploit_combinations(
                            None, first_node, ordered_nodes, path_data, path_template
                        )
                        for combination in combinations:
                            combination["path_no"] = len(valid_combinations) + 1
                            valid_combinations.append(combination)
                    else:
                        # For other templates, build combinations for each first item
                        for first_item in first_node_data:
                            combinations = self._build_all_combinations_from_first_node(
                                first_item, first_node, ordered_nodes, path_data, path_template
                            )
                            for combination in combinations:
                                combination["path_no"] = len(valid_combinations) + 1
                                valid_combinations.append(combination)
            
            total_combinations = len(valid_combinations)
            debug_logger.info("📊 Total combinations created: %d", total_combinations)
        
        # Create the joined data structure
        joined_data = {
            "path_id": path_template.id,
            "name": path_template.name,
            "description": path_template.description,
            "goals": path_template.goals,
            "outcomes": path_template.outcomes,
            "possible_paths": [],
            "total_possible_paths": total_combinations
        }
        
        # Convert valid combinations to the required format
        for i, combination in enumerate(valid_combinations, 1):
            path_entry = {
                "path_no": i
            }
            
            # Add each node's data to the path entry
            for node_type, node_data in combination.items():
                if node_data is not None:
                    path_entry[node_type] = node_data
            
            joined_data["possible_paths"].append(path_entry)
        
        return joined_data
    
    
    def _get_mitigating_evidence(self, path_template: AttackPath, path_data: Dict[str, Any]) -> List[str]:
        """Get mitigating evidence based on mitigation rules"""
        mitigating_evidence = []
        
        # Since supporting_findings are no longer part of the path chain,
        # we don't gather mitigating evidence from findings
        # This method is kept for potential future use with other data sources
        
        return mitigating_evidence
    
    async def _apply_joins_legacy(self, path_data: Dict[str, Any], joins: List[Dict[str, str]]) -> Dict[str, Any]:
        """Apply joins between different data sources"""
        if not joins:
            return path_data
        
        # For now, implement basic join logic
        # This would need to be expanded based on specific join requirements
        joined_data = path_data.copy()
        
        for join in joins:
            from_table, from_field = join['from'].split('.')
            to_table, to_field = join['to'].split('.')
            
            if from_table in path_data and to_table in path_data:
                # Perform the join
                joined_data[f"{from_table}_{to_table}_joined"] = self._perform_join(
                    path_data[from_table], from_field,
                    path_data[to_table], to_field
                )
        
        return joined_data
    
    def _perform_join(self, from_data: List[Any], from_field: str, to_data: List[Any], to_field: str) -> List[Dict[str, Any]]:
        """Perform a join between two datasets"""
        joined_results = []
        
        for from_item in from_data:
            from_value = from_item.get(from_field, None)
            
            for to_item in to_data:
                to_value = to_item.get(to_field, None)
                
                # Special handling for email join: OrganizationEmailAddresses.email to OrganizationEmailBreaches.email
                # OrganizationEmailBreaches.email format is "email:::source", we join on the part before :::
                if (from_field == 'email' and to_field == 'email' and 
                    'organization_id' in from_item and 'organization_id' in to_item and
                    from_item['organization_id'] == to_item['organization_id']):
                    
                    # Extract email part before ::: from OrganizationEmailBreaches
                    breach_email = to_value
                    if ':::' in breach_email:
                        breach_email_clean = breach_email.split(':::')[0]
                    else:
                        breach_email_clean = breach_email
                    
                    if from_value == breach_email_clean:
                        joined_results.append({
                            'from_item': from_item,
                            'to_item': to_item,
                            'join_value': from_value,
                            'breach_email_original': to_value,
                            'breach_email_clean': breach_email_clean
                        })
                else:
                    # Standard join logic for other fields
                    if from_value == to_value:
                        joined_results.append({
                            'from_item': from_item,
                            'to_item': to_item,
                            'join_value': from_value
                        })
        
        return joined_results


# Global attack path engine instance
attack_path_engine = AttackPathEngine()


# AWS Batch Entry Point
async def main():
    """
    AWS Batch entry point for attack path generation
    """
    import sys
    import os
    from datetime import datetime
    from s3_utils import S3Manager
    from llm_scoring_service import LLMScoringService
    from database import DatabaseManager
    from config import settings
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    # Set specific logger levels to reduce noise
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("🚀 Starting AWS Batch Attack Path Generation")
        logger.info(f"   Domain: {settings.DOMAIN}")
        logger.info(f"   Organization ID: {settings.ORGANIZATION_ID}")
        logger.info(f"   Scan ID: {settings.SCAN_ID}")
        logger.info(f"   AWS Region: {settings.AWS_REGION}")
        
        # Validate required environment variables
        required_vars = ['DOMAIN', 'ORGANIZATION_ID', 'SCAN_ID']
        missing_vars = [var for var in required_vars if not getattr(settings, var)]
        if missing_vars:
            logger.error(f"❌ Missing required environment variables: {missing_vars}")
            sys.exit(1)
        
        # Step 1: Initialize S3 Manager
        logger.info("📡 Initializing S3 Manager...")
        s3_manager = S3Manager(settings.S3_BUCKET, settings.AWS_REGION)
        
        # Step 2: Download attack path templates from S3 (or use local fallback)
        logger.info("📥 Loading attack path templates...")
        try:
            templates_data = s3_manager.download_attack_path_templates(settings.S3_TEMPLATES_KEY)
            logger.info("✅ Templates loaded from S3")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load from S3: {e}")
            logger.info("📁 Falling back to local templates file...")
            
            # Fallback to local file for testing
            local_templates_file = "attack_paths_rules_enhanced.json"
            try:
                import json
                with open(local_templates_file, 'r') as f:
                    templates_data = json.load(f)
                logger.info(f"✅ Templates loaded from local file: {local_templates_file}")
            except Exception as local_e:
                logger.error(f"❌ Failed to load local templates: {local_e}")
                raise FileNotFoundError(f"Could not load templates from S3 or local file: {e}, {local_e}")
        
        # Step 3: Initialize database connections
        logger.info("🗄️ Initializing database connections...")
        db_manager = DatabaseManager()
        await db_manager.initialize()
        
        # Step 4: Initialize attack path engine and load templates
        logger.info("⚙️ Initializing attack path engine...")
        engine = AttackPathEngine()
        
        # Load templates from S3 data (adapt format if needed)
        await engine.load_attack_path_templates_from_data(templates_data)
        logger.info(f"✅ Loaded {len(engine.path_templates)} attack path templates")
        
        # Step 5: Generate attack paths
        logger.info("🔍 Generating attack paths...")
        start_time = datetime.now()
        
        attack_paths_json = await engine.generate_attack_paths_json(
            db_manager=db_manager,
            organization_id=settings.ORGANIZATION_ID,
            scan_id=settings.SCAN_ID
        )
        
        generation_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"✅ Generated attack paths in {generation_time:.2f}s")
        logger.info(f"   Templates processed: {len(attack_paths_json)}")
        total_paths = sum(template.get('total_possible_paths', 0) for template in attack_paths_json)
        logger.info(f"   Total attack paths: {total_paths}")
        
        # Step 6: Score attack paths with LLM
        logger.info("🧠 Scoring attack paths with LLM...")
        llm_service = LLMScoringService()
        
        scored_paths = await llm_service.score_attack_paths_from_json(
            attack_paths_json=attack_paths_json,
            chunk_size=settings.LLM_CHUNK_SIZE,
            progress_callback=lambda current, total: logger.info(f"   Progress: {current}/{total} chunks processed")
        )
        
        scoring_time = (datetime.now() - start_time).total_seconds() - generation_time
        logger.info(f"✅ Completed LLM scoring in {scoring_time:.2f}s")
        logger.info(f"   Scored paths: {len(scored_paths)}")
        
        # Step 7: Upload results to S3 (or save locally for testing)
        logger.info("📤 Saving results...")
        try:
            s3_key = s3_manager.upload_attack_path_results(
                domain=settings.DOMAIN,
                organization_id=settings.ORGANIZATION_ID,
                results_data=scored_paths
            )
            
            # Step 8: Verify upload
            if s3_manager.verify_upload(s3_key):
                total_time = (datetime.now() - start_time).total_seconds()
                logger.info("🎉 AWS Batch execution completed successfully!")
                logger.info(f"   Total execution time: {total_time:.2f}s")
                logger.info(f"   Results uploaded to: s3://{settings.S3_BUCKET}/{s3_key}")
                sys.exit(0)
            else:
                logger.error("❌ Upload verification failed")
                sys.exit(7)
                
        except Exception as e:
            logger.warning(f"⚠️ S3 upload failed: {e}")
            logger.info("📁 Saving results locally for testing...")
            
            # Fallback: save to local file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            local_filename = f"local_batch_results_{settings.DOMAIN}_{timestamp}.json"
            
            try:
                import json
                with open(local_filename, 'w') as f:
                    json.dump({
                        "metadata": {
                            "domain": settings.DOMAIN,
                            "organization_id": settings.ORGANIZATION_ID,
                            "generated_timestamp": timestamp,
                            "generated_at": datetime.now().isoformat(),
                            "local_execution": True
                        },
                        "results": scored_paths
                    }, f, indent=2)
                
                total_time = (datetime.now() - start_time).total_seconds()
                logger.info("🎉 Local batch execution completed successfully!")
                logger.info(f"   Total execution time: {total_time:.2f}s")
                logger.info(f"   Results saved locally: {local_filename}")
                sys.exit(0)
                
            except Exception as local_e:
                logger.error(f"❌ Failed to save results locally: {local_e}")
                sys.exit(7)
        
    except FileNotFoundError as e:
        logger.error(f"❌ Template file not found: {e}")
        sys.exit(4)
    except ConnectionError as e:
        logger.error(f"❌ Database connection error: {e}")
        sys.exit(2)
    except Exception as e:
        logger.error(f"❌ Unexpected error during batch execution: {e}")
        logger.exception("Full error details:")
        sys.exit(5)
    finally:
        # Cleanup database connections
        if 'db_manager' in locals() and db_manager:
            if db_manager.pg_pool:
                await db_manager.pg_pool.close()
                logger.info("🔌 PostgreSQL connection pool closed")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main()) 