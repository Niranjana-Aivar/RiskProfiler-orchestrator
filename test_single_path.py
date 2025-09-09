#!/usr/bin/env python3
"""
Siemens test focused on single attack path template: cve_exploit_internet_host
Shows complete attack path generation logic for one specific path
"""

import logging
import asyncio
import json
from test_siemens_attack_paths import SiemensAttackPathTester

def setup_debug_logging():
    """Set up comprehensive debug logging"""
    # Configure debug logger
    debug_logger = logging.getLogger("attackpath.debug")
    debug_logger.setLevel(logging.DEBUG)
    
    # Configure main logger
    main_logger = logging.getLogger("attack_path_engine")
    main_logger.setLevel(logging.INFO)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    
    # Create detailed formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # Add handlers
    debug_logger.addHandler(console_handler)
    main_logger.addHandler(console_handler)
    
    # Also configure other relevant loggers
    logging.getLogger("database").setLevel(logging.INFO)
    logging.getLogger("attack_path_service").setLevel(logging.INFO)
    
    print("🔧 Debug logging enabled for single path test!")
    print("   - Debug logger: attackpath.debug (DEBUG level)")
    print("   - Main logger: attack_path_engine (INFO level)")
    print("   - Database logger: database (INFO level)")
    print()

async def main():
    """Run Siemens test focused on cve_exploit_internet_host path template"""
    print("🚀 Siemens Single Attack Path Test: cve_exploit_internet_host")
    print("=" * 70)
    
    # Set up minimal logging (INFO, WARNING, ERROR only)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Disable debug logging for attack path engine
    logging.getLogger("attackpath.debug").setLevel(logging.WARNING)
    logging.getLogger("attack_path_engine").setLevel(logging.INFO)
    logging.getLogger("database").setLevel(logging.INFO)
    logging.getLogger("attack_path_service").setLevel(logging.INFO)
    
    # Create tester
    tester = SiemensAttackPathTester()
    
    # Test organization resolution and single attack path generation
    print("🔍 Testing Organization Resolution and Single Attack Path Generation")
    print("-" * 70)
    
    try:
        # Initialize database manager
        from database import db_manager
        await db_manager.initialize()
        
        # Initialize attack path service (this loads the templates)
        await tester.service.initialize()
        
        # Get organization by domain
        organization = await db_manager.get_organization_by_domain(tester.domain)
        
        if not organization:
            print(f"❌ Organization not found for domain: {tester.domain}")
            return
        
        print(f"✅ Organization found: {organization['id']}")
        print(f"   - Domain: {organization['domain']}")
        print(f"   - Latest scan: {organization['latest_scan_id']}")
        
        # Get the first attack path template (cve_exploit_internet_host)
        attack_path_engine = tester.service.attack_path_engine
        if not attack_path_engine.path_templates:
            print("❌ No attack path templates loaded")
            return
        
        first_template = attack_path_engine.path_templates[0]
        print(f"\n🎯 Focusing on first attack path template:")
        print(f"   - Path ID: {first_template.id}")
        print(f"   - Name: {first_template.name}")
        print(f"   - Description: {first_template.description}")
        print(f"   - Goals: {first_template.goals}")
        print(f"   - Outcomes: {first_template.outcomes}")
        print(f"   - Nodes: {[node.node_type for node in first_template.nodes]}")
        
        # Verify that supporting_findings node has been filtered out
        node_types = [node.node_type for node in first_template.nodes]
        if 'supporting_findings' in node_types:
            print("❌ ERROR: supporting_findings node still present in template!")
            return
        else:
            print("✅ VERIFIED: supporting_findings node has been filtered out")
        
        # Generate attack paths for this specific template only
        print(f"\n🔧 Generating attack paths for template: {first_template.id}")
        print("-" * 50)
        
        # Use the engine's internal method to generate paths for this specific template
        path_instances = await attack_path_engine._instantiate_single_path(
            first_template, 
            organization['id'], 
            organization['latest_scan_id']
        )
        
        # Generate attack path instances for the first template only
        
        if path_instances:
            # Convert to the exact JSON structure requested
            json_output = []
            
            for path_instance in path_instances:
                path_json = {
                    "path_id": path_instance.path_id,
                    "name": path_instance.path_name,
                    "description": path_instance.path_description,
                    "goals": path_instance.goals,
                    "outcomes": path_instance.outcomes,
                    "possible_paths": [],
                    "total_possible_paths": 0
                }
                
                # Add possible paths if available
                if hasattr(path_instance, 'nodes_data') and path_instance.nodes_data:
                    if 'possible_paths' in path_instance.nodes_data:
                        path_json["possible_paths"] = path_instance.nodes_data['possible_paths']
                        path_json["total_possible_paths"] = len(path_instance.nodes_data['possible_paths'])
                    elif 'total_possible_paths' in path_instance.nodes_data:
                        path_json["total_possible_paths"] = path_instance.nodes_data['total_possible_paths']
                
                json_output.append(path_json)
            
            # Verify that no supporting findings are in the output
            print(f"\n🔍 Verifying output contains no supporting findings...")
            has_supporting_findings = False
            for path_data in json_output:
                # Check if any possible_paths contain supporting_findings
                for possible_path in path_data.get("possible_paths", []):
                    if "supporting_findings" in possible_path:
                        has_supporting_findings = True
                        print(f"❌ ERROR: Found supporting_findings in path {path_data.get('path_id')}")
                        break
                if has_supporting_findings:
                    break
            
            if not has_supporting_findings:
                print("✅ VERIFIED: No supporting_findings found in output JSON")
            
            # Display data summary
            print(f"\n📊 DATA SUMMARY:")
            print(f"   - Total attack path instances: {len(json_output)}")
            
            total_possible_paths = sum(path_data.get("total_possible_paths", 0) for path_data in json_output)
            print(f"   - Total possible paths across all instances: {total_possible_paths}")
            
            # Show 5 sample combinations from the first path instance
            if json_output and json_output[0].get("possible_paths"):
                print(f"\n🔍 SAMPLE COMBINATIONS (first 5 from {json_output[0]['path_id']}):")
                sample_paths = json_output[0]["possible_paths"][:5]
                for i, path in enumerate(sample_paths, 1):
                    print(f"   Path {i}:")
                    for node_type, node_data in path.items():
                        if node_type != "path_no" and node_data:
                            if isinstance(node_data, dict):
                                # Show key fields for each node type
                                if node_type == "dns_to_ip":
                                    print(f"     - {node_type}: {node_data.get('name', 'N/A')} -> {node_data.get('value', 'N/A')}")
                                elif node_type == "ip_asset":
                                    print(f"     - {node_type}: {node_data.get('ip_range', 'N/A')}")
                                elif node_type == "vulnerability_on_asset":
                                    print(f"     - {node_type}: {node_data.get('cve', 'N/A')} on {node_data.get('asset', 'N/A')}")
                                else:
                                    print(f"     - {node_type}: {str(node_data)[:100]}...")
                            else:
                                print(f"     - {node_type}: {str(node_data)[:100]}...")
                    print()
            
            # Save JSON data to file
            output_filename = f"siemens_attack_paths_{first_template.id}.json"
            with open(output_filename, 'w') as f:
                json.dump(json_output, f, indent=2, default=str)
            print(f"💾 Attack path data saved to: {output_filename}")
        else:
            print("❌ No attack path instances were generated for this template")
            
    except Exception as e:
        print(f"❌ Error during test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
