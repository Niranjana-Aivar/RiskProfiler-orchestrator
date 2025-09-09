#!/usr/bin/env python3
"""
Test script for Siemens.com attack path generation
Tests the complete attack path generation workflow with real data
Verifies that all possible attack paths per template are generated as expected
"""

import asyncio
import logging
from typing import List, Dict, Any

from attack_path_service import AttackPathService
from database import db_manager
from models import AttackPathRequest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Disable debug logging for attack path engine (same as test_siemens_single_path.py)
logging.getLogger("attackpath.debug").setLevel(logging.WARNING)
logging.getLogger("attack_path_engine").setLevel(logging.INFO)
logging.getLogger("database").setLevel(logging.INFO)
logging.getLogger("attack_path_service").setLevel(logging.INFO)

logger = logging.getLogger(__name__)


class SiemensAttackPathTester:
    def __init__(self):
        self.service = AttackPathService()
        self.domain = "siemens.com"
    
    async def test_organization_resolution(self):
        """Test that Siemens organization is found and resolved correctly"""
        print("🔍 Testing Organization Resolution")
        print("-" * 50)
        
        try:
            # Initialize database manager
            await db_manager.initialize()
            
            # Initialize attack path service (this loads the templates)
            await self.service.initialize()
            
            # Get organization by domain
            organization = await db_manager.get_organization_by_domain(self.domain)
            
            if not organization:
                print(f"❌ Organization not found for domain: {self.domain}")
                return False
            
            print(f"✅ Organization found:")
            print(f"   - ID: {organization['id']}")
            print(f"   - Domain: {organization['domain']}")
            print(f"   - Latest Scan ID: {organization['latest_scan_id']}")
            
            if not organization['latest_scan_id']:
                print(f"⚠️  No latest scan ID found for {self.domain}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Error resolving organization: {e}")
            logger.exception("Organization resolution failed")
            return False
    
    async def test_data_availability(self):
        """Test that required data is available for attack path generation"""
        print("\n📊 Testing Data Availability")
        print("-" * 50)
        
        try:
            # Get organization
            organization = await db_manager.get_organization_by_domain(self.domain)
            if not organization:
                print("❌ Organization not found")
                return False
            
            org_id = organization['id']
            scan_id = organization['latest_scan_id']
            
            # Test data availability for each table
            data_tests = [
                ("Findings", db_manager.get_findings_by_scan(scan_id)),
                ("OrganizationCVEsV2", db_manager.get_organization_cves(org_id)),
                ("OrganizationDNS", db_manager.get_organization_dns(org_id)),
                ("OrganizationIPRanges", db_manager.get_organization_ip_ranges(org_id)),
                ("OrganizationLoginURLs", db_manager.get_organization_login_urls(org_id)),
                ("OrganizationEmailAddresses", db_manager.get_organization_email_addresses(org_id)),
                ("OrganizationEmailBreaches", db_manager.get_organization_email_breaches(org_id)),
                ("OrganizationAPIs", db_manager.get_organization_apis(org_id)),
                ("OrganizationObjectStorages", db_manager.get_organization_object_storages(org_id)),
                ("OrganizationCDNs", db_manager.get_organization_cdns(org_id)),
                ("OrganizationDomainNames", db_manager.get_organization_domain_names(org_id)),
                ("PhishingResults", db_manager.get_phishing_results(org_id)),
                ("OrganizationTyposquattingDomain", db_manager.get_typosquatting_domains(org_id)),
                ("LogoAbuseFindings", db_manager.get_logo_abuse_findings(org_id)),
                ("PortfolioDomains", db_manager.get_portfolio_domains(org_id)),
            ]
            
            data_summary = {}
            total_records = 0
            
            for table_name, data_fetch_func in data_tests:
                try:
                    data = await data_fetch_func
                    record_count = len(data) if data else 0
                    data_summary[table_name] = record_count
                    total_records += record_count
                    
                    status = "✅" if record_count > 0 else "⚠️"
                    print(f"   {status} {table_name}: {record_count} records")
                    
                except Exception as e:
                    print(f"   ❌ {table_name}: Error - {e}")
                    data_summary[table_name] = 0
            
            print(f"\n📈 Data Summary:")
            print(f"   - Total records across all tables: {total_records}")
            print(f"   - Tables with data: {sum(1 for count in data_summary.values() if count > 0)}")
            print(f"   - Tables without data: {sum(1 for count in data_summary.values() if count == 0)}")
            
            return data_summary
            
        except Exception as e:
            print(f"❌ Error testing data availability: {e}")
            logger.exception("Data availability test failed")
            return {}
    
    async def test_attack_path_generation(self):
        """Test complete attack path generation for Siemens (without LLM scoring)"""
        print("\n🎯 Testing Attack Path Generation (Raw Data Only)")
        print("-" * 50)
        
        try:
            print(f"🚀 Generating raw attack paths for {self.domain}...")
            print(f"   - Domain: {self.domain}")
            print(f"   - Skipping LLM scoring for faster results")
            
            # Get organization
            organization = await db_manager.get_organization_by_domain(self.domain)
            if not organization:
                print("❌ Organization not found")
                return None
            
            # Build data cache
            from cache_manager import build_org_data_cache
            cache = await build_org_data_cache(
                db_manager, 
                organization['id'], 
                organization['latest_scan_id']
            )
            
            # Generate raw attack path instances (without LLM scoring)
            path_instances = await self.service.attack_path_engine.instantiate_attack_paths(
                organization['id'], organization['latest_scan_id'], cache
            )
            
            if not path_instances:
                print("❌ No attack path instances generated")
                return None
            
            print(f"\n✅ Raw attack path generation completed!")
            print(f"   - Total path instances: {len(path_instances)}")
            
            # Convert to JSON format (similar to test_siemens_single_path.py)
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
            
            # Save JSON data to file
            import json
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"siemens_all_attack_paths_raw_{timestamp}.json"
            
            with open(output_filename, 'w') as f:
                json.dump(json_output, f, indent=2, default=str)
            
            print(f"💾 Raw attack path data saved to: {output_filename}")
            
            # Display data summary
            print(f"\n📊 DATA SUMMARY:")
            print(f"   - Total attack path instances: {len(json_output)}")
            
            total_possible_paths = sum(path_data.get("total_possible_paths", 0) for path_data in json_output)
            print(f"   - Total possible paths across all instances: {total_possible_paths}")
            
            # Show path type breakdown
            path_types = {}
            for path_data in json_output:
                path_id = path_data.get("path_id", "unknown")
                path_types[path_id] = path_types.get(path_id, 0) + 1
            
            print(f"   - Path types found: {len(path_types)}")
            for path_type, count in path_types.items():
                print(f"     * {path_type}: {count} instances")
            
            return json_output
            
        except Exception as e:
            print(f"❌ Error generating attack paths: {e}")
            logger.exception("Attack path generation failed")
            return None
    
    def analyze_attack_paths(self, json_output):
        """Analyze the generated attack paths from JSON output"""
        if not json_output:
            print("❌ No attack paths to analyze")
            return False
        
        analysis_results = {
            "total_paths": len(json_output),
            "path_types": {},
            "possible_paths_per_template": {},
            "join_combinations": {}
        }
        
        # Analyze each attack path from JSON data
        for path_data in json_output:
            path_type = path_data.get("path_id", "unknown")
            analysis_results["path_types"][path_type] = analysis_results["path_types"].get(path_type, 0) + 1
            
            # Track possible paths structure
            possible_paths = path_data.get("possible_paths", [])
            total_possible = path_data.get("total_possible_paths", 0)
            
            if possible_paths:
                analysis_results["possible_paths_per_template"][path_type] = {
                    "count": len(possible_paths),
                    "total": total_possible
                }
                
                # Analyze join combinations
                if possible_paths:
                    first_path = possible_paths[0]
                    node_types = [key for key in first_path.keys() if key != "path_no"]
                    analysis_results["join_combinations"][path_type] = node_types
        
        print(f"\n📈 Analysis Results:")
        print(f"   - Total path instances: {analysis_results['total_paths']}")
        print(f"   - Path types: {len(analysis_results['path_types'])}")
        print(f"   - Templates with combinations: {len(analysis_results['possible_paths_per_template'])}")
        
        return analysis_results
    
    
    
    def validate_join_combinations(self, analysis_results):
        """Validate that join combinations are working correctly"""
        if not analysis_results or not analysis_results["possible_paths_per_template"]:
            return False
        
        total_combinations = 0
        templates_with_combinations = 0
        
        for path_type, combo_data in analysis_results["possible_paths_per_template"].items():
            count = combo_data["count"]
            total_combinations += count
            templates_with_combinations += 1
        
        return total_combinations > 0
    
    async def run_comprehensive_test(self):
        """Run comprehensive test suite for Siemens attack path generation"""
        print("🚀 Starting Comprehensive Siemens Attack Path Test")
        print("=" * 70)
        
        test_results = {
            "organization_resolution": False,
            "data_availability": False,
            "attack_path_generation": False,
            "path_analysis": False,
            "join_combinations_validation": False
        }
        
        try:
            # Test 1: Organization Resolution
            test_results["organization_resolution"] = await self.test_organization_resolution()
            
            if not test_results["organization_resolution"]:
                return test_results
            
            # Test 2: Data Availability
            data_summary = await self.test_data_availability()
            test_results["data_availability"] = len(data_summary) > 0
            
            if not test_results["data_availability"]:
                return test_results
            
            # Test 3: Attack Path Generation (Raw Data Only)
            json_output = await self.test_attack_path_generation()
            test_results["attack_path_generation"] = json_output is not None
            
            if not test_results["attack_path_generation"]:
                return test_results
            
            # Test 4: Path Analysis
            analysis_results = self.analyze_attack_paths(json_output)
            test_results["path_analysis"] = analysis_results is not False
            
            if not test_results["path_analysis"]:
                return test_results
            
            # Test 5: Join Combinations Validation
            test_results["join_combinations_validation"] = self.validate_join_combinations(analysis_results)
            
            # Final Summary
            passed_tests = sum(test_results.values())
            total_tests = len(test_results)
            
            if passed_tests == total_tests:
                print("✅ All tests passed!")
            else:
                print("⚠️  Some tests failed.")
            
            return test_results
            
        except Exception as e:
            print(f"❌ Test suite failed with error: {e}")
            logger.exception("Comprehensive test failed")
            return test_results


async def main():
    """Main test runner"""
    tester = SiemensAttackPathTester()
    results = await tester.run_comprehensive_test()
    
    # Exit with appropriate code
    if all(results.values()):
        print("\n✅ All tests passed successfully!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
