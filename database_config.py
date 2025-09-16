"""
Database configuration for dynamic query handling
Maps tables to their respective database types (PostgreSQL vs DynamoDB)
"""

# Database type mapping for all tables
DATABASE_TYPE_MAPPING = {
    # PostgreSQL tables
    "Findings": "postgresql",
    "PhishingResults": "postgresql",
    "OrganizationTyposquattingDomain": "postgresql",
    "LogoAbuseFindings": "postgresql",
    "PortfolioDomains": "postgresql",
    
    # DynamoDB tables
    "Organizations": "dynamodb",
    "OrganizationCVEsV2": "dynamodb", 
    "OrganizationDNS": "dynamodb",
    "OrganizationIPRanges": "dynamodb",
    "OrganizationLoginURLs": "dynamodb",
    "OrganizationEmailAddresses": "dynamodb",
    "OrganizationEmailBreaches": "dynamodb",
    "OrganizationAPIs": "dynamodb",
    "OrganizationObjectStorages": "dynamodb",
    "OrganizationCDNs": "dynamodb",
    "OrganizationDomainNames": "dynamodb",
    "OrganizationDataStores": "dynamodb",
    "WhoisRecords": "dynamodb",
}

def get_database_type(table_name: str) -> str:
    """Get database type for a given table name"""
    return DATABASE_TYPE_MAPPING.get(table_name, "unknown")

def is_postgresql_table(table_name: str) -> bool:
    """Check if table is PostgreSQL"""
    return get_database_type(table_name) == "postgresql"

def is_dynamodb_table(table_name: str) -> bool:
    """Check if table is DynamoDB"""
    return get_database_type(table_name) == "dynamodb"
