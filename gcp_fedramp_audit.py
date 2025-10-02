#!/usr/bin/env python3

"""
GCP FedRAMP High Audit Script
This script collects relevant security and compliance information from GCP resources
for FedRAMP High audit purposes, with specific focus on FedRAMP High controls.
"""

import json
import datetime
from typing import Dict, List, Any
from google.cloud import asset_v1
from google.cloud import container_v1
from google.cloud import iam_v1
from google.cloud import monitoring_v3
from google.cloud import storage
from google.cloud import resource_manager_v3
from google.cloud import security_center_v1
from google.cloud import audit_logs_v1
from google.cloud import kms_v1
from google.cloud import compute_v1
from google.cloud import cloud_audit_logs_v1

def get_project_info(project_id):
    """Collect basic project information."""
    client = resource_manager_v3.ProjectsClient()
    project = client.get_project(name=f'projects/{project_id}')
    return {
        'name': project.display_name,
        'project_id': project_id,
        'project_number': project.name.split('/')[-1],
        'create_time': project.create_time.isoformat(),
        'state': project.state.name
    }

def get_iam_policies(project_id):
    """Collect IAM policies and roles."""
    client = iam_v1.IAMClient()
    request = iam_v1.ListRolesRequest(parent=f'projects/{project_id}')
    roles = client.list_roles(request=request)
    return [{'name': role.name, 'title': role.title, 'description': role.description} for role in roles]

def get_security_findings(project_id):
    """Collect Security Command Center findings."""
    client = security_center_v1.SecurityCenterClient()
    parent = f'projects/{project_id}'
    request = security_center_v1.ListFindingsRequest(parent=parent)
    findings = client.list_findings(request=request)
    return [{'name': finding.name, 'category': finding.category, 'severity': finding.severity} for finding in findings]

def get_gke_clusters(project_id):
    """Collect GKE cluster configurations."""
    client = container_v1.ClusterManagerClient()
    parent = f'projects/{project_id}/locations/-'
    clusters = client.list_clusters(parent=parent)
    return [{'name': cluster.name, 'location': cluster.location, 'master_version': cluster.current_master_version} for cluster in clusters]

def get_storage_buckets(project_id):
    """Collect Cloud Storage bucket configurations (SC-13, SC-28)."""
    client = storage.Client(project=project_id)
    buckets = client.list_buckets()
    return [{
        'name': bucket.name,
        'location': bucket.location,
        'storage_class': bucket.storage_class,
        'encryption': bucket.encryption_configuration,
        'public_access_prevention': bucket.iam_configuration.public_access_prevention,
        'uniform_bucket_level_access': bucket.iam_configuration.uniform_bucket_level_access_enabled,
        'retention_policy': bucket.retention_policy,
        'logging': bucket.logging
    } for bucket in buckets]

def get_kms_info(project_id):
    """Collect KMS configurations (SC-12, SC-13)."""
    client = kms_v1.KeyManagementServiceClient()
    parent = f'projects/{project_id}/locations/-'
    
    key_rings = client.list_key_rings(request={'parent': parent})
    kms_info = []
    
    for key_ring in key_rings:
        crypto_keys = client.list_crypto_keys(request={'parent': key_ring.name})
        keys = [{
            'name': key.name,
            'creation_time': key.create_time,
            'rotation_period': key.rotation_period,
            'protection_level': key.protection_level,
            'algorithm': key.version_template.algorithm,
        } for key in crypto_keys]
        
        kms_info.append({
            'key_ring': key_ring.name,
            'crypto_keys': keys
        })
    
    return kms_info

def get_network_security(project_id):
    """Collect network security configurations (AC-4, SC-7)."""
    client = compute_v1.FirewallsClient()
    
    request = compute_v1.ListFirewallsRequest(project=project_id)
    firewalls = client.list(request=request)
    
    return [{
        'name': firewall.name,
        'network': firewall.network,
        'direction': firewall.direction,
        'priority': firewall.priority,
        'source_ranges': firewall.source_ranges,
        'allowed': [{'protocol': rule.protocol, 'ports': rule.ports} for rule in firewall.allowed] if firewall.allowed else [],
        'denied': [{'protocol': rule.protocol, 'ports': rule.ports} for rule in firewall.denied] if firewall.denied else []
    } for firewall in firewalls]

def get_audit_logs_config(project_id):
    """Collect audit logging configurations (AU-2, AU-3, AU-12)."""
    client = audit_logs_v1.AuditLogsClient()
    
    parent = f'projects/{project_id}'
    sinks = client.list_sinks(request={'parent': parent})
    
    return [{
        'name': sink.name,
        'destination': sink.destination,
        'filter': sink.filter,
        'include_children': sink.include_children
    } for sink in sinks]

def get_org_policies(project_id):
    """Collect organization policies (AC-3, CM-2)."""
    client = asset_v1.AssetServiceClient()
    
    request = {
        'parent': f'projects/{project_id}',
        'asset_types': ['google.cloud.orgpolicy.v1.Policy']
    }
    
    response = client.analyze_iam_policy(request=request)
    return [{
        'policy': policy.policy,
        'resource': policy.resource,
        'constraints': policy.constraints
    } for policy in response.main_analysis.analysis_results]

def get_security_controls(project_id):
    """Collect security control configurations (SI-4, SI-7)."""
    client = security_center_v1.SecurityCenterClient()
    
    parent = f'projects/{project_id}'
    sources = client.list_sources(request={'parent': parent})
    
    controls = []
    for source in sources:
        findings = client.list_findings(request={'parent': source.name})
        controls.append({
            'source': source.name,
            'display_name': source.display_name,
            'findings': [{
                'name': finding.name,
                'category': finding.category,
                'severity': finding.severity,
                'state': finding.state,
                'finding_class': finding.finding_class,
                'event_time': finding.event_time.isoformat() if finding.event_time else None,
                'resource_name': finding.resource_name
            } for finding in findings]
        })
    
    return controls

def main(project_id):
    """Main function to collect all audit information with FedRAMP High controls."""
    audit_data = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'project_info': get_project_info(project_id),
        'iam_policies': get_iam_policies(project_id),  # AC-2, AC-3, AC-6
        'security_findings': get_security_findings(project_id),  # SI-2, SI-4
        'gke_clusters': get_gke_clusters(project_id),  # CM-6, SC-7
        'storage_buckets': get_storage_buckets(project_id),  # SC-13, SC-28
        'kms_configuration': get_kms_info(project_id),  # SC-12, SC-13
        'network_security': get_network_security(project_id),  # AC-4, SC-7
        'audit_logs': get_audit_logs_config(project_id),  # AU-2, AU-3, AU-12
        'org_policies': get_org_policies(project_id),  # AC-3, CM-2
        'security_controls': get_security_controls(project_id)  # SI-4, SI-7
    }
    
    # Write results to a file
    output_file = f'fedramp_audit_{project_id}_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
    with open(output_file, 'w') as f:
        json.dump(audit_data, f, indent=2)
    print(f'Audit data written to {output_file}')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Collect GCP resources information for FedRAMP High audit.')
    parser.add_argument('project_id', help='GCP Project ID to audit')
    args = parser.parse_args()
    main(args.project_id)
